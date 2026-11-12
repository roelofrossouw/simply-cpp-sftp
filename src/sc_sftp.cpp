// sc::sftp::client on libssh2: a blocking session with a timeout, the host key checked against known_hosts (a new
// host's line appended to the file with accept_new), signing in with a key file, a password or the SSH agent, and
// SFTP requests whose failures carry the server's status.

#include <sc_sftp.h>

#include <libssh2.h>
#include <libssh2_sftp.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <system_error>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

namespace sc::sftp {
    const char *reason_name(const reason why) {
        switch (why) {
            case reason::no_such_file: return "no such file";
            case reason::permission_denied: return "permission denied";
            case reason::failure: return "failure";
            case reason::bad_message: return "bad message";
            case reason::no_connection: return "no connection";
            case reason::connection_lost: return "connection lost";
            case reason::unsupported: return "not supported by the server";
            case reason::invalid_handle: return "invalid handle";
            case reason::no_such_path: return "no such path";
            case reason::file_exists: return "file exists";
            case reason::write_protected: return "write protected";
            case reason::no_media: return "no media";
            case reason::no_space: return "no space left";
            case reason::quota_exceeded: return "quota exceeded";
            case reason::unknown_principal: return "unknown principal";
            case reason::lock_conflict: return "lock conflict";
            case reason::folder_not_empty: return "folder not empty";
            case reason::not_a_folder: return "not a folder";
            case reason::invalid_filename: return "invalid file name";
            case reason::link_loop: return "link loop";
            case reason::host_key_unknown: return "host key unknown";
            case reason::host_key_changed: return "host key changed";
            case reason::authentication_failed: return "authentication failed";
            case reason::timeout: return "timed out";
            case reason::local: return "local file";
            case reason::other: return "error";
        }
        return "error";
    }

    namespace {
        constexpr std::size_t chunk = 256 * 1024;

        void start_libssh2() {
            static std::once_flag once;
            std::call_once(once, [] {
                if (const int rc = libssh2_init(0); rc != 0) throw error{"libssh2 didn't start (" + std::to_string(rc) + ")", reason::other};
            });
        }

        reason from_status(const unsigned long status) {
            switch (status) {
                case LIBSSH2_FX_NO_SUCH_FILE: return reason::no_such_file;
                case LIBSSH2_FX_PERMISSION_DENIED: return reason::permission_denied;
                case LIBSSH2_FX_FAILURE: return reason::failure;
                case LIBSSH2_FX_BAD_MESSAGE: return reason::bad_message;
                case LIBSSH2_FX_NO_CONNECTION: return reason::no_connection;
                case LIBSSH2_FX_CONNECTION_LOST: return reason::connection_lost;
                case LIBSSH2_FX_OP_UNSUPPORTED: return reason::unsupported;
                case LIBSSH2_FX_INVALID_HANDLE: return reason::invalid_handle;
                case LIBSSH2_FX_NO_SUCH_PATH: return reason::no_such_path;
                case LIBSSH2_FX_FILE_ALREADY_EXISTS: return reason::file_exists;
                case LIBSSH2_FX_WRITE_PROTECT: return reason::write_protected;
                case LIBSSH2_FX_NO_MEDIA: return reason::no_media;
                case LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM: return reason::no_space;
                case LIBSSH2_FX_QUOTA_EXCEEDED: return reason::quota_exceeded;
                case LIBSSH2_FX_UNKNOWN_PRINCIPAL: return reason::unknown_principal;
                case LIBSSH2_FX_LOCK_CONFLICT: return reason::lock_conflict;
                case LIBSSH2_FX_DIR_NOT_EMPTY: return reason::folder_not_empty;
                case LIBSSH2_FX_NOT_A_DIRECTORY: return reason::not_a_folder;
                case LIBSSH2_FX_INVALID_FILENAME: return reason::invalid_filename;
                case LIBSSH2_FX_LINK_LOOP: return reason::link_loop;
                default: return reason::other;
            }
        }

        std::string base64(const unsigned char *bytes, const std::size_t size) {
            static constexpr char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            for (std::size_t at = 0; at < size; at += 3) {
                const std::uint32_t group = bytes[at] << 16 | (at + 1 < size ? bytes[at + 1] << 8 : 0) | (at + 2 < size ? bytes[at + 2] : 0);
                out += digits[group >> 18 & 63];
                out += digits[group >> 12 & 63];
                if (at + 1 < size) out += digits[group >> 6 & 63];
                if (at + 2 < size) out += digits[group & 63];
            }
            return out; // without padding, as ssh writes fingerprints
        }

        entry entry_of(std::string name, const LIBSSH2_SFTP_ATTRIBUTES &attributes) {
            entry made;
            made.name = std::move(name);
            if (attributes.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
                const auto mode = attributes.permissions;
                made.kind = LIBSSH2_SFTP_S_ISREG(mode) ? entry_kind::file
                            : LIBSSH2_SFTP_S_ISDIR(mode) ? entry_kind::folder
                            : LIBSSH2_SFTP_S_ISLNK(mode) ? entry_kind::link
                            : entry_kind::other;
                made.permissions = static_cast<std::uint32_t>(mode & 07777);
            }
            if (attributes.flags & LIBSSH2_SFTP_ATTR_SIZE) made.size = attributes.filesize;
            if (attributes.flags & LIBSSH2_SFTP_ATTR_ACMODTIME)
                made.modified = std::chrono::system_clock::time_point{std::chrono::seconds{attributes.mtime}};
            return made;
        }

        std::string parent_of(const std::string &path) {
            const auto slash = path.find_last_of('/');
            return slash == std::string::npos ? std::string{} : path.substr(0, slash);
        }

        // A TCP connection to host:port within timeout, IPv4 or IPv6.
        int open_socket(const std::string &host, const std::uint16_t port, const std::chrono::milliseconds timeout) {
            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            addrinfo *found = nullptr;
            if (const int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &found); rc != 0)
                throw error{"can't find " + host + ": " + gai_strerror(rc), reason::no_connection};
            std::string why = "no address";
            for (const addrinfo *at = found; at; at = at->ai_next) {
                const int fd = socket(at->ai_family, at->ai_socktype, at->ai_protocol);
                if (fd < 0) continue;
                const int flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                int rc = ::connect(fd, at->ai_addr, at->ai_addrlen);
                if (rc != 0 && errno == EINPROGRESS) {
                    pollfd wait{fd, POLLOUT, 0};
                    rc = poll(&wait, 1, static_cast<int>(timeout.count()));
                    if (rc == 1) {
                        int problem = 0;
                        socklen_t length = sizeof problem;
                        getsockopt(fd, SOL_SOCKET, SO_ERROR, &problem, &length);
                        rc = problem == 0 ? 0 : -1;
                        errno = problem;
                    } else {
                        if (rc == 0) errno = ETIMEDOUT;
                        rc = -1;
                    }
                }
                if (rc == 0) {
                    fcntl(fd, F_SETFL, flags);
                    freeaddrinfo(found);
                    return fd;
                }
                why = std::strerror(errno == 0 ? ETIMEDOUT : errno);
                close(fd);
            }
            freeaddrinfo(found);
            throw error{"can't connect to " + host + ":" + std::to_string(port) + ": " + why, reason::no_connection};
        }

        std::filesystem::path default_known_hosts() {
            const char *home = std::getenv("HOME");
            return std::filesystem::path{home ? home : ""} / ".ssh" / "known_hosts";
        }

        void set_local_time(const std::filesystem::path &file, const std::chrono::system_clock::time_point when) {
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(when.time_since_epoch()).count();
            timeval times[2]{{static_cast<time_t>(seconds), 0}, {static_cast<time_t>(seconds), 0}};
            utimes(file.c_str(), times);
        }
    }

    struct client::state {
        int socket = -1;
        LIBSSH2_SESSION *session = nullptr;
        LIBSSH2_SFTP *sftp = nullptr;
        std::chrono::steady_clock::time_point last_request{};

        ~state() { close(false); }

        // Ends the session; polite: tell the server first (not when the connection is gone).
        void close(const bool polite) {
            if (sftp) libssh2_sftp_shutdown(sftp);
            sftp = nullptr;
            if (session) {
                if (polite) libssh2_session_disconnect(session, "closing");
                libssh2_session_free(session);
            }
            session = nullptr;
            if (socket >= 0) ::close(socket);
            socket = -1;
        }

        [[nodiscard]] std::string last_message() const {
            char *message = nullptr;
            int length = 0;
            if (session) libssh2_session_last_error(session, &message, &length, 0);
            return message && length > 0 ? std::string{message, static_cast<std::size_t>(length)} : std::string{"unknown error"};
        }

        // The failure of a call that returned rc (or a null handle: rc from the session), as an error; a lost
        // connection ends the session.
        [[noreturn]] void fail(const std::string &what, int rc = 0) {
            if (rc == 0 && session) rc = libssh2_session_last_errno(session);
            reason why = reason::other;
            std::string detail;
            if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL && sftp) {
                const auto status = libssh2_sftp_last_error(sftp);
                why = from_status(status);
                detail = reason_name(why);
            } else {
                detail = last_message();
                switch (rc) {
                    case LIBSSH2_ERROR_TIMEOUT: why = reason::timeout; break;
                    case LIBSSH2_ERROR_SOCKET_SEND:
                    case LIBSSH2_ERROR_SOCKET_RECV:
                    case LIBSSH2_ERROR_SOCKET_DISCONNECT:
                    case LIBSSH2_ERROR_SOCKET_TIMEOUT:
                    case LIBSSH2_ERROR_CHANNEL_CLOSED:
                    case LIBSSH2_ERROR_CHANNEL_EOF_SENT:
                    case LIBSSH2_ERROR_BANNER_RECV:
                    case LIBSSH2_ERROR_KEX_FAILURE:
                    case LIBSSH2_ERROR_PROTO: why = reason::connection_lost; break;
                    default: break;
                }
            }
            if (why == reason::timeout || why == reason::connection_lost || why == reason::no_connection) close(false);
            throw error{what + ": " + detail, why};
        }
    };

    namespace {
        // An open file or folder on the server, closed when it goes.
        struct handle {
            LIBSSH2_SFTP_HANDLE *raw = nullptr;
            ~handle() { if (raw) libssh2_sftp_close_handle(raw); }
            handle() = default;
            handle(const handle &) = delete;
            handle &operator=(const handle &) = delete;
            // Closes it now, so a failure to close (a write the server refused at the end) is seen.
            int close() {
                const int rc = raw ? libssh2_sftp_close_handle(raw) : 0;
                raw = nullptr;
                return rc;
            }
        };
    }

    client::client(options how) : options_{std::move(how)}, state_{std::make_unique<state>()} {
        if (options_.known_hosts.empty()) options_.known_hosts = default_known_hosts();
    }

    client::~client() {
        if (state_) state_->close(true);
    }

    client::client(client &&) noexcept = default;
    client &client::operator=(client &&) noexcept = default;

    bool client::connected() const { return state_ && state_->sftp; }

    void client::disconnect() {
        if (state_) state_->close(true);
    }

    void client::connect() {
        if (connected()) return;
        start_libssh2();
        auto &s = *state_;
        s.close(false);
        const std::string where = options_.user + "@" + options_.host + ":" + std::to_string(options_.port);
        s.socket = open_socket(options_.host, options_.port, options_.timeout);
        s.session = libssh2_session_init();
        if (!s.session) {
            s.close(false);
            throw error{"can't start an SSH session", reason::other};
        }
        libssh2_session_set_blocking(s.session, 1);
        libssh2_session_set_timeout(s.session, static_cast<long>(options_.timeout.count()));
        if (const int rc = libssh2_session_handshake(s.session, s.socket); rc != 0) s.fail("SSH handshake with " + where, rc);

        // The host key against known_hosts
        std::size_t key_length = 0;
        int key_type = 0;
        const char *key = libssh2_session_hostkey(s.session, &key_length, &key_type);
        if (!key) s.fail("no host key from " + where);
        LIBSSH2_KNOWNHOSTS *known = libssh2_knownhost_init(s.session);
        const bool readable = libssh2_knownhost_readfile(known, options_.known_hosts.c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH) >= 0;
        libssh2_knownhost *found = nullptr;
        const int check = readable
                              ? libssh2_knownhost_checkp(known, options_.host.c_str(), options_.port, key, key_length,
                                                         LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW, &found)
                              : LIBSSH2_KNOWNHOST_CHECK_NOTFOUND;
        const std::string fingerprint_text = fingerprint();
        if (check == LIBSSH2_KNOWNHOST_CHECK_MISMATCH) {
            libssh2_knownhost_free(known);
            s.close(false);
            throw error{"the host key of " + options_.host + " (" + fingerprint_text + ") isn't the one in " + options_.known_hosts.string()
                        + ": refused (if the server's key really changed, remove its line)", reason::host_key_changed};
        }
        if (check != LIBSSH2_KNOWNHOST_CHECK_MATCH) {
            if (options_.host_key != host_key_check::accept_new) {
                libssh2_knownhost_free(known);
                s.close(false);
                throw error{options_.host + " (" + fingerprint_text + ") isn't in " + options_.known_hosts.string(), reason::host_key_unknown};
            }
            int key_bits = 0;
            switch (key_type) {
                case LIBSSH2_HOSTKEY_TYPE_RSA: key_bits = LIBSSH2_KNOWNHOST_KEY_SSHRSA; break;
                case LIBSSH2_HOSTKEY_TYPE_DSS: key_bits = LIBSSH2_KNOWNHOST_KEY_SSHDSS; break;
                case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: key_bits = LIBSSH2_KNOWNHOST_KEY_ECDSA_256; break;
                case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: key_bits = LIBSSH2_KNOWNHOST_KEY_ECDSA_384; break;
                case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: key_bits = LIBSSH2_KNOWNHOST_KEY_ECDSA_521; break;
                case LIBSSH2_HOSTKEY_TYPE_ED25519: key_bits = LIBSSH2_KNOWNHOST_KEY_ED25519; break;
                default: break;
            }
            const std::string name = options_.port == 22 ? options_.host : "[" + options_.host + "]:" + std::to_string(options_.port);
            libssh2_knownhost *added = nullptr;
            std::array<char, 8192> line{};
            std::size_t line_length = 0;
            bool written = false;
            if (key_bits && libssh2_knownhost_addc(known, name.c_str(), nullptr, key, key_length, nullptr, 0,
                                                   LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | key_bits, &added) == 0
                && libssh2_knownhost_writeline(known, added, line.data(), line.size(), &line_length, LIBSSH2_KNOWNHOST_FILE_OPENSSH) == 0) {
                // Appended, so the file's other lines (comments, keys libssh2 doesn't read) stay as they are
                std::error_code ignored;
                std::filesystem::create_directories(options_.known_hosts.parent_path(), ignored);
                std::ofstream out{options_.known_hosts, std::ios::app};
                out.write(line.data(), static_cast<std::streamsize>(line_length));
                written = static_cast<bool>(out);
            }
            if (!written) {
                libssh2_knownhost_free(known);
                s.close(false);
                throw error{"can't add " + options_.host + " (" + fingerprint_text + ") to " + options_.known_hosts.string(), reason::host_key_unknown};
            }
        }
        libssh2_knownhost_free(known);

        // Signing in: the key, the password, the agent, as far as given
        bool signed_in = false;
        std::string tried;
        if (!options_.key.empty()) {
            tried = "key " + options_.key.string();
            signed_in = libssh2_userauth_publickey_fromfile_ex(s.session, options_.user.c_str(), static_cast<unsigned>(options_.user.size()), nullptr,
                                                               options_.key.c_str(), options_.passphrase.empty() ? nullptr : options_.passphrase.c_str()) == 0;
        }
        if (!signed_in && !options_.password.empty()) {
            tried += tried.empty() ? "password" : ", password";
            signed_in = libssh2_userauth_password_ex(s.session, options_.user.c_str(), static_cast<unsigned>(options_.user.size()),
                                                     options_.password.c_str(), static_cast<unsigned>(options_.password.size()), nullptr) == 0;
        }
        if (!signed_in && options_.agent) {
            tried += tried.empty() ? "agent" : ", agent";
            if (LIBSSH2_AGENT *agent = libssh2_agent_init(s.session)) {
                if (libssh2_agent_connect(agent) == 0 && libssh2_agent_list_identities(agent) == 0) {
                    libssh2_agent_publickey *identity = nullptr, *previous = nullptr;
                    while (!signed_in && libssh2_agent_get_identity(agent, &identity, previous) == 0) {
                        signed_in = libssh2_agent_userauth(agent, options_.user.c_str(), identity) == 0;
                        previous = identity;
                    }
                    libssh2_agent_disconnect(agent);
                }
                libssh2_agent_free(agent);
            }
        }
        if (!signed_in) {
            const std::string message = tried.empty() ? "no key, password or agent given" : tried + " refused (" + s.last_message() + ")";
            s.close(false);
            throw error{"can't sign in to " + where + ": " + message, reason::authentication_failed};
        }

        s.sftp = libssh2_sftp_init(s.session);
        if (!s.sftp) s.fail("can't start SFTP on " + where);
        s.last_request = std::chrono::steady_clock::now();
    }

    std::string client::fingerprint() {
        if (!state_->session) connect();
        const auto *hash = reinterpret_cast<const unsigned char *>(libssh2_hostkey_hash(state_->session, LIBSSH2_HOSTKEY_HASH_SHA256));
        return hash ? "SHA256:" + base64(hash, 32) : std::string{"unknown"};
    }

    std::vector<entry> client::list(const std::string &folder) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        handle opened;
        opened.raw = libssh2_sftp_open_ex(s.sftp, folder.c_str(), static_cast<unsigned>(folder.size()), 0, 0, LIBSSH2_SFTP_OPENDIR);
        if (!opened.raw) s.fail("can't list " + folder);
        std::vector<entry> entries;
        std::array<char, 4096> name{};
        while (true) {
            LIBSSH2_SFTP_ATTRIBUTES attributes{};
            const int length = libssh2_sftp_readdir_ex(opened.raw, name.data(), name.size(), nullptr, 0, &attributes);
            if (length == 0) break;
            if (length < 0) s.fail("can't list " + folder, length);
            std::string text{name.data(), static_cast<std::size_t>(length)};
            if (text == "." || text == "..") continue;
            entries.push_back(entry_of(std::move(text), attributes));
        }
        return entries;
    }

    std::optional<entry> client::stat(const std::string &path, const bool follow) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        LIBSSH2_SFTP_ATTRIBUTES attributes{};
        const int rc = libssh2_sftp_stat_ex(s.sftp, path.c_str(), static_cast<unsigned>(path.size()), follow ? LIBSSH2_SFTP_STAT : LIBSSH2_SFTP_LSTAT,
                                            &attributes);
        if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL) {
            const auto status = libssh2_sftp_last_error(s.sftp);
            if (status == LIBSSH2_FX_NO_SUCH_FILE || status == LIBSSH2_FX_NO_SUCH_PATH) return std::nullopt;
        }
        if (rc != 0) s.fail("can't stat " + path, rc);
        const auto slash = path.find_last_of('/');
        return entry_of(slash == std::string::npos ? path : path.substr(slash + 1), attributes);
    }

    bool client::exists(const std::string &path) { return stat(path, false).has_value(); }

    std::string client::real_path(const std::string &path) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        std::array<char, 4096> resolved{};
        const int length = libssh2_sftp_realpath(s.sftp, path.c_str(), resolved.data(), static_cast<unsigned>(resolved.size()));
        if (length < 0) s.fail("can't resolve " + path, length);
        return {resolved.data(), static_cast<std::size_t>(length)};
    }

    std::uint64_t client::download(const std::string &remote, const std::filesystem::path &local, const transfer_options &how) {
        if (!how.overwrite && std::filesystem::exists(local))
            throw error{"can't download " + remote + ": " + local.string() + " is there already", reason::file_exists};
        const auto source = stat(remote);
        if (!source) throw error{"can't download " + remote + ": no such file", reason::no_such_file};
        auto &s = *state_;
        handle opened;
        opened.raw = libssh2_sftp_open_ex(s.sftp, remote.c_str(), static_cast<unsigned>(remote.size()), LIBSSH2_FXF_READ, 0, LIBSSH2_SFTP_OPENFILE);
        if (!opened.raw) s.fail("can't open " + remote);

        const std::filesystem::path target = how.temporary ? std::filesystem::path{local.string() + how.suffix} : local;
        std::ofstream out{target, std::ios::binary | std::ios::trunc};
        if (!out) throw error{"can't write " + target.string() + ": " + std::strerror(errno), reason::local};
        const auto discard = [&] {
            out.close();
            std::error_code ignored;
            if (how.temporary) std::filesystem::remove(target, ignored);
        };
        std::vector<char> buffer(chunk);
        std::uint64_t done = 0;
        while (true) {
            s.last_request = std::chrono::steady_clock::now();
            const auto got = libssh2_sftp_read(opened.raw, buffer.data(), buffer.size());
            if (got == 0) break;
            if (got < 0) {
                discard();
                s.fail("can't read " + remote, static_cast<int>(got));
            }
            out.write(buffer.data(), got);
            if (!out) {
                const std::string why = std::strerror(errno);
                discard();
                throw error{"can't write " + target.string() + ": " + why, reason::local};
            }
            done += static_cast<std::uint64_t>(got);
            if (how.progress) how.progress(done, source->size);
        }
        out.close();
        if (!out) {
            discard();
            throw error{"can't write " + target.string(), reason::local};
        }
        if (how.keep_time && source->modified.time_since_epoch().count() != 0) set_local_time(target, source->modified);
        if (how.temporary) {
            std::error_code problem;
            std::filesystem::rename(target, local, problem);
            if (problem) {
                discard();
                throw error{"can't rename " + target.string() + " to " + local.string() + ": " + problem.message(), reason::local};
            }
        }
        return done;
    }

    std::uint64_t client::upload(const std::filesystem::path &local, const std::string &remote, const transfer_options &how) {
        std::ifstream in{local, std::ios::binary};
        if (!in) throw error{"can't read " + local.string() + ": " + std::strerror(errno), reason::local};
        std::error_code problem;
        const auto total = std::filesystem::file_size(local, problem);
        std::uint64_t done = 0;
        std::vector<char> buffer(chunk);
        const auto feed = [&](const std::function<void(const char *, std::size_t)> &send) {
            while (in) {
                in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
                const auto got = static_cast<std::size_t>(in.gcount());
                if (got == 0) break;
                send(buffer.data(), got);
                done += got;
                if (how.progress) how.progress(done, problem ? 0 : total);
            }
            if (in.bad()) throw error{"can't read " + local.string(), reason::local};
        };
        std::optional<std::chrono::system_clock::time_point> modified;
        if (how.keep_time) {
            struct ::stat info{};
            if (::stat(local.c_str(), &info) == 0) modified = std::chrono::system_clock::time_point{std::chrono::seconds{info.st_mtime}};
        }
        // The copy, then its time and name
        const auto send_file = [&](LIBSSH2_SFTP_HANDLE *raw, const std::string &name) {
            auto &s = *state_;
            feed([&](const char *data, std::size_t size) {
                while (size > 0) {
                    s.last_request = std::chrono::steady_clock::now();
                    const auto sent = libssh2_sftp_write(raw, data, size);
                    if (sent < 0) s.fail("can't write " + name, static_cast<int>(sent));
                    data += sent;
                    size -= static_cast<std::size_t>(sent);
                }
            });
        };
        connect();
        if (!how.overwrite && exists(remote)) throw error{"can't upload to " + remote + ": a file is there already", reason::file_exists};
        auto &s = *state_;
        const std::string target = how.temporary ? remote + how.suffix : remote;
        handle opened;
        opened.raw = libssh2_sftp_open_ex(s.sftp, target.c_str(), static_cast<unsigned>(target.size()),
                                          LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0644, LIBSSH2_SFTP_OPENFILE);
        if (!opened.raw) s.fail("can't create " + target);
        try {
            send_file(opened.raw, target);
            if (const int rc = opened.close(); rc != 0) s.fail("can't finish " + target, rc);
            if (modified) set_modified(target, *modified);
            if (how.temporary) rename(target, remote, how.overwrite);
        } catch (const error &failed) {
            // A partial copy under the temporary name goes (when the connection is still there)
            if (how.temporary && !failed.lost() && connected()) {
                opened.close();
                libssh2_sftp_unlink_ex(state_->sftp, target.c_str(), static_cast<unsigned>(target.size()));
            }
            throw;
        }
        return done;
    }

    std::string client::read(const std::string &remote) {
        connect();
        auto &s = *state_;
        handle opened;
        opened.raw = libssh2_sftp_open_ex(s.sftp, remote.c_str(), static_cast<unsigned>(remote.size()), LIBSSH2_FXF_READ, 0, LIBSSH2_SFTP_OPENFILE);
        if (!opened.raw) s.fail("can't open " + remote);
        std::string content;
        std::vector<char> buffer(chunk);
        while (true) {
            s.last_request = std::chrono::steady_clock::now();
            const auto got = libssh2_sftp_read(opened.raw, buffer.data(), buffer.size());
            if (got == 0) break;
            if (got < 0) s.fail("can't read " + remote, static_cast<int>(got));
            content.append(buffer.data(), static_cast<std::size_t>(got));
        }
        return content;
    }

    void client::write(const std::string &remote, const std::string &content, const transfer_options &how) {
        connect();
        if (!how.overwrite && exists(remote)) throw error{"can't write " + remote + ": a file is there already", reason::file_exists};
        auto &s = *state_;
        const std::string target = how.temporary ? remote + how.suffix : remote;
        handle opened;
        opened.raw = libssh2_sftp_open_ex(s.sftp, target.c_str(), static_cast<unsigned>(target.size()),
                                          LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0644, LIBSSH2_SFTP_OPENFILE);
        if (!opened.raw) s.fail("can't create " + target);
        const char *data = content.data();
        std::size_t left = content.size();
        while (left > 0) {
            s.last_request = std::chrono::steady_clock::now();
            const auto sent = libssh2_sftp_write(opened.raw, data, std::min(left, chunk));
            if (sent < 0) s.fail("can't write " + target, static_cast<int>(sent));
            data += sent;
            left -= static_cast<std::size_t>(sent);
            if (how.progress) how.progress(content.size() - left, content.size());
        }
        if (const int rc = opened.close(); rc != 0) s.fail("can't finish " + target, rc);
        if (how.temporary) rename(target, remote, how.overwrite);
    }

    void client::rename(const std::string &from, const std::string &to, const bool overwrite) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        const auto attempt = [&] {
            return libssh2_sftp_rename_ex(s.sftp, from.c_str(), static_cast<unsigned>(from.size()), to.c_str(), static_cast<unsigned>(to.size()),
                                          LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE);
        };
        int rc = attempt();
        // SFTP version 3 (OpenSSH) won't rename onto a file: with overwrite, that file goes first
        if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL && overwrite) {
            const auto status = libssh2_sftp_last_error(s.sftp);
            if ((status == LIBSSH2_FX_FAILURE || status == LIBSSH2_FX_FILE_ALREADY_EXISTS) && exists(to)) {
                remove(to);
                rc = attempt();
            }
        } else if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL && libssh2_sftp_last_error(s.sftp) == LIBSSH2_FX_FAILURE && exists(to)) {
            throw error{"can't rename " + from + " to " + to + ": a file is there already", reason::file_exists};
        }
        if (rc != 0) s.fail("can't rename " + from + " to " + to, rc);
    }

    void client::remove(const std::string &path) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        if (const int rc = libssh2_sftp_unlink_ex(s.sftp, path.c_str(), static_cast<unsigned>(path.size())); rc != 0) s.fail("can't remove " + path, rc);
    }

    void client::make_folder(const std::string &path, const std::uint32_t permissions) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        if (const int rc = libssh2_sftp_mkdir_ex(s.sftp, path.c_str(), static_cast<unsigned>(path.size()), static_cast<long>(permissions)); rc != 0)
            s.fail("can't make folder " + path, rc);
    }

    void client::remove_folder(const std::string &path) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        if (const int rc = libssh2_sftp_rmdir_ex(s.sftp, path.c_str(), static_cast<unsigned>(path.size())); rc != 0) s.fail("can't remove folder " + path, rc);
    }

    void client::set_modified(const std::string &path, const std::chrono::system_clock::time_point when) {
        connect();
        auto &s = *state_;
        s.last_request = std::chrono::steady_clock::now();
        LIBSSH2_SFTP_ATTRIBUTES attributes{};
        attributes.flags = LIBSSH2_SFTP_ATTR_ACMODTIME;
        attributes.atime = attributes.mtime = static_cast<unsigned long>(std::chrono::duration_cast<std::chrono::seconds>(when.time_since_epoch()).count());
        if (const int rc = libssh2_sftp_stat_ex(s.sftp, path.c_str(), static_cast<unsigned>(path.size()), LIBSSH2_SFTP_SETSTAT, &attributes); rc != 0)
            s.fail("can't set the time of " + path, rc);
    }

    void client::keep_alive() {
        if (!connected() || options_.keepalive.count() <= 0) return;
        if (std::chrono::steady_clock::now() - state_->last_request < options_.keepalive) return;
        // A real round trip, so a connection that's gone is noticed (and thrown) now, not on the next transfer
        (void) real_path(".");
    }
}
