#pragma once

// SFTP for simply-cpp: a client on libssh2 that lists, reads and writes files on an SSH server, with the server's
// host key checked against known_hosts.
//
//     sc::sftp::client sftp{{.host = "sftp.example.com", .user = "h2h", .key = "/etc/example/id_ed25519",
//                            .host_key = sc::sftp::host_key_check::accept_new}};
//     for (const auto &entry: sftp.list("/IN"))
//         if (entry.is_file()) sftp.download("/IN/" + entry.name, "/var/lib/example/" + entry.name);
//     sftp.upload("/var/lib/example/out.xml", "/OUT/out.xml");
//
// The client connects on its first call and again after a lost connection. One client is one SSH session: use it
// from one thread at a time.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace sc::sftp {
    // How the server's host key is checked against the known_hosts file:
    //   strict      the key must be there already (ssh's StrictHostKeyChecking=yes);
    //   accept_new  a host not in it yet is added, one whose key changed is refused (accept-new).
    // A key that doesn't match is always refused.
    enum class host_key_check { strict, accept_new };

    struct options {
        std::string host;
        std::uint16_t port = 22;
        std::string user;
        // Signing in: a private key file (with its passphrase, if any), else a password, else the SSH agent.
        std::filesystem::path key;
        std::string passphrase;
        std::string password;
        bool agent = false;
        // Empty: ~/.ssh/known_hosts.
        std::filesystem::path known_hosts;
        host_key_check host_key = host_key_check::strict;
        // Connecting and every request; a request that takes longer fails, and the connection with it.
        std::chrono::milliseconds timeout{30000};
        // How often keep_alive() asks the server whether it's still there; 0: never.
        std::chrono::seconds keepalive{30};
    };

    enum class entry_kind { file, folder, link, other };

    // A file or folder on the server.
    struct entry {
        std::string name; // without its folder
        entry_kind kind = entry_kind::other;
        std::uint64_t size = 0;
        std::chrono::system_clock::time_point modified{};
        std::uint32_t permissions = 0; // the mode's permission bits, e.g. 0644

        [[nodiscard]] bool is_file() const { return kind == entry_kind::file; }
        [[nodiscard]] bool is_folder() const { return kind == entry_kind::folder; }
    };

    // Why a request failed, from the SFTP status the server gave, or the connection.
    enum class reason {
        no_such_file, permission_denied, failure, bad_message, no_connection, connection_lost, unsupported,
        invalid_handle, no_such_path, file_exists, write_protected, no_media, no_space, quota_exceeded,
        unknown_principal, lock_conflict, folder_not_empty, not_a_folder, invalid_filename, link_loop,
        host_key_unknown, host_key_changed, authentication_failed, timeout, local, other
    };
    const char *reason_name(reason why);

    class error : public std::runtime_error {
    public:
        error(const std::string &message, const reason why) : std::runtime_error{message}, reason_{why} {}

        [[nodiscard]] reason why() const { return reason_; }
        // The connection is gone (dropped, timed out, refused): the next call connects again.
        [[nodiscard]] bool lost() const {
            return reason_ == reason::connection_lost || reason_ == reason::no_connection || reason_ == reason::timeout;
        }

    private:
        reason reason_;
    };

    // How a file is copied.
    struct transfer_options {
        // Written under a temporary name (the name + suffix) and renamed when complete, so whoever watches the folder
        // never sees half a file. Turn it off for a server that can't rename.
        bool temporary = true;
        std::string suffix = ".part";
        // Replace a file of that name; without it a file that's there already is an error (file_exists).
        bool overwrite = true;
        // Give the copy the original's modified time.
        bool keep_time = true;
        // Called as it goes: bytes done, bytes in all (0 when unknown).
        std::function<void(std::uint64_t done, std::uint64_t total)> progress;
    };

    class client {
    public:
        explicit client(options how);
        ~client();
        client(const client &) = delete;
        client &operator=(const client &) = delete;
        client(client &&) noexcept;
        client &operator=(client &&) noexcept;

        // Connects, checks the host key and signs in; done by every call when not connected.
        void connect();
        [[nodiscard]] bool connected() const;
        void disconnect();

        // The server's host key as ssh shows it: "SHA256:..." (connects).
        [[nodiscard]] std::string fingerprint();

        // A folder's files and folders, without . and .., in the server's order.
        [[nodiscard]] std::vector<entry> list(const std::string &folder);
        // What's at path (a link itself, not where it points, with follow false); nothing when nothing is there.
        [[nodiscard]] std::optional<entry> stat(const std::string &path, bool follow = true);
        [[nodiscard]] bool exists(const std::string &path);
        // The full path the server gives for path ("." is where the session starts).
        [[nodiscard]] std::string real_path(const std::string &path);

        // Copies a file from the server to local, or from local to the server; returns the bytes copied.
        std::uint64_t download(const std::string &remote, const std::filesystem::path &local, const transfer_options &how = {});
        std::uint64_t upload(const std::filesystem::path &local, const std::string &remote, const transfer_options &how = {});
        // A file's content, and a file written from content.
        [[nodiscard]] std::string read(const std::string &remote);
        void write(const std::string &remote, const std::string &content, const transfer_options &how = {});

        // Renames from to to; with overwrite a file at to goes first (SFTP version 3 won't rename onto one).
        void rename(const std::string &from, const std::string &to, bool overwrite = false);
        void remove(const std::string &path);
        void make_folder(const std::string &path, std::uint32_t permissions = 0755);
        void remove_folder(const std::string &path);
        void set_modified(const std::string &path, std::chrono::system_clock::time_point when);

        // Keeps an idle connection open: asks the server whether it's there when options.keepalive has passed
        // since the last request. Call it while waiting between requests. A lost connection throws.
        void keep_alive();

        [[nodiscard]] const options &settings() const { return options_; }

    private:
        struct state;
        options options_;
        std::unique_ptr<state> state_;
    };
}
