// sc::sftp::client against a throwaway OpenSSH sshd on 127.0.0.1 (a free port, its own host key, run as the user
// running the test): host keys (strict, accept_new, a changed key), signing in (keys, a passphrase, a wrong key),
// listing, reading and writing, uploads and downloads under a temporary name with their times, renames over a file,
// removing, errors with their reasons, reconnecting and timeouts. The server's files are local, so they're checked
// on disk. Skipped (77) without sshd or ssh-keygen.
#include <sc/sftp/sc_sftp.h>
#include <sc_test.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {
    fs::path find_program(const std::string &name, const std::vector<std::string> &places) {
        for (const auto &place: places)
            if (fs::exists(place + "/" + name)) return place + "/" + name;
        return {};
    }

    std::string slurp(const fs::path &file) {
        std::ifstream in{file, std::ios::binary};
        std::stringstream text;
        text << in.rdbuf();
        return text.str();
    }

    void spill(const fs::path &file, const std::string &content) {
        std::ofstream out{file, std::ios::binary | std::ios::trunc};
        out << content;
    }

    int run(const std::string &command) { return std::system((command + " >/dev/null 2>&1").c_str()); }

    std::string output_of(const std::string &command) {
        std::string out;
        if (FILE *pipe = popen(command.c_str(), "r")) {
            char buffer[512];
            while (fgets(buffer, sizeof buffer, pipe)) out += buffer;
            pclose(pipe);
        }
        return out;
    }

    // A port nobody listens on right now
    std::uint16_t free_port() {
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof address);
        socklen_t length = sizeof address;
        getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length);
        close(fd);
        return ntohs(address.sin_port);
    }

    bool port_open(const std::uint16_t port) {
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        const bool open = ::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof address) == 0;
        close(fd);
        return open;
    }

    std::string random_bytes(const std::size_t size) {
        std::mt19937 generator{20261112};
        std::string bytes(size, '\0');
        for (auto &byte: bytes) byte = static_cast<char>(generator() & 0xff);
        return bytes;
    }

    template<typename Call>
    sc::sftp::reason reason_of(Call call) {
        try {
            call();
        } catch (const sc::sftp::error &failed) {
            return failed.why();
        }
        return sc::sftp::reason::other; // didn't throw
    }
}

int main() {
    const auto sshd = find_program("sshd", {"/usr/sbin", "/usr/local/sbin", "/opt/homebrew/sbin"});
    const auto keygen = find_program("ssh-keygen", {"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"});
    if (sshd.empty() || keygen.empty()) {
        std::cout << "SKIPPED: no sshd or ssh-keygen\n";
        return 77;
    }
    const passwd *me = getpwuid(getuid());
    const std::string user = me ? me->pw_name : "";
    // sshd as root wants its privilege separation folder
    if (getuid() == 0 && !fs::exists("/run/sshd")) {
        std::error_code ignored;
        fs::create_directories("/run/sshd", ignored);
    }

    // The server: its keys, the user's keys (one with a passphrase), its configuration
    const fs::path work = fs::temp_directory_path() / ("sc-sftp-test-" + std::to_string(getpid()));
    fs::remove_all(work);
    fs::create_directories(work / "remote");
    const auto key = [&](const std::string &name, const std::string &passphrase = "") {
        return run(keygen.string() + " -q -t ed25519 -N '" + passphrase + "' -C test -f " + (work / name).string()) == 0;
    };
    if (!key("host_key") || !key("other_host_key") || !key("user_key") || !key("passphrase_key", "secret words") || !key("stranger_key")) {
        std::cout << "SKIPPED: ssh-keygen failed\n";
        return 77;
    }
    spill(work / "authorized_keys", slurp(work / "user_key.pub") + slurp(work / "passphrase_key.pub"));
    fs::permissions(work / "authorized_keys", fs::perms::owner_read | fs::perms::owner_write);
    const std::uint16_t port = free_port();
    spill(work / "sshd_config", "Port " + std::to_string(port) + "\nListenAddress 127.0.0.1\nHostKey " + (work / "host_key").string()
                                + "\nAuthorizedKeysFile " + (work / "authorized_keys").string() + "\nPidFile " + (work / "sshd.pid").string()
                                + "\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                                + "PermitRootLogin prohibit-password\nSubsystem sftp internal-sftp\n");
    const pid_t server = fork();
    if (server == 0) {
        execl(sshd.c_str(), sshd.c_str(), "-D", "-f", (work / "sshd_config").c_str(), "-E", (work / "sshd.log").c_str(), nullptr);
        _exit(127);
    }
    for (int i = 0; i < 100 && !port_open(port); ++i) std::this_thread::sleep_for(50ms);
    if (!port_open(port)) {
        std::cout << "SKIPPED: sshd didn't start: " << slurp(work / "sshd.log") << "\n";
        kill(server, SIGTERM);
        waitpid(server, nullptr, 0);
        fs::remove_all(work);
        return 77;
    }

    const auto settings = [&](const sc::sftp::host_key_check check) {
        sc::sftp::options how;
        how.host = "127.0.0.1";
        how.port = port;
        how.user = user;
        how.key = work / "user_key";
        how.known_hosts = work / "known_hosts";
        how.host_key = check;
        how.timeout = 10s;
        return how;
    };
    const std::string remote = (work / "remote").string();
    // ssh-keygen's fingerprint of the host key, as the client should show it
    const std::string expected_fingerprint = [&] {
        std::istringstream line{output_of(keygen.string() + " -lf " + (work / "host_key.pub").string())};
        std::string bits, print;
        line >> bits >> print;
        return print;
    }();

    SECTION("Host keys: strict refuses a host that isn't known; accept_new adds it, then strict accepts it");
    {
        sc::sftp::client strict{settings(sc::sftp::host_key_check::strict)};
        CHECK(reason_of([&] { strict.connect(); }) == sc::sftp::reason::host_key_unknown);
        CHECK(!strict.connected());
        CHECK(!fs::exists(work / "known_hosts"));

        sc::sftp::client fresh{settings(sc::sftp::host_key_check::accept_new)};
        CHECK_NOTHROW(fresh.connect());
        CHECK(fresh.connected());
        CHECK_EQ(fresh.fingerprint(), expected_fingerprint);
        const auto known = slurp(work / "known_hosts");
        CHECK(known.rfind("[127.0.0.1]:" + std::to_string(port) + " ssh-ed25519 ", 0) == 0);

        sc::sftp::client again{settings(sc::sftp::host_key_check::strict)};
        CHECK_NOTHROW(again.connect());
        CHECK_EQ(slurp(work / "known_hosts"), known); // nothing added twice
    }

    SECTION("A host key that changed is refused, whatever the check");
    {
        const auto known = slurp(work / "known_hosts");
        std::istringstream other{slurp(work / "other_host_key.pub")};
        std::string type, blob;
        other >> type >> blob;
        spill(work / "changed_hosts", "# a comment stays\n[127.0.0.1]:" + std::to_string(port) + " " + type + " " + blob + "\n");
        for (const auto check: {sc::sftp::host_key_check::strict, sc::sftp::host_key_check::accept_new}) {
            auto how = settings(check);
            how.known_hosts = work / "changed_hosts";
            sc::sftp::client changed{how};
            CHECK(reason_of([&] { changed.connect(); }) == sc::sftp::reason::host_key_changed);
        }
        CHECK(slurp(work / "changed_hosts").rfind("# a comment stays\n", 0) == 0);
        CHECK_EQ(slurp(work / "known_hosts"), known);
    }

    SECTION("Signing in: a key with its passphrase; a key the server doesn't know, a wrong passphrase, nothing at all");
    {
        auto how = settings(sc::sftp::host_key_check::strict);
        how.key = work / "passphrase_key";
        how.passphrase = "secret words";
        sc::sftp::client with_passphrase{how};
        CHECK_NOTHROW(with_passphrase.connect());

        how.passphrase = "wrong words";
        sc::sftp::client wrong_passphrase{how};
        CHECK(reason_of([&] { wrong_passphrase.connect(); }) == sc::sftp::reason::authentication_failed);

        how = settings(sc::sftp::host_key_check::strict);
        how.key = work / "stranger_key";
        sc::sftp::client stranger{how};
        CHECK(reason_of([&] { stranger.connect(); }) == sc::sftp::reason::authentication_failed);

        how.key.clear();
        sc::sftp::client nothing{how};
        CHECK(reason_of([&] { nothing.connect(); }) == sc::sftp::reason::authentication_failed);
    }

    sc::sftp::client sftp{settings(sc::sftp::host_key_check::strict)};

    SECTION("Folders and small files: written, read, listed, looked at");
    {
        CHECK_NOTHROW(sftp.make_folder(remote + "/IN"));
        CHECK(fs::is_directory(work / "remote" / "IN"));
        CHECK_NOTHROW(sftp.write(remote + "/IN/hello.txt", "Hello, world\n"));
        CHECK_EQ(slurp(work / "remote" / "IN" / "hello.txt"), std::string{"Hello, world\n"});
        CHECK(!fs::exists(work / "remote" / "IN" / "hello.txt.part"));
        CHECK_EQ(sftp.read(remote + "/IN/hello.txt"), std::string{"Hello, world\n"});

        const auto entries = sftp.list(remote);
        CHECK_EQ(entries.size(), std::size_t{1});
        CHECK(!entries.empty() && entries[0].name == "IN" && entries[0].is_folder());
        const auto inside = sftp.list(remote + "/IN");
        CHECK(inside.size() == 1 && inside[0].name == "hello.txt" && inside[0].is_file() && inside[0].size == 13);

        const auto found = sftp.stat(remote + "/IN/hello.txt");
        CHECK(found.has_value() && found->size == 13 && found->is_file() && found->permissions != 0);
        CHECK(!sftp.stat(remote + "/IN/missing.txt").has_value());
        CHECK(sftp.exists(remote + "/IN"));
        CHECK(!sftp.exists(remote + "/OUT"));
        CHECK_EQ(sftp.real_path(remote + "/IN/../IN"), fs::canonical(work / "remote" / "IN").string());
    }

    SECTION("Uploads: under a temporary name, renamed, the modified time kept; a file there already when not overwriting");
    {
        const auto content = random_bytes(3 * 1024 * 1024 + 17);
        spill(work / "big.bin", content);
        const auto when = std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}};
        const timeval times[2]{{1700000000, 0}, {1700000000, 0}};
        utimes((work / "big.bin").c_str(), times);

        std::uint64_t reported = 0, total = 0;
        sc::sftp::transfer_options how;
        how.progress = [&](const std::uint64_t done, const std::uint64_t all) {
            reported = done;
            total = all;
        };
        CHECK_EQ(sftp.upload(work / "big.bin", remote + "/IN/big.bin", how), std::uint64_t{content.size()});
        CHECK(slurp(work / "remote" / "IN" / "big.bin") == content);
        CHECK(!fs::exists(work / "remote" / "IN" / "big.bin.part"));
        CHECK_EQ(reported, std::uint64_t{content.size()});
        CHECK_EQ(total, std::uint64_t{content.size()});
        const auto uploaded = sftp.stat(remote + "/IN/big.bin");
        CHECK(uploaded && uploaded->modified == when && uploaded->size == content.size());

        // Overwriting by default; refused without it
        spill(work / "small.txt", "new content");
        CHECK_NOTHROW(sftp.upload(work / "small.txt", remote + "/IN/hello.txt"));
        CHECK_EQ(slurp(work / "remote" / "IN" / "hello.txt"), std::string{"new content"});
        sc::sftp::transfer_options keep;
        keep.overwrite = false;
        CHECK(reason_of([&] { sftp.upload(work / "small.txt", remote + "/IN/hello.txt", keep); }) == sc::sftp::reason::file_exists);
        // Straight to its name, for a server that can't rename
        sc::sftp::transfer_options direct;
        direct.temporary = false;
        CHECK_NOTHROW(sftp.upload(work / "small.txt", remote + "/IN/direct.txt", direct));
        CHECK_EQ(slurp(work / "remote" / "IN" / "direct.txt"), std::string{"new content"});
        // A local file that isn't there
        CHECK(reason_of([&] { sftp.upload(work / "nothing.txt", remote + "/IN/x"); }) == sc::sftp::reason::local);
    }

    SECTION("Downloads: under a temporary name, renamed, the modified time kept; refused over a file when asked");
    {
        CHECK_EQ(sftp.download(remote + "/IN/big.bin", work / "copy.bin"), std::uint64_t{3 * 1024 * 1024 + 17});
        CHECK(slurp(work / "copy.bin") == slurp(work / "big.bin"));
        CHECK(!fs::exists(work / "copy.bin.part"));
        struct stat info{};
        ::stat((work / "copy.bin").c_str(), &info);
        CHECK_EQ(static_cast<long>(info.st_mtime), 1700000000L);

        sc::sftp::transfer_options keep;
        keep.overwrite = false;
        CHECK(reason_of([&] { sftp.download(remote + "/IN/big.bin", work / "copy.bin", keep); }) == sc::sftp::reason::file_exists);
        CHECK(reason_of([&] { sftp.download(remote + "/IN/missing.bin", work / "missing.bin"); }) == sc::sftp::reason::no_such_file);
        CHECK(!fs::exists(work / "missing.bin") && !fs::exists(work / "missing.bin.part"));
    }

    SECTION("Renames, removing, and the server's reasons for refusing");
    {
        CHECK_NOTHROW(sftp.rename(remote + "/IN/direct.txt", remote + "/IN/renamed.txt"));
        CHECK(fs::exists(work / "remote" / "IN" / "renamed.txt") && !fs::exists(work / "remote" / "IN" / "direct.txt"));
        CHECK(reason_of([&] { sftp.rename(remote + "/IN/renamed.txt", remote + "/IN/hello.txt"); }) == sc::sftp::reason::file_exists);
        CHECK_NOTHROW(sftp.rename(remote + "/IN/renamed.txt", remote + "/IN/hello.txt", true));
        CHECK(!fs::exists(work / "remote" / "IN" / "renamed.txt"));

        CHECK(reason_of([&] { (void) sftp.read(remote + "/IN/missing.txt"); }) == sc::sftp::reason::no_such_file);
        CHECK(reason_of([&] { (void) sftp.list(remote + "/NOWHERE"); }) == sc::sftp::reason::no_such_file);
        CHECK(reason_of([&] { sftp.make_folder(remote + "/IN"); }) != sc::sftp::reason::other); // there already: refused
        CHECK(reason_of([&] { sftp.remove_folder(remote + "/IN"); }) != sc::sftp::reason::other); // not empty: refused
        CHECK(sftp.connected()); // refusals don't end the session

        const auto when = std::chrono::system_clock::time_point{std::chrono::seconds{1600000000}};
        CHECK_NOTHROW(sftp.set_modified(remote + "/IN/hello.txt", when));
        CHECK(sftp.stat(remote + "/IN/hello.txt")->modified == when);

        for (const auto &entry: sftp.list(remote + "/IN")) CHECK_NOTHROW(sftp.remove(remote + "/IN/" + entry.name));
        CHECK_NOTHROW(sftp.remove_folder(remote + "/IN"));
        CHECK(sftp.list(remote).empty());
    }

    SECTION("Reconnecting after a disconnect, keep_alive, and a server that never answers");
    {
        sftp.disconnect();
        CHECK(!sftp.connected());
        CHECK(sftp.list(remote).empty()); // connects again
        CHECK(sftp.connected());

        auto how = settings(sc::sftp::host_key_check::strict);
        how.keepalive = 1s;
        sc::sftp::client idle{how};
        idle.connect();
        std::this_thread::sleep_for(1100ms);
        CHECK_NOTHROW(idle.keep_alive());
        CHECK(idle.connected());

        // A port that accepts and says nothing: the handshake times out
        const int silent = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(silent, reinterpret_cast<sockaddr *>(&address), sizeof address);
        listen(silent, 1);
        socklen_t length = sizeof address;
        getsockname(silent, reinterpret_cast<sockaddr *>(&address), &length);
        how = settings(sc::sftp::host_key_check::strict);
        how.port = ntohs(address.sin_port);
        how.timeout = 500ms;
        sc::sftp::client mute{how};
        const auto started = std::chrono::steady_clock::now();
        try {
            mute.connect();
            CHECK_MSG(false, "connected to a server that says nothing");
        } catch (const sc::sftp::error &failed) {
            CHECK(failed.lost());
        }
        CHECK(std::chrono::steady_clock::now() - started < 5s);
        close(silent);

        // Nobody there at all
        how.port = free_port();
        sc::sftp::client nobody{how};
        CHECK(reason_of([&] { nobody.connect(); }) == sc::sftp::reason::no_connection);
    }

    kill(server, SIGTERM);
    waitpid(server, nullptr, 0);
    fs::remove_all(work);
    TEST_SUMMARY();
}
