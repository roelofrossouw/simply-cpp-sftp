// sftp-tool: one SFTP request from the command line (list, stat, get, put, cat, mv, rm, mkdir, rmdir, fingerprint),
// with the host key checked against known_hosts. For trying a server by hand, and in scripts.

#include <sc_sftp.h>

#include <params.h>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace {
    std::string time_text(const std::chrono::system_clock::time_point when) {
        const std::time_t seconds = std::chrono::system_clock::to_time_t(when);
        std::tm local{};
        localtime_r(&seconds, &local);
        std::ostringstream out;
        out << std::put_time(&local, "%Y-%m-%d %H:%M:%S");
        return out.str();
    }

    char kind_letter(const sc::sftp::entry &entry) {
        switch (entry.kind) {
            case sc::sftp::entry_kind::file: return '-';
            case sc::sftp::entry_kind::folder: return 'd';
            case sc::sftp::entry_kind::link: return 'l';
            default: return '?';
        }
    }

    void show(const sc::sftp::entry &entry) {
        std::cout << kind_letter(entry) << ' ' << std::oct << std::setw(4) << std::setfill('0') << entry.permissions << std::dec << std::setfill(' ')
                  << ' ' << std::setw(12) << entry.size << ' ' << time_text(entry.modified) << ' ' << entry.name << '\n';
    }
}

int main(int argc, char **argv) {
    const sc::params args{argc, argv, {
        {"name", "sftp-tool"},
        {"description", "Lists, copies, renames and removes files on an SFTP server. The server's host key is checked "
                        "against known_hosts; --accept-new adds a server that isn't there yet."},
        {"version", SC_SFTP_VERSION},
        {"epilog", "Commands: ls [FOLDER] lists a folder (the start folder without one); stat PATH shows one entry; "
                   "get REMOTE [LOCAL] and put LOCAL [REMOTE] copy a file, under a temporary name (NAME.part) renamed "
                   "when complete unless --direct; cat REMOTE writes a file to standard output; mv FROM TO renames "
                   "(--overwrite replaces a file at TO); rm PATH, mkdir PATH and rmdir PATH; pwd shows the start folder; "
                   "fingerprint shows the server's host key. A password or a key's passphrase is read from the "
                   "environment, SFTP_PASSWORD or SFTP_PASSPHRASE, never from the command line. Exit status: 0 done, "
                   "1 refused or failed, 2 a mistake in the command line."},
        {"options", {
            {"host", {{"short", "H"}, {"required", true}, {"value", "HOST"}, {"help", "the server"}}},
            {"port", {{"short", "p"}, {"type", "integer"}, {"default", 22}, {"value", "PORT"}}},
            {"user", {{"short", "u"}, {"value", "USER"}, {"help", "who to sign in as (default: you)"}}},
            {"key", {{"short", "i"}, {"value", "FILE"}, {"help", "the private key file to sign in with"}}},
            {"agent", {{"short", "A"}, {"type", "boolean"}, {"help", "sign in with a key from the SSH agent"}}},
            {"known-hosts", {{"value", "FILE"}, {"help", "the known_hosts file (default: ~/.ssh/known_hosts)"}}},
            {"accept-new", {{"type", "boolean"}, {"help", "add a server that isn't in known_hosts yet (a changed key is still refused)"}}},
            {"timeout", {{"short", "t"}, {"type", "integer"}, {"default", 30}, {"value", "SECONDS"}, {"help", "for connecting and each request"}}},
            {"direct", {{"type", "boolean"}, {"help", "get and put write straight to the file's name, not under a temporary one"}}},
            {"overwrite", {{"short", "f"}, {"type", "boolean"}, {"help", "get, put and mv replace a file that's there (get and put do anyway, unless --keep)"}}},
            {"keep", {{"short", "k"}, {"type", "boolean"}, {"help", "get and put refuse to replace a file that's there"}}}}},
        {"positional", {
            {"command", {{"choices", {"ls", "stat", "get", "put", "cat", "mv", "rm", "mkdir", "rmdir", "pwd", "fingerprint"}},
                         {"help", "what to do"}}}}},
        {"extra", {{"paths", {{"help", "the paths the command takes"}}}}}}};

    const std::string command = args["command"];
    std::vector<std::string> paths;
    for (const auto &path: args["paths"]) paths.push_back(path.get<std::string>());
    const auto need = [&](const std::size_t least, const std::size_t most) {
        if (paths.size() < least || paths.size() > most) {
            std::cerr << "sftp-tool: " << command << " takes " << (least == most ? std::to_string(least) : std::to_string(least) + " or " + std::to_string(most))
                      << " path" << (most == 1 ? "" : "s") << "\nTry 'sftp-tool --help' for more information.\n";
            std::exit(2);
        }
    };

    sc::sftp::options how;
    how.host = args["host"];
    how.port = static_cast<std::uint16_t>(args.as<int>("port"));
    if (args.contains("user")) how.user = args["user"];
    else if (const char *me = std::getenv("USER")) how.user = me;
    if (args.contains("key")) how.key = args["key"].get<std::string>();
    if (const char *passphrase = std::getenv("SFTP_PASSPHRASE")) how.passphrase = passphrase;
    if (const char *password = std::getenv("SFTP_PASSWORD")) how.password = password;
    how.agent = args["agent"].get<bool>() || (how.key.empty() && how.password.empty());
    if (args.contains("known-hosts")) how.known_hosts = args["known-hosts"].get<std::string>();
    how.host_key = args["accept-new"].get<bool>() ? sc::sftp::host_key_check::accept_new : sc::sftp::host_key_check::strict;
    how.timeout = std::chrono::seconds{args.as<int>("timeout")};

    sc::sftp::transfer_options transfer;
    transfer.temporary = !args["direct"].get<bool>();
    transfer.overwrite = !args["keep"].get<bool>();

    try {
        sc::sftp::client sftp{how};
        if (command == "ls") {
            need(0, 1);
            const std::string folder = paths.empty() ? "." : paths[0];
            for (const auto &entry: sftp.list(folder)) show(entry);
        } else if (command == "stat") {
            need(1, 1);
            const auto found = sftp.stat(paths[0], false);
            if (!found) {
                std::cerr << "sftp-tool: " << paths[0] << ": no such file\n";
                return 1;
            }
            show(*found);
        } else if (command == "get") {
            need(1, 2);
            const std::string local = paths.size() > 1 ? paths[1] : std::filesystem::path{paths[0]}.filename().string();
            std::cout << sftp.download(paths[0], local, transfer) << " bytes to " << local << '\n';
        } else if (command == "put") {
            need(1, 2);
            const std::string remote = paths.size() > 1 ? paths[1] : std::filesystem::path{paths[0]}.filename().string();
            std::cout << sftp.upload(paths[0], remote, transfer) << " bytes to " << remote << '\n';
        } else if (command == "cat") {
            need(1, 1);
            std::cout << sftp.read(paths[0]);
        } else if (command == "mv") {
            need(2, 2);
            sftp.rename(paths[0], paths[1], args["overwrite"].get<bool>());
        } else if (command == "rm") {
            need(1, 1);
            sftp.remove(paths[0]);
        } else if (command == "mkdir") {
            need(1, 1);
            sftp.make_folder(paths[0]);
        } else if (command == "rmdir") {
            need(1, 1);
            sftp.remove_folder(paths[0]);
        } else if (command == "pwd") {
            need(0, 0);
            std::cout << sftp.real_path(".") << '\n';
        } else if (command == "fingerprint") {
            need(0, 0);
            std::cout << sftp.fingerprint() << '\n';
        }
    } catch (const sc::sftp::error &failed) {
        std::cerr << "sftp-tool: " << failed.what() << '\n';
        return 1;
    }
    return 0;
}
