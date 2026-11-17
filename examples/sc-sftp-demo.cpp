// sc-sftp's example: lists a folder on an SFTP server and copies its files here, under temporary names.
//
//     sc-sftp-demo HOST USER KEYFILE [FOLDER]
#include <sc/sftp/sc_sftp.h>

#include <sc/core/params.h>

#include <iostream>

int main(int argc, char **argv) {
    const sc::params args{argc, argv, {
        {"description", "Lists a folder on an SFTP server and downloads its files into the current folder."},
        {"positional", {
            {"host", {{"help", "the server"}}},
            {"user", {{"help", "who to sign in as"}}},
            {"key", {{"help", "the private key file"}}},
            {"folder", {{"default", "."}, {"help", "the folder on the server"}}}}}}};

    sc::sftp::client sftp{{.host = args["host"].get<std::string>(), .user = args["user"].get<std::string>(), .key = args["key"].get<std::string>(),
                           .host_key = sc::sftp::host_key_check::accept_new}};
    const std::string folder = args["folder"];
    std::cout << "Connected to " << args["host"].get<std::string>() << " (" << sftp.fingerprint() << ")\n";
    for (const auto &entry: sftp.list(folder)) {
        std::cout << (entry.is_folder() ? "d " : "  ") << entry.size << "\t" << entry.name << "\n";
        if (entry.is_file()) sftp.download(folder + "/" + entry.name, entry.name);
    }
}
