# simply-cpp-sftp

SFTP for simply-cpp: a C++20 client on [libssh2](https://libssh2.org) that lists, reads, writes, renames and removes
files on an SSH server, with the server's host key checked against `known_hosts`, and `sftp-tool`, a program to try a
server by hand.

```cpp
#include <sc/sftp/sc_sftp.h>

sc::sftp::client sftp{{.host = "sftp.example.com", .user = "h2h", .key = "/etc/example/id_ed25519",
                       .host_key = sc::sftp::host_key_check::accept_new}};
for (const auto &entry: sftp.list("/IN"))                  // name, kind, size, modified, permissions
    if (entry.is_file()) sftp.download("/IN/" + entry.name, "/var/lib/example/" + entry.name);
sftp.upload("/var/lib/example/payments.xml", "/OUT/payments.xml");
```

## What it does

- **Connecting**: IPv4 or IPv6, a timeout for connecting and for every request (`options::timeout`, 30 s), and
  `keep_alive()` to keep an idle connection open (a request every `options::keepalive`, 30 s). The client connects on
  its first call and again after a lost connection. One client is one SSH session: use it from one thread at a time.
- **Host keys** against `known_hosts` (`options::known_hosts`, default `~/.ssh/known_hosts`; hashed entries and
  `[host]:port` work): `host_key_check::strict` wants the server there already, `accept_new` adds a server that isn't
  (the line is appended, the file's other lines stay as they are). A key that doesn't match is always refused, as ssh
  does. `fingerprint()` gives the server's key as ssh shows it (`SHA256:...`).
- **Signing in** with a private key file (and its passphrase), a password, or the SSH agent, in that order, as far as
  given.
- **Files**: `list()`, `stat()` (nothing when nothing is there), `exists()`, `real_path()`, `read()` and `write()` for
  small files, `download()` and `upload()` in 256 kB chunks with progress, `rename()`, `remove()`, `make_folder()`,
  `remove_folder()`, `set_modified()`.
- **Copies are safe for whoever watches the folder**: `download()` and `upload()` write under a temporary name
  (`NAME.part`) and rename it when complete, give the copy the original's modified time, and replace a file that's
  there unless told not to (`transfer_options`). Turn `temporary` off for a server that can't rename. SFTP version 3
  (OpenSSH) won't rename onto a file: with overwrite, that file is removed first.
- **Errors** are `sc::sftp::error` with `why()`, the server's SFTP status (`no_such_file`, `permission_denied`,
  `file_exists`, ...) or what went wrong on the way (`host_key_unknown`, `host_key_changed`, `authentication_failed`,
  `timeout`, `connection_lost`, `local`), and `lost()` when the connection is gone: the next call connects again.

## sftp-tool

```bash
sftp-tool -H sftp.example.com -u h2h -i ~/.ssh/h2h_key --accept-new ls /IN
sftp-tool -H sftp.example.com -u h2h -i ~/.ssh/h2h_key get /IN/statement.txt
sftp-tool -H sftp.example.com -u h2h -i ~/.ssh/h2h_key put payments.xml /OUT/payments.xml
```

Commands: `ls`, `stat`, `get`, `put`, `cat`, `mv`, `rm`, `mkdir`, `rmdir`, `pwd`, `fingerprint`. A password or a key's
passphrase comes from the environment (`SFTP_PASSWORD`, `SFTP_PASSPHRASE`), never the command line. `man sftp-tool`.

## Building and testing

```bash
cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
```

It needs sc-core and libssh2 (`libssh2-1-dev`, Homebrew `libssh2`), found or installed by CMake. The test starts a
throwaway OpenSSH `sshd` on 127.0.0.1 (a free port, its own host and user keys, run as you) and checks the client
against it, the server's files on disk; it's skipped where there's no `sshd`.

## License

Apache-2.0 (see LICENSE and NOTICE). libssh2 is BSD 3-Clause, linked from the system.
