# EXAMPLES

List a folder, adding the server to known_hosts the first time:

```
sftp-tool -H sftp.example.com -u h2h -i ~/.ssh/h2h_key --accept-new ls /IN
```

Copy a file down and one up:

```
sftp-tool -H sftp.example.com -u h2h -i ~/.ssh/h2h_key get /IN/statement.txt
sftp-tool -H sftp.example.com -u h2h -i ~/.ssh/h2h_key put payments.xml /OUT/payments.xml
```

# ENVIRONMENT

- `SFTP_PASSWORD`: the password, for a server that signs in with one.
- `SFTP_PASSPHRASE`: the passphrase of the key given with `--key`.

# SEE ALSO

ssh(1), sftp(1), ssh-keygen(1)
