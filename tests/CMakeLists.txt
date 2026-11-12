set(SC_TEST_LINK_LIBRARIES sc-sftp)

# Against a throwaway OpenSSH sshd on 127.0.0.1 (started by the test, as the user running it); skipped (77) where
# there's no sshd or ssh-keygen.
add_sc_test(sftp LABELS unit TIMEOUT 180)
set_tests_properties(test-sftp PROPERTIES SKIP_RETURN_CODE 77)
