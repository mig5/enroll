# 0.0.2

 * Merge pkg_ and roles created based on file/service detection
 * Avoid idempotency issue with users (password_lock)
 * Rename subcommands/args ('export' is now 'enroll', '--bundle' is now '--harvest') 
 * Don't try and start systemd services that were Inactive at harvest time
 * Capture miscellaneous files in /etc under their own etc_custom role, but not backup files
 * Add tests
 * Various other bug fixes

# 0.0.1

 * Initial commit
