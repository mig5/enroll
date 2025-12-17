# 0.1.0

 * Add remote mode for harvesting a remote machine via a local workstation (no need to install enroll remotely)
   Optionally use `--no-sudo` if you don't want the remote user to have passwordless sudo when conducting the
   harvest, albeit you'll end up with less useful data (same as if running `enroll harvest` on a machine without
   sudo)
 * Add `--dangerous` flag to capture even sensitive data (use at your own risk!)
 * Add `--sops` flag which makes the harvest and the manifest 'out' data encrypted as a single SOPS data file.
   This would make `--dangerous` a little bit safer, if your intention is just to store the Ansible manifest
   in git or somewhere similar for disaster-recovery purposes (e.g encrypted at rest for safe-keeping).
 * Do a better job at capturing other config files in `/etc/<package>/` even if that package doesn't normally
   ship or manage those files.
 * Don't collect files ending in `.log`

# 0.0.5

 * Use JinjaTurtle to generate dynamic template/inventory if it's on the PATH
 * Support --fqdn flag for site-specific inventory and an inventory hosts file.
   This radically re-architects the roles to loop through abstract inventory
   because otherwise different servers can collide with each other through use
   of the same role. Use 'single site' mode (no `--fqdn`) if you want more readable,
   self-contained roles (in which case, store each manifested output in its own
   repo per server)
 * Generate an ansible.cfg if not present, to support `host_vars` plugin and other params,
   when using `--fqdn` mode
 * Be more permissive with files that we previously thought contained secrets (ignore commented lines)

# 0.0.4

 * Fix dash package detection issue
 * Reorder which roles install first

# 0.0.3

 * various bug fixes
 * Add debian packaging

# 0.0.2

 * Merge pkg_ and roles created based on file/service detection
 * Avoid idempotency issue with users (`password_lock`)
 * Rename subcommands/args ('export' is now 'enroll', '--bundle' is now '--harvest') 
 * Don't try and start systemd services that were Inactive at harvest time
 * Capture miscellaneous files in /etc under their own `etc_custom` role, but not backup files
 * Add tests
 * Various other bug fixes

# 0.0.1

 * Initial commit
