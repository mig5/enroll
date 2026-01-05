# 0.3.0

 * Introduce `enroll explain` - a tool to analyze and explain what's in (or not in) a harvest and why.
 * Centralise the cron and logrotate stuff into their respective roles, we had a bit of duplication between roles based on harvest discovery.

# 0.2.3

 * Introduce --ask-become-pass or -K to support password-required sudo on remote hosts, just like Ansible. It will also fall back to this prompt if a password is required but the arg wasn't passed in.

# 0.2.2

 * Fix stat() of parent directory so that we set directory perms correct on --include paths.
 * Set pty for remote calls when sudo is required, to help systems with limits on sudo without pty

# 0.2.1

 * Don't accidentally add extra_paths role to usr_local_custom list, resulting in extra_paths appearing twice in manifested playbook
 * Ensure directories in the tree of anything included with --include are defined in the state and manifest so we make dirs before we try to create files

# 0.2.0

 * Add version CLI arg
 * Add ability to enroll RH-style systems (DNF5/DNF/RPM)
 * Refactor harvest state to track package versions

# 0.1.7

 * Fix an attribution bug for certain files ending up in the wrong package/role.

# 0.1.6

 * DRY up some code logic
 * More test coverage

# 0.1.5

 * Consolidate logrotate and cron files into their main service/package roles if they exist.
 * Standardise on MAX_FILES_CAP in one place
 * Manage apt stuff in its own role, not in etc_custom

# 0.1.4

 * Attempt to capture more stuff from /etc that might not be attributable to a specific package. This includes common singletons and systemd timers
 * Avoid duplicate apt data in package-specific roles.

# 0.1.3

 * Allow the user to add extra paths to harvest, or paths to ignore, using `--exclude-path` and `--include-path`
   arguments.
 * Add support for an enroll.ini config file to store arguments per subcommand, to avoid having to remember
   them all for repetitive executions.

# 0.1.2

 * Include files from `/usr/local/bin` and `/usr/local/etc` in harvest (assuming they aren't binaries or
   symlinks) and store in `usr_local_custom` role, similar to `etc_custom`.

# 0.1.1

 * Add `diff` subcommand which can compare two harvests and send email or webhook notifications in different
   formats.

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
