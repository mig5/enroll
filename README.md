# Enroll

<div align="center">
  <img src="https://git.mig5.net/mig5/enroll/raw/branch/main/enroll.svg" alt="Enroll logo" width="240" />
</div>

**enroll** inspects a Linux machine (Debian-like or RedHat-like) and generates Ansible roles/playbooks (and optionally inventory) for what it finds.

- Detects packages that have been installed.
- Detects package ownership of `/etc` files where possible
- Captures config that has **changed from packaged defaults** where possible (e.g dpkg conffile hashes + package md5sums when available).
- Also captures **service-relevant custom/unowned files** under `/etc/<service>/...` (e.g. drop-in config includes).
- Defensively excludes likely secrets (path denylist + content sniff + size caps).
- Captures non-system users and their SSH public keys and any .bashrc or .bash_aliases or .profile files that deviate from the skel defaults.
- Captures miscellaneous `/etc` files it can't attribute to a package and installs them in an `etc_custom` role.
- Captures symlinks in common applications that rely on them, e.g apache2/nginx 'sites-enabled'
- Ditto for /usr/local/bin (for non-binary files) and /usr/local/etc
- Avoids trying to start systemd services that were detected as inactive during harvest.

---

## Mental model

`enroll` works in two phases:

1) **Harvest**: collect host facts + relevant files into a harvest bundle (`state.json` + harvested artifacts)
2) **Manifest**: turn that harvest into Ansible roles/playbooks (and optionally inventory)

Additionally, some other functionalities exist:

- **Diff**: compare two harvests and report what changed (packages/services/users/files) since the previous snapshot.
- **Single-shot mode**: run both harvest and manifest at once.

---

## Output modes: single-site vs multi-site (`--fqdn`)

`enroll manifest` (and `enroll single-shot`) support two distinct output styles.

### Single-site mode (default: *no* `--fqdn`)
Use when enrolling **one server** (or generating a “golden” role set you intend to reuse).

**Characteristics**
- Roles are more self-contained.
- Raw config files live in the role's `files/`.
- Template variables live in the role's `defaults/main.yml`.

### Multi-site mode (`--fqdn`)
Use when enrolling **several existing servers** quickly, especially if they differ.

**Characteristics**
- Roles are shared, host-specific state lives in inventory.
- Host inventory drives what gets managed (files/packages/services).
- Non-templated raw files live per-host under `inventory/host_vars/<fqdn>/<role>/.files/...`.

**Rule of thumb**
- “Make this one server reproducible/provisionable” → start with **single-site**
- “Get multiple already-running servers under management quickly” → use **multi-site**

---

## Subcommands

### `enroll harvest`
Harvest state about a host and write a harvest bundle.

**What it captures (high level)**
- Detected services + service-relevant packages
- “Manual” packages
- Changed-from-default config (plus related custom/unowned files under service dirs)
- Non-system users + SSH public keys
- Misc `/etc` that can't be attributed to a package (`etc_custom` role)
- Optional user-specified extra files/dirs via `--include-path` (emitted as an `extra_paths` role at manifest time)

**Common flags**
- Remote harvesting:
  - `--remote-host`, `--remote-user`, `--remote-port`
  - `--no-sudo` (if you don't want/need sudo)
- Sensitive-data behaviour:
  - default: tries to avoid likely secrets
  - `--dangerous`: disables secret-safety checks (see “Sensitive data” below)
- Encrypt bundles at rest:
  - `--sops <FINGERPRINT...>`: writes a single encrypted `harvest.tar.gz.sops` instead of a plaintext directory
- Path selection (include/exclude):
  - `--include-path <PATTERN>` (repeatable): add extra files/dirs to harvest (even from locations normally ignored, like `/home`). Still subject to secret-safety checks unless `--dangerous`.
  - `--exclude-path <PATTERN>` (repeatable): skip files/dirs even if they would normally be harvested.
  - Pattern syntax:
    - plain path: matches that file; directories match the directory + everything under it
    - glob (default): supports `*` and `**` (prefix with `glob:` to force)
    - regex: prefix with `re:` or `regex:`
  - Precedence: excludes win over includes.
* Using remote mode and sudo requires password?
  - `--ask-become-pass` (or `-K`) will prompt for the password. If you forget, and remote requires password for sudo, it'll still fall back to prompting for a password, but will be a bit slower to do so.

---

### `enroll manifest`
Generate Ansible output from an existing harvest bundle.

**Inputs**
- `--harvest /path/to/harvest` (directory)
  or `--harvest /path/to/harvest.tar.gz.sops` (if using `--sops`)

**Output**
- In plaintext mode: an Ansible repo-like directory structure (roles/playbooks, and inventory in multi-site mode).
- In `--sops` mode: a single encrypted file `manifest.tar.gz.sops` containing the generated output.

**Common flags**
- `--fqdn <host>`: enables **multi-site** output style

**Role tags**
Generated playbooks tag each role so you can target just the parts you need:

- Tag format: `role_<role_name>` (e.g. `role_services`, `role_users`)
- Fallback/safe tag: `role_other`

Example:
```bash
ansible-playbook -i "localhost," -c local /tmp/enroll-ansible/playbook.yml --tags role_services,role_users
```

---

### `enroll single-shot`
Convenience wrapper that runs **harvest → manifest** in one command.

Use this when you want “get me something workable ASAP”.

Supports the same general flags as harvest/manifest, including `--fqdn`, remote harvest flags, and `--sops`.

---

### `enroll diff`
Compare two harvest bundles and report what changed.

**What it reports**
- Packages added/removed
- Services enabled added/removed, plus key state changes
- Users added/removed, plus field changes (uid/gid/home/shell/groups, etc.)
- Managed files added/removed/changed (metadata + content hash changes where available)

**Inputs**
- `--old <harvest>` and `--new <harvest>` (directories or `state.json` paths)
- `--sops` when comparing SOPS-encrypted harvest bundles
- `--exclude-path <PATTERN>` (repeatable) to ignore file/dir drift under matching paths (same pattern syntax as harvest)
- `--ignore-package-versions` to ignore package version-only drift (upgrades/downgrades)
- `--enforce` to apply the **old** harvest state locally (requires `ansible-playbook` on `PATH`)

**Noise suppression**
- `--exclude-path` is useful for things that change often but you still want in the harvest baseline (e.g. `/var/anacron`).
- `--ignore-package-versions` keeps routine upgrades from alerting; package add/remove drift is still reported.

**Enforcement (`--enforce`)**
If a diff exists and `ansible-playbook` is available, Enroll will:
1) generate a manifest from the **old** harvest into a temporary directory
2) run `ansible-playbook -i localhost, -c local <tmp>/playbook.yml` (often with `--tags role_<...>` to limit runtime)
3) record in the diff report that the old harvest was enforced

Enforcement is intentionally “safe”:
- reinstalls packages that were removed (`state: present`), but does **not** attempt downgrades/pinning
- restores users, files (contents + permissions/ownership), and service enable/start state

If `ansible-playbook` is not on `PATH`, Enroll returns an error and does not enforce.


**Output formats**
- `--format json` (default for webhooks)
- `--format markdown` / `--format text` (human-oriented)

**Notifications**
- Webhook:
  - `--webhook <url>`
  - `--webhook-format json|markdown|text`
  - `--webhook-header 'Header-Name: value'` (repeatable)
- Email (optional):
  - `--email-to <addr>` (plus optional SMTP/sendmail-related flags, depending on your install)

---

### `enroll explain`
Analyze a harvest and provide user-friendly explanations for what's in it and why.

This may also explain why something *wasn't* included (e.g a binary file, a file that was too large, unreadable due to permissions, or looked like a log file/secret.

Provide either the path to the harvest or the path to its state.json. It can also handle SOPS-encrypted harvests.

Output can be provided in plaintext or json.

---

### `enroll validate`

Validates a harvest by checking:

 * state.json exists and is valid JSON
 * state.json validates against a JSON Schema (by default the vendored one)
 * Every `managed_file` entry has a corresponding artifact at: `artifacts/<role_name>/<src_rel>`
 * That there are no **unreferenced files** sitting in `artifacts/` that aren't in the state.

#### Schema location + overrides

The master schema lives at: `enroll/schema/state.schema.json`.

You can override with a local file or URL:

```
enroll validate /path/to/harvest --schema ./state.schema.json
enroll validate /path/to/harvest --schema https://enroll.sh/schema/state.schema.json
```

Or skip schema checks (still does artifact consistency checks):

```
enroll validate /path/to/harvest --no-schema
```

#### CLI usage examples

Validate a local harvest:

```
enroll validate ./harvest
```

Validate a harvest tarball or a sops bundle:

```
enroll validate ./harvest.tar.gz
enroll validate ./harvest.sops --sops
```

JSON output + write to file:

```
enroll validate ./harvest --format json --out validate.json
```

Return exit code 1 for any warnings, not just errors (useful for CI):

```
enroll validate ./harvest --fail-on-warnings
```

---

## Sensitive data

By default, `enroll` does **not** assume how you handle secrets in Ansible. It will attempt to avoid harvesting likely sensitive data (private keys, passwords, tokens, etc.). This can mean it skips some config files you may ultimately want to manage.

If you opt in to collecting everything:

### `--dangerous`
**WARNING:** disables “likely secret” safety checks. This can copy private keys, TLS key material, API tokens, database passwords, and other credentials into the harvest output **in plaintext**.

If you intend to keep harvests/manifests long-term (especially in git), strongly consider encrypting them at rest.

### Encrypt bundles at rest with `--sops`
`--sops` encrypts the harvest and/or manifest outputs into a single `.tar.gz.sops` file (GPG). This is for **storage-at-rest**, not for direct “Ansible SOPS inventory” workflows.

⚠️ Important: `manifest --sops` produces one encrypted file. You must decrypt + extract it before running `ansible-playbook`.

---

## JinjaTurtle integration (both modes)

If [JinjaTurtle](https://git.mig5.net/mig5/jinjaturtle) is installed, `enroll` can generate Jinja2 templates for ini/json/xml/toml-style config.

- Templates live in `roles/<role>/templates/...`
- Variables live in:
  - single-site: `roles/<role>/defaults/main.yml`
  - multi-site: `inventory/host_vars/<fqdn>/<role>.yml`

You can force it on with `--jinjaturtle` or disable with `--no-jinjaturtle`.

---

## How multi-site avoids “shared role breaks a host”

In multi-site mode, roles are **data-driven**. The role tasks are generic (“deploy the files listed for this host”, “install the packages listed for this host”, “apply systemd enable/start state listed for this host”). Host inventory decides what applies per-host, avoiding the classic “host2 adds config, host1 breaks” failure mode.

---

# Install

## Ubuntu/Debian apt repository
```bash
sudo mkdir -p /usr/share/keyrings
curl -fsSL https://mig5.net/static/mig5.asc | sudo gpg --dearmor -o /usr/share/keyrings/mig5.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/mig5.gpg] https://apt.mig5.net $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mig5.list
sudo apt update
sudo apt install enroll
```

## Fedora

```bash
sudo rpm --import https://mig5.net/static/mig5.asc

sudo tee /etc/yum.repos.d/mig5.repo > /dev/null << 'EOF'
[mig5]
name=mig5 Repository
baseurl=https://rpm.mig5.net/$releasever/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mig5.net/static/mig5.asc
EOF

sudo dnf upgrade --refresh
sudo dnf install enroll
```

## AppImage
Download it from my Releases page, then:

```bash
chmod +x Enroll.AppImage
./Enroll.AppImage
```

## Pip/PipX
```bash
pip install enroll
```

## Poetry (dev)
```bash
poetry install
poetry run enroll --help
```

---

## Found a bug / have a suggestion?

My Forgejo doesn't currently support federation, so I haven't opened registration/login for issues.

Instead, email me (see `pyproject.toml`) or contact me on the Fediverse:

https://goto.mig5.net/@mig5

---

# Examples

## Harvest

### Local harvest
```bash
enroll harvest --out /tmp/enroll-harvest
```

### Remote harvest over SSH
```bash
enroll harvest --remote-host myhost.example.com --remote-user myuser --out /tmp/enroll-harvest
```

### Include paths (`--include-path`)
```bash
# Add a few dotfiles from /home (still secret-safe unless --dangerous)
enroll harvest --out /tmp/enroll-harvest --include-path '/home/*/.bashrc' --include-path '/home/*/.profile'
```

### Exclude paths (`--exclude-path`)
```bash
# Skip specific /usr/local/bin entries (or patterns)
enroll harvest --out /tmp/enroll-harvest --exclude-path '/usr/local/bin/docker-*' --exclude-path '/usr/local/bin/some-tool'
```

### Regex include
```bash
enroll harvest --out /tmp/enroll-harvest --include-path 're:^/home/[^/]+/\.config/myapp/.*$'
```

### `--dangerous`
```bash
enroll harvest --out /tmp/enroll-harvest --dangerous
```

### Remote + dangerous:
```bash
enroll harvest --remote-host myhost.example.com --remote-user myuser --dangerous
```

### `--sops` (encrypt at rest)
```bash
# Encrypted harvest bundle (writes /tmp/enroll-harvest/harvest.tar.gz.sops)
enroll harvest --out /tmp/enroll-harvest --dangerous --sops <FINGERPRINT(s)>
```

---

## Manifest

### Single-site (default: no --fqdn)
```bash
enroll manifest --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible
```

### Multi-site (--fqdn)
```bash
enroll manifest --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible --fqdn "$(hostname -f)"
```

### Manifest with `--sops`
```bash
# Generate encrypted manifest bundle (writes /tmp/enroll-ansible/manifest.tar.gz.sops)
enroll manifest --harvest /tmp/enroll-harvest/harvest.tar.gz.sops --out /tmp/enroll-ansible --sops <FINGERPRINT(s)>

# Decrypt/extract the manifest bundle, then run Ansible from inside ./manifest/
cd /tmp/enroll-ansible
sops -d manifest.tar.gz.sops | tar -xzvf -
cd manifest
```

---

## Single-shot

```bash
enroll single-shot --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible --fqdn "$(hostname -f)"
```

Remote single-shot (run harvest over SSH, then manifest locally):
```bash
enroll single-shot --remote-host myhost.example.com --remote-user myuser   --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible --fqdn "myhost.example.com"
```

---

## Diff

### Compare two harvest directories, output in json
```bash
enroll diff --old /path/to/harvestA --new /path/to/harvestB --format json
```

### Diff + webhook notify
```bash
enroll diff   --old /path/to/golden/harvest   --new /path/to/new/harvest   --webhook https://nr.mig5.net/forms/webhooks/xxxx   --webhook-format json   --webhook-header 'X-Enroll-Secret: xxxx'
```

`diff` mode also supports email sending and text or markdown format, as well as `--exit-code` mode to trigger a return code of 2 (useful for crons or CI)

### Ignore a specific directory or file from the diff
```bash
enroll diff --old /path/to/harvestA --new /path/to/harvestB --exclude-path /var/anacron
```

### Ignore package version drift (routine upgrades) but still alert on add/remove
```bash
enroll diff --old /path/to/harvestA --new /path/to/harvestB --ignore-package-versions
```

### Enforce the old harvest state when drift is detected (requires Ansible)
```bash
enroll diff --old /path/to/harvestA --new /path/to/harvestB --enforce --ignore-package-versions --exclude-path /var/anacron
```

---

## Explain

### Explain a harvest

All of these do the same thing:

```bash
enroll explain /path/to/state.json
enroll explain /path/to/bundle_dir
enroll explain /path/to/harvest.tar.gz
```

### Explain a SOPS-encrypted harvest

```bash
enroll explain /path/to/harvest.tar.gz.sops --sops
```

### Explain with JSON output and more examples

```bash
enroll explain /path/to/state.json --format json --max-examples 25
```

### Example output

```
❯ enroll explain /tmp/syrah.harvest
Enroll explain: /tmp/syrah.harvest
Host: syrah.mig5.net (os: debian, pkg: dpkg)
Enroll: 0.2.3

Inventory
- Packages: 254
- Why packages were included (observed_via):
  - user_installed: 248 – Package appears explicitly installed (as opposed to only pulled in as a dependency).
  - package_role: 232 – Package was referenced by an enroll packages snapshot/role. (e.g. acl, acpid, adduser)
  - systemd_unit: 22 – Package is associated with a systemd unit that was harvested. (e.g. postfix.service, tor.service, apparmor.service)

Roles collected
- users: 1 user(s), 1 file(s), 0 excluded
- services: 19 unit(s), 111 file(s), 6 excluded
- packages: 232 package snapshot(s), 41 file(s), 0 excluded
- apt_config: 26 file(s), 7 dir(s), 10 excluded
- dnf_config: 0 file(s), 0 dir(s), 0 excluded
- etc_custom: 70 file(s), 20 dir(s), 0 excluded
- usr_local_custom: 35 file(s), 1 dir(s), 0 excluded
- extra_paths: 0 file(s), 0 dir(s), 0 excluded

Why files were included (managed_files.reason)
- custom_unowned (179): A file not owned by any package (often custom/operator-managed).. Examples: /etc/apparmor.d/local/lsb_release, /etc/apparmor.d/local/nvidia_modprobe, /etc/apparmor.d/local/sbin.dhclient
- usr_local_bin_script (35): Executable scripts under /usr/local/bin (often operator-installed).. Examples: /usr/local/bin/check_firewall, /usr/local/bin/awslogs
- apt_keyring (13): Repository signing key material used by APT.. Examples: /etc/apt/keyrings/openvpn-repo-public.asc, /etc/apt/trusted.gpg, /etc/apt/trusted.gpg.d/deb.torproject.org-keyring.gpg
- modified_conffile (10): A package-managed conffile differs from the packaged/default version.. Examples: /etc/dnsmasq.conf, /etc/ssh/moduli, /etc/tor/torrc
- logrotate_snippet (9): logrotate snippets/configs referenced in system configuration.. Examples: /etc/logrotate.d/rsyslog, /etc/logrotate.d/tor, /etc/logrotate.d/apt
- apt_config (7): APT configuration affecting package installation and repository behavior.. Examples: /etc/apt/apt.conf.d/01autoremove, /etc/apt/apt.conf.d/20listchanges, /etc/apt/apt.conf.d/70debconf
[...]
```

---

## Run Ansible

### Single-site
```bash
ansible-playbook -i "localhost," -c local /tmp/enroll-ansible/playbook.yml
```

### Multi-site (--fqdn)
```bash
ansible-playbook /tmp/enroll-ansible/playbooks/"$(hostname -f)".yml
```

### Run only specific roles (tags)
Generated playbooks tag each role as `role_<name>` (e.g. `role_users`, `role_services`), so you can speed up targeted runs:
```bash
ansible-playbook -i "localhost," -c local /tmp/enroll-ansible/playbook.yml --tags role_users
```

## Configuration file

As can be seen above, there are a lot of powerful 'permutations' available to all four subcommands.

Sometimes, it can be easier to store them in a config file so you don't have to remember them!

Enroll supports reading an ini-style file of all the arguments for each subcommand.

### Location of the config file

The path the config file can be specified with `-c` or `--config` on the command-line. Otherwise,
Enroll will look for `./enroll.ini`, `./.enroll.ini` (in the current working directory),
`~/.config/enroll/enroll.ini` (or `$XDG_CONFIG_HOME/enroll/enroll.ini`).

You may also pass `--no-config` if you deliberately want to ignore the config file even if it existed.

### Precedence

Highest wins:

 * Explicit CLI flags
 * INI config ([cmd], [enroll])
 * argparse defaults

### Example config file

Here is an example.

Whenever an argument on the command-line has a 'hyphen' in it, just be sure to change it to an underscore in the ini file.

```ini
[enroll]
# (future global flags may live here)

[harvest]
dangerous = false
include_path =
  /home/*/.bashrc
  /home/*/.profile
exclude_path = /usr/local/bin/docker-*, /usr/local/bin/some-tool
# remote_host = yourserver.example.com
# remote_user = you
# remote_port = 2222

[manifest]
# you can set defaults here too, e.g.
no_jinjaturtle = true
sops = 00AE817C24A10C2540461A9C1D7CDE0234DB458D

[diff]
# ignore noisy drift
exclude_path = /var/anacron
ignore_package_versions = true
# enforce = true  # requires ansible-playbook on PATH

[single-shot]
# if you use single-shot, put its defaults here.
# It does not inherit those of the subsections above, so you
# may wish to repeat them here.
include_path = re:^/home/[^/]+/\.config/myapp/.*$
```
