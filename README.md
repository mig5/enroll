# Enroll 

**enroll** inspects a Linux machine (currently Debian-only) and generates Ansible roles for things it finds running on the machine.

It aims to be **optimistic and noninteractive**:
- Detects packages that have been installed
- Detects Debian package ownership of `/etc` files using dpkg’s local database.
- Captures config that has **changed from packaged defaults** (dpkg conffile hashes + package md5sums when available).
- Also captures **service-relevant custom/unowned files** under `/etc/<service>/...` (e.g. drop-in config includes).
- Defensively excludes likely secrets (path denylist + content sniff + size caps).
- Captures non-system users that exist on the system, and their SSH public keys
- Captures miscellaneous `/etc` files that it can't attribute to a package, and installs it in an `etc_custom` role
- Avoids trying to start systemd services that were detected as being Inactive during harvest

## Install (Poetry)

```bash
poetry install
poetry run enroll --help
```

## Usage

On the host (root recommended):

### 1. Harvest state/information about the host

```bash
sudo poetry run enroll harvest --out /tmp/enroll-harvest
```

### 2. Generate Ansible manifests (roles/playbook) from that harvest

```bash
sudo poetry run enroll manifest --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible
```

### Alternatively, do both steps in one shot:

```bash
sudo poetry run enroll enroll --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible
```

Then run:

```bash
ansible-playbook -i "localhost," -c local /tmp/enroll-ansible/playbook.yml
```


## Notes / Safety

- enroll **skips** common sensitive locations like `/etc/ssl/private/*`, `/etc/ssh/ssh_host_*`, and files that look like private keys/tokens.
- It also skips symlinks, binary-ish files, and large files by default.
- Review each generated role’s README before committing it anywhere.
- It only stores the raw config files. If you want to turn these into Jinja2 templates with dynamic inventory, see my other tool https://git.mig5.net/mig5/jinjaturtle .


## Troubleshooting

- Run as root for the most complete harvest (`sudo ...`).
