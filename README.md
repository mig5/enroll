# Enroll 

<div align="center">
  <img src="https://git.mig5.net/mig5/enroll/raw/branch/main/enroll.svg" alt="Enroll logo" width="240" />
</div>

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

## Install

### Ubuntu/Debian apt repository

```bash
sudo mkdir -p /usr/share/keyrings
curl -fsSL https://mig5.net/static/mig5.asc | sudo gpg --dearmor -o /usr/share/keyrings/mig5.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/mig5.gpg] https://apt.mig5.net $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mig5.list
sudo apt update
sudo apt install enroll
```

### AppImage

Download the AppImage file from the Releases page (verify with GPG if you wish, my fingerprint is [here](https://mig5.net/static/mig5.asc),
then make it executable and run it:

```bash
chmod +x Enroll.AppImage
./Enroll.AppImage
```

### Pip/PipX

```bash
pip install enroll
```

### Poetry

Clone this repository with git, then:

```bash
poetry install
poetry run enroll --help
```

## Usage

On the host (root recommended to harvest as much data as possible):

### 1. Harvest state/information about the host

```bash
enroll harvest --out /tmp/enroll-harvest
```

### 2. Generate Ansible manifests (roles/playbook) from that harvest

```bash
enroll manifest --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible
```

### Alternatively, do both steps in one shot:

```bash
enroll enroll --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible
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

## Found a bug, have a suggestion?

You can e-mail me (see the pyproject.toml for details) or contact me on the Fediverse:

https://goto.mig5.net/@mig5
