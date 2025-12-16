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

---

# Two modes: single-site vs multi-site (`--fqdn`)

**enroll** has two distinct ways to generate Ansible:

## 1) Single-site mode (default: *no* `--fqdn`)
Use this when you’re enrolling **one server** (or you’re generating a “golden” role set you intend to reuse).

**What you get**
- Config, templates, and defaults are primarily **contained inside each role**.
- Raw config files (when not templated) live in the role’s `files/`.
- Template variables (when templated) live in the role’s `defaults/main.yml`.

**Pros**
- Roles are more **self-contained** and easier to understand.
- Better starting point for **provisioning new servers**, because the role contains most of what it needs.
- Less inventory abstraction/duplication.

**Cons**
- Less convenient for quickly enrolling multiple hosts with divergent configs (you’ll do more manual work to make roles flexible across hosts).

## 2) Multi-site mode (`--fqdn`)
Use this when you want to enroll **several existing servers** quickly, especially if they differ.

**What you get**
- Roles are **shared** across hosts, but host-specific data lives in inventory.
- Host inventory drives what’s managed:
  - which files to deploy for that host
  - which packages are relevant for that host
  - which services should be enabled/started for that host
- For non-templated config, raw files live in host-specific inventory under `.files/` (per role).

**Pros**
- Fastest way to retrofit **multiple servers** into config management.
- Avoids shared-role “host A breaks host B” problems by keeping host-specific state in inventory.
- Better fit when you already have a fleet and want to capture/reflect reality first.

**Cons**
- More abstraction: roles become more “data-driven”.
- Potential duplication: raw files may exist per-host in inventory (even if identical).
- Harder to use the roles to **provision a brand-new server** without also building an inventory for that new host, because multi-site output assumes the server already exists and is being retrofitted.

**Rule of thumb**
- If your goal is *“make this one server reproducible / provisionable”* → start with **single-site**.
- If your goal is *“get several already-running servers under management quickly”* → use **multi-site**.

---

# Key concepts

## Harvest

**enroll** begins by 'harvesting' known state about your host. This includes detecting what running services exist, what packages have been installed 'manually' (that is, stuff that doesn't come out of the box with the OS), and anything 'custom' in `/etc` that it can't attribute to a specific package.

It also detects if any config files have been *changed* from their packaged defaults. If they have, it will attempt to 'harvest' them. If the config file is identical to how it comes with the package, then it doesn't bother harvesting it, because there's little value in config-managing it if it's identical to what you get by simply installing the package!

The harvest writes a state.json file explaining all the data it harvested and, if it chose not to harvest something, explanations as to why that is the case (see below: sensitive data).

## Sensitive data

**enroll** doesn't make any assumptions about how you might handle sensitive data from your config files, in Ansible. Some people might use SOPS, others might use Vault, others might do something else entirely.

For this reason, **enroll** will attempt to read config files, and if it detects data that looks like a sensitive SSH/SSL private key, or password, or API key, etc, then it won't harvest it for config management.

This inevitably means that it will deliberately miss some important config files that you probably *want* to manage in Ansible.

Nonetheless, in the Harvest 'state' file, there should be an explanation of 'excluded files'. You can parse or inspect this file to find what it chose to ignore, and then you know what you might want to augment the results with later, once you 'manifest' the harvest into Ansible configuration.

## Manifest

The 'manifest' subcommand expects to be given a path to the 'harvest' obtained in the first step. It will then attempt to generate Ansible roles and playbooks (and potentially 'inventory') from that harvest.

Manifesting is the most complex step because a lot of people will have opinions on how Ansible roles and inventory should work. No solution is perfect for everyone. However, **enroll** tries to strike a reasonable balance.

Remember, the purpose of this tool is to save **time** getting your systems into a decently-managed state. It's still up to you to wrangle it into a form that works for you on an ongoing basis.

---

# Single-shot mode for the impatient sysadmin

**enroll** has a 'single-shot' subcommand which combines the two other phases (harvest and manifest) into one. Use it to generate both the harvest and then manifest ansible from that harvest all in one go. Perfect if you're in a hurry!

---

# JinjaTurtle integration (both modes)

If you also have my other tool [JinjaTurtle](https://git.mig5.net/mig5/jinjaturtle) installed, **enroll** will attempt to create Jinja2 templates for any ini/json/xml/toml style configuration that it finds.

- Templates live in the **role** (`roles/<role>/templates/...`)
- Variables live in:
  - **single-site**: `roles/<role>/defaults/main.yml`
  - **multi-site** (`--fqdn`): `inventory/host_vars/<fqdn>/<role>.yml`

JinjaTurtle will be used automatically if it is detected on the `$PATH`. You can also be explicit and pass `--jinjaturtle`, but this will throw an error if JinjaTurtle is not on the `$PATH`.

If you *do* have JinjaTurtle installed, but *don't* wish to make use of it, you can use `--no-jinjaturtle`, in which case all config files will be kept as 'raw' files.

---

# How multi-site avoids “shared role breaks a host”

In multi-site mode, **roles are data-driven**. The role contains generic tasks like:

- “deploy all files listed for this host”
- “install packages listed for this host”
- “apply systemd enable/start state listed for this host”

The host inventory is what decides which files/packages/services apply to that host. This prevents the classic failure mode where host2 adds a config file to a shared role and host1 then fails trying to deploy a file it never had.

Raw non-templated files are stored under:

- `inventory/host_vars/<fqdn>/<role>/.files/...`

…and the host’s role variables describe which of those files should be deployed.

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

## AppImage

Download the AppImage file from the Releases page (verify with GPG if you wish, my fingerprint is [here](https://mig5.net/static/mig5.asc)),
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

---

# Usage

## 1. Harvest state/information about the host

On the host (root recommended to harvest as much data as possible):

```bash
enroll harvest --out /tmp/enroll-harvest
```

## 2. Generate Ansible manifests (roles/playbook) from that harvest

### Single-site (default: no --fqdn)

Good for one server, or for producing roles you want to reuse to provision new machines:

```bash
enroll manifest --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible
```

### Multi-site (--fqdn)

Best when enrolling multiple already-running servers into one repo:

```bash
enroll manifest --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible --fqdn "$(hostname -f)"
```

## Single-shot

Alternatively, do both steps in one shot:

```bash
enroll single-shot --harvest /tmp/enroll-harvest --out /tmp/enroll-ansible --fqdn "$(hostname -f)"
```

## 3. Run Ansible

### Single-site

You can run it however you prefer (local connection or your own inventory). Example:

```bash
ansible-playbook -i "localhost," -c local /tmp/enroll-ansible/playbook.yml
```

### Multi-site (--fqdn)

In multi-site mode, enroll generates an ansible.cfg, `host_vars` inventory, and a host-specific playbook:

```bash
ansible-playbook /tmp/enroll-ansible/playbooks/"$(hostname -f)".yml
```

---

# Found a bug, have a suggestion?

My Forgejo doesn't yet support proper federation, and for that reason I've not opened up registration/login to use the issue queue.

Instead, you can e-mail me (see the pyproject.toml for details) or contact me on the Fediverse:

https://goto.mig5.net/@mig5

