# Enroll Threat Model and Security Scope

Enroll is a command-line systems administration tool. It is designed to be executed intentionally by a system administrator, often with elevated privileges, in order to inspect a host, harvest selected system state, and optionally generate or apply configuration-management output.

Because of that design, Enroll’s security model is different from that of a network service, web application, daemon, or setuid program. Enroll does not attempt to defend against arbitrary local compromise of the account executing it. If an attacker can control the command line, environment, configuration file, working directory, `PATH`, harvested input bundle, or configuration-management tools used by the administrator, they may be able to influence what Enroll does. That situation is considered a local trust-boundary failure outside Enroll’s intended security model.

## Core assumptions

Enroll assumes that the person running the tool understands what they are asking it to do.

In particular:

* If Enroll is run as root, the root user is assumed to control and understand the command line, environment, configuration file, and output location being used.
* If an `enroll.ini` configuration file is loaded, its location and contents are assumed to be owned, selected, and understood by the operator.
* The operator is expected to understand the implications of options such as `--dangerous`, `--assume-safe-path`, `--sops`, `--remote-host`, and `--remote-ssh-config`.
* Harvest bundles used for `manifest` or `diff` are assumed to come from a trusted source unless the operator is deliberately inspecting untrusted input without applying it.
* Configuration-management tools invoked by Enroll, such as Ansible, SOPS, SSH, `sudo`, Docker, Podman, Flatpak, Snap, package managers, and system utilities, are assumed to be the trusted tools the operator intended to use.

## What is in scope

Enroll tries to protect careful administrators from common and serious mistakes that can occur when a privileged CLI tool reads and writes host state.

In-scope security concerns include:

* Avoiding accidental capture of obvious secrets in default safe mode.
* Refusing known sensitive paths such as shadow files, SSH host keys, private key material, and common certificate/private-key locations unless the operator explicitly opts into dangerous collection.
* Warning when `--dangerous` is used, especially without encrypted output.
* Supporting encrypted harvest bundles via `--sops`.
* Avoiding symlink traversal and time-of-check/time-of-use mistakes when copying harvested files.
* Refusing unsafe artifact paths, symlinks, hardlinks, device nodes, and tar path traversal in harvest bundles.
* Treating a harvest bundle as point-in-time validated: before `manifest` or `diff` re-open artifacts to render or hash them, a plain *directory* bundle is copied into a private, attacker-immutable temp tree (regular files only, no symlinks or hardlinks, opened without following links) so the bundle that is consumed cannot be raced and swapped after validation. Tar and SOPS inputs get the equivalent treatment by being extracted into a private temp directory.
* Keeping harvested values in Ansible *data* rather than playbook *structure*, so a harvested path, owner, group, username, or link target cannot inject YAML structure or be re-evaluated as a Jinja/template expression at apply time.
* Writing plaintext harvest outputs into private directories by default.
* Hardening root-run output path handling so Enroll does not accidentally write through attacker-prepared symlinks or unsafe parent directories.
* Refusing to continue non-interactively when run as root with an unsafe `PATH`, unless the operator explicitly confirms with `--assume-safe-path`.
* Avoiding injection in generated manifests where harvested values are embedded into Ansible output — not only shell injection, but YAML-structure injection and runtime Jinja/template re-evaluation — by serializing harvested data through a safe YAML dumper, tagging template-looking values as Ansible `!unsafe`, and allowlisting the only identifiers ever spliced into raw task YAML.
* Rejecting unknown SSH host keys by default during remote harvests.

These measures are defense-in-depth. They are intended to reduce the chance of accidental exposure, unsafe filesystem writes, path traversal, command injection, or dangerous behavior when Enroll is used normally by an administrator.

## What is out of scope

The following are generally out of scope and should not be reported as Enroll vulnerabilities unless they also bypass one of Enroll’s explicit hardening mechanisms:

* A malicious local user who can already control the root user’s command line, shell environment, config file, `PATH`, `XDG_CONFIG_HOME`, SSH config, working directory, or invoked binaries.
* A root user loading an `enroll.ini` file whose contents intentionally request dangerous behavior.
* A root user passing `--dangerous` and then observing that Enroll may collect sensitive information.
* A root user passing `--assume-safe-path` and then observing that Enroll does not prompt about `PATH` safety.
* A user applying generated Ansible manifests from an untrusted harvest.
* A user configuring a webhook, email target, SSH proxy command, SOPS binary, package manager, or configuration-management tool that they do not trust.
* A compromised system where an attacker already controls root-owned files, root’s shell, root’s configuration, or the privileged tools Enroll invokes.
* Reports that amount to “if root runs this tool with malicious options, root can make the system do dangerous things.”
* Enroll harvesting a file that merely *mentions* a credential-related word in a comment with no assigned value (for example a commented-out `# token` hint in a stock config). Enroll tolerates value-less keyword mentions in comments so it is not useless for harvesting ordinary configuration files. However, a commented-out credential *value* — a populated `key = value` assignment, a URI with embedded credentials, an `Authorization` header, or private-key material — is treated as sensitive even inside a comment, because a "commented out" secret is very often a real secret that was merely disabled. Such a file is refused in default safe mode and requires `--dangerous` (ideally with `--sops`) to collect. It remains the responsibility of the user to use `--sops` or appropriate at-rest encryption if in the slightest doubt about what might get harvested.

Enroll is a tool for administrators, not a sandbox for hostile local users. It cannot make unsafe local trust decisions safe if the operator’s own execution environment is already attacker-controlled.

## Trusted harvests

Harvest bundles should be treated as sensitive and trusted administrative artifacts.

A harvest may contain hostnames, usernames, package lists, service state, filesystem metadata, configuration files, firewall snapshots, container image references, Flatpak/Snap state, and other operational details. In `--dangerous` mode it may contain substantially more sensitive material.

Before running `manifest` or `diff`, or applying a generated manifest, the operator should be confident that the harvest bundle came from a trusted source and has not been tampered with.

Enroll validates harvest structure and artifact safety. Validation can detect many unsafe filesystem constructs, such as path traversal, missing artifacts, symlinks, hardlinks, and schema mismatches. Validation does not and cannot prove that the desired state represented by a harvest is safe to apply.

## Local compromise

Enroll includes hardening against some local filesystem attack patterns because it is often run with high privileges. For example, it tries to avoid symlink races, unsafe output directories, path traversal, and accidental secret capture.

However, local compromise cannot be ruled out completely for a privileged CLI tool. If an attacker can influence the administrator’s shell, environment, config file, binaries, SSH configuration, SOPS binary, configuration-management tools, or harvest inputs, they may be able to influence Enroll’s behavior.

Such scenarios are treated as local compromise or operator trust failures, not as vulnerabilities in Enroll by themselves.

## Security report guidance

Useful vulnerability reports include issues where Enroll behaves unsafely despite the documented trust model. Examples include:

* Enroll captures a clearly sensitive default-denied file without `--dangerous`.
* Enroll follows a symlink or hardlink in a way that causes privileged file disclosure or overwrite.
* Enroll extracts a tar member outside the intended harvest directory.
* Enroll accepts a malicious harvest artifact that escapes the artifact root.
* Enroll generates an Ansible manifest where ordinary harvested data can cause command injection.
* Enroll writes root-run output into an unsafe attacker-controlled path despite its safety checks.
* Enroll silently ignores a failed safety check and proceeds anyway.
* Enroll accepts an unknown SSH host key unexpectedly.
* Enroll exposes secrets in logs, errors, reports, or generated output when not explicitly requested by the operator.

Less useful reports, and normally out of scope, include:

* “Root can configure Enroll to collect sensitive files.”
* “Root can pass `--dangerous` and collect dangerous data.”
* “Root can pass `--assume-safe-path` and bypass the root `PATH` warning.”
* “Root can point Enroll at a malicious config file.”
* “A malicious local user can compromise Enroll after already controlling root’s environment or binaries.”

Reports about concrete bypasses of Enroll's hardening are welcomed (see https://enroll.sh/security.html), but the project does not treat intentional administrator-controlled execution as a vulnerability.
