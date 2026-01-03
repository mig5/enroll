%global upstream_version 0.2.2

Name:           enroll
Version:        %{upstream_version}
Release:        1%{?dist}.enroll1
Summary:        Enroll a server's running state retrospectively into Ansible.

License:        GPL-3.0-or-later
URL:            https://git.mig5.net/mig5/enroll
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  pyproject-rpm-macros
BuildRequires:  python3-devel
BuildRequires:  python3-poetry-core

Requires: python3-yaml
Requires: python3-paramiko

# Make sure private repo dependency is pulled in by package name as well.
Recommends:       jinjaturtle

%description
Enroll a server's running state retrospectively into Ansible.

%prep
%autosetup -n enroll

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files enroll

%files -f %{pyproject_files}
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/enroll

%changelog
* Sat Jan 02 2026 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Fix stat() of parent directory so that we set directory perms correct on --include paths.
- Set pty for remote calls when sudo is required, to help systems with limits on sudo without pty
* Fri Jan 01 2026 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Don't accidentally add extra_paths role to usr_local_custom list, resulting in extra_paths appearing twice in manifested playbook
- Ensure directories in the tree of anything included with --include are defined in the state and manifest so we make dirs before we try to create files
* Mon Dec 29 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Add version CLI arg
- Add ability to enroll RH-style systems (DNF5/DNF/RPM)
- Refactor harvest state to track package versions
* Sun Dec 28 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Fix an attribution bug for certain files ending up in the wrong package/role.
* Sun Dec 28 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- DRY up some code logic
- More test coverage
* Sun Dec 28 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Consolidate logrotate and cron files into their main service/package roles if they exist.
- Standardise on MAX_FILES_CAP in one place
- Manage apt stuff in its own role, not in etc_custom
* Sat Dec 27 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Attempt to capture more stuff from /etc that might not be attributable to a specific package. This includes common singletons and systemd timers
- Avoid duplicate apt data in package-specific roles.
* Sat Dec 27 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Initial RPM packaging for Fedora 42
