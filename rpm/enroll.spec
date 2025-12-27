%global upstream_version 0.1.4

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
* Sat Dec 27 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Attempt to capture more stuff from /etc that might not be attributable to a specific package. This includes common singletons and systemd timers
- Avoid duplicate apt data in package-specific roles.
* Sat Dec 27 2025 Miguel Jacq <mig@mig5.net> - %{version}-%{release}
- Initial RPM packaging for Fedora 42
