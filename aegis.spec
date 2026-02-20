Name:           aegis
Version:        1.13.0
Release:        1%{?dist}
Summary:        SSH-based compliance scanner for SysAdmin
License:        MIT
URL:            https://github.com/hanalyx/aegis
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-wheel
BuildRequires:  python3-hatchling
BuildRequires:  pyproject-rpm-macros

Requires:       python3-paramiko >= 3.0
Requires:       python3-PyYAML >= 6.0
Requires:       python3-click >= 8.0
Requires:       python3-rich >= 13.0
# EPEL required on RHEL 8/9 for python3-click and python3-rich

%description
SSH-based compliance scanner. Connects to remote hosts via SSH, evaluates
YAML compliance rules, captures machine-verifiable evidence, and maps
results to CIS, STIG, NIST 800-53, PCI-DSS, and FedRAMP frameworks.

%prep
%autosetup

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files runner

# Install data files
install -d %{buildroot}%{_datadir}/aegis
cp -a rules %{buildroot}%{_datadir}/aegis/rules
cp -a schema %{buildroot}%{_datadir}/aegis/schema
cp -a mappings %{buildroot}%{_datadir}/aegis/mappings

# Install config
install -d %{buildroot}%{_sysconfdir}/aegis/conf.d
install -d %{buildroot}%{_sysconfdir}/aegis/groups
install -d %{buildroot}%{_sysconfdir}/aegis/hosts
install -m 644 config/defaults.yml %{buildroot}%{_sysconfdir}/aegis/defaults.yml
install -m 644 config/inventory.yml.example %{buildroot}%{_sysconfdir}/aegis/inventory.yml.example
cp -a config/conf.d/* %{buildroot}%{_sysconfdir}/aegis/conf.d/ 2>/dev/null || true

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/aegis
%{_datadir}/aegis/
%dir %{_sysconfdir}/aegis/
%config(noreplace) %{_sysconfdir}/aegis/defaults.yml
%{_sysconfdir}/aegis/inventory.yml.example
%config(noreplace) %dir %{_sysconfdir}/aegis/conf.d/
%config(noreplace) %dir %{_sysconfdir}/aegis/groups/
%config(noreplace) %dir %{_sysconfdir}/aegis/hosts/
