Summary: A console-based network monitoring utility.
Name: localtraf
Version: 1.4
Release: 0%{?dist}
Source: %{name}-%{version}.tar.gz
License: GPL
Group: Applications/System
BuildRequires: ncurses-devel libpcap-devel
BuildRoot: /var/tmp/%{name}-%{version}-root

%description
Localtraf is a console-based utility for network monitoring.
Localtraf gathers data like IP packet, byte counts and
rate statistics by hosts in your local network.

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_prefix}/sbin
cp %{name} $RPM_BUILD_ROOT%{_prefix}/sbin

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(755,root,root)
%{_prefix}/sbin/%{name}

%changelog
