Name:           purple-mattermost
Version:        1.1
Release:        1%{?dist}
Summary:        Pidgin protocol plugin to connect to Mattermost
Vendor:         Eion Robb

Group:          Applications/Internet
License:        GPLv3
URL:            https://github.com/EionRobb/purple-mattermost

Source0:        https://github.com/EionRobb/purple-mattermost/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

# package version as available on RHEL7/EPEL7
BuildRequires:  json-glib-devel >= 1.0.2
BuildRequires:  libmarkdown-devel >= 2.1.8
BuildRequires:  libpurple-devel >= 2.8.0
BuildRequires:  mercurial >= 2.6.2

%description
A third-party plugin for the Pidgin multi-protocol instant messenger.
It connects libpurple-based instant messaging clients with Mattermost server. 

This package provides the protocol plugin for libpurple clients.

%package -n pidgin-mattermost
Summary:        Libpurple protocol plugin to connect to Mattermost
Group:          Applications/Internet
License:        GPLv2+

Requires:       %{name} = %{version}-%{release}


%description -n pidgin-mattermost
A third-party plugin for the Pidgin multi-protocol instant messenger.
It connects libpurple-based instant messaging clients with Mattermost server. 

This package provides the icon set for Pidgin.

%prep
%setup -q 

%build
make 

%install
DESTDIR=$RPM_BUILD_ROOT/ make install

%clean
rm -rf %{buildroot}


%files 
%defattr(-,root,root,-)
%doc INSTALL.md LICENSE README.md VERIFICATION.md
%{_libdir}/purple-*/libmattermost.so

%files -n pidgin-mattermost 
%defattr(-,root,root,-)
%{_datadir}/pixmaps/pidgin/protocols/*/mattermost.png

%changelog
* Wed May 31 2017 Jaroslaw Polok <jaroslaw.polok@gmail.com> - 1.1
- Initial packaging.

