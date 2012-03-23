%define _incdir /usr/include/ploop
Summary: ploop tools
Name: ploop
Version: 1.1
Release: 1
Group: Applications/System
License: GNU GPL
Source: ploop-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: parted
BuildRequires: libxml2-devel

%description
This package contains tools to work with ploop devices and images.

%prep
%setup -q

%build
make LIBDIR=%{_libdir} all

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/%{_sbindir}
make DESTDIR=%{buildroot} LIBDIR=%{_libdir} install

%clean
rm -rf %{buildroot}

%triggerin -- udev
SCRIPT="/lib/udev/rules.d/60-persistent-storage.rules"
if [ -f $SCRIPT ]; then
	fgrep 'KERNEL=="ploop*", GOTO="persistent_storage_end"' $SCRIPT > /dev/null 2>&1 ||
	sed -i -e '1 s/^/KERNEL=="ploop*", GOTO="persistent_storage_end"\n/;' $SCRIPT
fi

%files
%attr(755,root,root) /sbin/*
%attr(755,root,root) %{_sbindir}/ploop
%attr(755,root,root) %{_sbindir}/ploop-*

%package lib
Summary: ploop library
Group: Applications/System
Requires: libxml2

%description lib
Parallels loopback (ploop) block device API library

%files lib
%defattr(-,root,root)
%dir %{_libdir}
%attr(755,root,root) %{_libdir}/libploop.so
%dir /var/lock/ploop

%package devel
Summary: Headers for development with ploop library
Group: Applications/System
%description devel
Headers and a static version of ploop library

%files devel
%defattr(-,root,root)
%dir %{_libdir}
%dir %{_incdir}
%attr(644,root,root) %{_libdir}/libploop.a
%attr(644,root,root) %{_incdir}/libploop.h
%attr(644,root,root) %{_incdir}/ploop_if.h
%attr(644,root,root) %{_incdir}/ploop1_image.h

%changelog
* Tue Mar 13 2012 Kir Kolyshkin <kir@openvz.org> 1.0-1
- initial version
