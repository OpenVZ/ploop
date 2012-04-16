%define _incdir /usr/include/ploop
Summary: ploop tools
Name: ploop
Version: 1.1
%define rel 1
Release: %{rel}%{?dist}
Group: Applications/System
License: GNU GPL
Source: %{name}-%{version}.tar.bz2
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
* Thu Mar 22 2012 Kir Kolyshkin <kir@openvz.org> 1.1-1
- support for variable block size
- default block size changed from 256K to 1M
- ploop_set_log_file(): make NULL a valid argument
- logger: introduce, use and expose PLOOP_LOG_NOCONSOLE
- ploop_getdevice(): expose
- ploop_store_diskdescriptor(): fix for a case when image is in root dir
- Fixed expanded to preallocated conversion
- Remove some unused functions and non-existent function prototypes
- Introduce and use SYSEXIT_MKNOD error code
- Changed image -> device mapping schema
- Use strcasecmp for guid comparison
- Made ploop_merge_param.guid field const
- tools/ploop: remove -b option
- tools/ploop: remove unused and untested replace & add commands
- Log/error message fixes, improvements, and unification
- Makefiles: fixes, improvements

* Tue Mar 13 2012 Kir Kolyshkin <kir@openvz.org> 1.0-1
- initial version
