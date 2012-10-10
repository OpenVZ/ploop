%define _incdir /usr/include/ploop
Summary: ploop tools
Name: ploop
Version: 1.5
%define rel 1
Release: %{rel}%{?dist}
Group: Applications/System
License: GNU GPL
Source: %{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: ploop-lib = %{version}
BuildRequires: libxml2-devel

%description
This package contains tools to work with ploop devices and images.

%prep
%setup -q

%build
make %{?_smp_mflags} LIBDIR=%{_libdir} all

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/%{_sbindir}
make DESTDIR=%{buildroot} LIBDIR=%{_libdir} install

%clean
rm -rf %{buildroot}

%files
%attr(755,root,root) /sbin/*
%attr(755,root,root) %{_sbindir}/ploop
%attr(755,root,root) %{_sbindir}/ploop-*
%attr(644,root,root) %{_mandir}/man8/ploop.8.*

%package lib
Summary: ploop library
Group: Applications/System
Requires: libxml2
Requires: parted
Conflicts: vzkernel < 2.6.32-042stab061.1

%description lib
Parallels loopback (ploop) block device API library

%files lib
%defattr(-,root,root)
%attr(755,root,root) %{_libdir}/libploop.so
%dir /var/lock/ploop

%triggerin lib -- udev
SCRIPT="/lib/udev/rules.d/60-persistent-storage.rules"
if [ -f $SCRIPT ]; then
	fgrep 'KERNEL=="ploop*", GOTO="persistent_storage_end"' $SCRIPT > /dev/null 2>&1 ||
	sed -i -e '1 s/^/KERNEL=="ploop*", GOTO="persistent_storage_end"\n/;' $SCRIPT
fi

SCRIPT2="/lib/udev/rules.d/80-iosched.rules"
if [ -f $SCRIPT2 ]; then
	fgrep 'KERNEL=="ploop*", GOTO="end_iosched"' $SCRIPT2 > /dev/null 2>&1 ||
	sed -i -e '1 s/^/KERNEL=="ploop*", GOTO="end_iosched"\n/;' $SCRIPT2
fi

%package devel
Summary: Headers for development with ploop library
Group: Applications/System
%description devel
Headers and a static version of ploop library

%files devel
%defattr(-,root,root)
%dir %{_incdir}
%attr(644,root,root) %{_libdir}/libploop.a
%attr(644,root,root) %{_incdir}/libploop.h
%attr(644,root,root) %{_incdir}/ploop_if.h
%attr(644,root,root) %{_incdir}/ploop1_image.h
%attr(644,root,root) %{_incdir}/dynload.h

%changelog
* Tue Sep 25 2012 Kir Kolyshkin <kir@openvz.org> 1.5-1
- NOTE: this version requires vzkernel >= 2.6.32-042stab061.1
- New functionality:
- * switch from old /dev/ploop/ symlink-based to new kernel cookie registration
- * snapshots: switch to schema with constant top delta uuid
- * use /proc/vz/ploop_minor based interface to get free minor
- * if ploop is in maintenance state, try to complete it before doing
    snapshot/resize/merge/mount/umount/copy operation
- * ploop mount: use in-kernel I/O module autodetection
- * ploop balloon discard: new iterative compacting support
- * ploop balloon discard: implement --stat
- * ploop balloon discard: implement --automount
- * ploop balloon discard: cancellation support
- * ploop balloon: allow DiskDescriptor.xml argument
- * ploop umount: implement -c component_name
- * ploop list: implement
- * /sbin/mount.ploop: do load ploop modules
- Bug fixes:
- * do not crash on empty DiskDescriptor.xml (libxml2 workaround)
- * ploop convert: fix converting from expanded to raw
- * ploop copy: fixed check for opened fd
- * ploop copy: do not leak opened fds
- * ploop create: fix gpt partition creation to be 4096 aligned
- * ploop create, resize: round up size to be cluster aligned
- * tools: few exit code fixes
- * multiple usage, log and error message fixes
- Improvements:
- * ploop mount: check that mount point is a directory
- * ploop umount: reduce retry count from 60 to 6
- * ploop umount: print lsof output in case of failed umount
- * ploop create: for prealloc image, use ftruncate if fallocate not supported
- * ploop create, resize: add check for correct block device size
- * scripts: de-bash-ify
- * assorted code refactoring, cleanups and nitpicks
- Library API changes:
- * add ploop_resolve_functions() to aid in dynamic library loading
- * introduce optimized ploop_get_info_by_descr(), remove ploop_get_info()
- * replace ploop_{alloc,read}_diskdescriptor() with ploop_read_disk_descr()
- * remove ploop_getdevice()

* Sat Jun  9 2012 Kir Kolyshkin <kir@openvz.org> 1.4-1
- ploop copy: fix data loss during migration (#2287)
- ploop(8): fixed according to doc team review
- ploop mount: tell about unsupported underlying fs
- ploop-copy: improve usage
- ploop-copy -s: added mode to copy to local file
- tools/ploop.c: do not return -1 from main()
- tools/ploop.c: fix/unify working with diskdescriptor

* Thu May 31 2012 Kir Kolyshkin <kir@openvz.org> 1.3-1
- New functionality
  - ploop copy is working now
  - added pcopy's send_process() and receive_process() to lib
  - ploop mount: added -c <component_name> option
  - ploop(8): added (still incomplete)
  - ploop balloon discard: add --to-free and --min-block
  - add Preallocated item to DiskDescriptor.xml
  - add add ploop_get_mnt_by_dev() to lib
- Bug fixes
  - fixed offline snapshot creation
  - fixed race between register/unregister_ploop_dev()
  - create image: if fallocate is not supported, fail
  - ploop init, ploop mount: fix -b option value validation
  - ploop mount: fix usage, -d is optional
  - ploop info: fix usage, DiskDescriptor.xml is required
  - ploop.spec: make main package require -lib of the same version
  - fixed a few ioctl-related error messages
  - ploop_create_snapshot(): check for number of snapshots limit (127)
  - ploop.spec: do not own _libdir
  - fix SYSEXIT_PARAM value
  - tools/ploop.c: do not use ploop_err()
  - tools: fixed/improved usage for many commands
  - tools: do not forget to print newlines
  - make install: use /usr/lib64 LIBDIR for x86_64
  - ploop_create_image(): free disk descriptor if fstype is NULL
  - create_balloon_file(): fix file name in error message
  - create_balloon_file(): umount and remove temp mnt point
  - create_balloon_file(): fix error message and return code
  - parse_xml(): add Blocksize validation
- Improvements and cleanups
  - ploop lib: add visibility=hidden for internal functions
  - tools: use parse_size() and is_xml_name() where possible
  - remove merge_top_only param of get_delta_info()
  - ploop balloon: make it accept either -m or -d or both
  - ploop convert: change -t to -f
  - tools: unify parsing -f option
  - various code and headers cleanups
  - setver.sh: add -v, -b, -i

* Tue Apr 17 2012 Kir Kolyshkin <kir@openvz.org> 1.2-1
- Added ploop_get_dev() function
- Added ploop_set_component_name() function
- Fix: do not clear in-use flag in ploop_fsck()
- ploop-fsck: add -d flag to forcefully drop "in use" image flag
- Fixed handling blocksize for raw images
- Added user_xattr,acl to default mount options
- ploop_mount(): added ability to pass MS_NOATIME flag
- ploop-balloon: add discard command to compact ploop image
- ploop_get_info(): return old info in case statfs() failed
- expanded2preallocated(): if fallocate not supported, use ftruncate
- ploop_resize_image(): Check is it possible to fallocate before inflating balloon file
- Fixed merging all snapshots
- Some fixes in ploop tool usage
- Some log message fixes
- Add function, source file and line number to error messages if DEBUG is set
- Build system fixes/improvements

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
