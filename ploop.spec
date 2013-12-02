%define _incdir /usr/include/ploop
Summary: ploop tools
Name: ploop
Version: 1.9
%define rel 1
Release: %{rel}%{?dist}
Group: Applications/System
License: GNU GPL
Source: %{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: ploop-lib = %{version}-%{release}
BuildRequires: libxml2-devel
BuildRequires: e2fsprogs-devel

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
Requires: util-linux
Requires: e2fsprogs
Requires: e2fsprogs-resize2fs-static
Requires: lsof
Requires: findutils
Conflicts: vzctl < 4.5

%description lib
Parallels loopback (ploop) block device API library

%files lib
%defattr(-,root,root)
%attr(755,root,root) %{_libdir}/libploop.so.*
%dir /var/lock/ploop
%{_prefix}/lib/tmpfiles.d/%{name}.conf

%post lib -p /sbin/ldconfig

%postun lib -p /sbin/ldconfig

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
%attr(644,root,root) %{_libdir}/libploop.so
%attr(644,root,root) %{_incdir}/libploop.h
%attr(644,root,root) %{_incdir}/ploop_if.h
%attr(644,root,root) %{_incdir}/ploop1_image.h
%attr(644,root,root) %{_incdir}/dynload.h

%changelog
* Wed Aug 28 2013 Kir Kolyshkin <kir@openvz.org> 1.9-1
- New functionality:
-- libploop.so: implement SONAME and versioning
-- Introduce ploop_get_devs() to get all mounted devices per dd.xml
- Fixes:
-- make_fs(): reserve max possible GDT block for online resize
-- do_lock(): set FD_CLOEXEC explicitly on lock fd
-- fix raw image creation (broken in ploop 1.8)
-- return SYSEXIT_SYS on ploop_find_dev_by_uuid() failure
-- ploop.spec: run ldconfig on install/uninstall
- Improvements:
-- Display mount data in error message on mount() failure
-- dynload.h: pad the struct ploop_functions to 64 pointers
-- gensym.sh: add code to check sizeof(struct ploop_function)
-- etc/Makefile: ploop.conf should not be executable
-- Makefile.inc: support Debian multiarch
-- Makefile: add distclean target
-- Makefile cleanups

* Tue Jul  9 2013 Kir Kolyshkin <kir@openvz.org> 1.8-1
- New functionality:
-- convert from/to v1/v2 ploop version format (ploop convert -v)
-- ploop_mount_fs(): add option to run fsck
-- ploop mount: add -F to run fsck for inner fs
-- export ploop_is_large_disk_supported()
-- add/export ploop_get_spec()
-- ploop fsck: rename to ploop check
- Fixes:
-- resize_gpt_partition(): skip if there is no partition
-- switch snapshot: read parameters from image we are to switch to
-- ploop create: error out if DiskDescriptor.xml exists
-- e2fsck(): properly check e2fsck binary exit code
-- ploop grow: check size wrt format
-- tools/Makefile: don't strip binaries on install
-- ploop init: fix an error message
- Improvements:
-- create_image(): remove useless assignment
-- number of log messages improved/fixed
-- tools parse_size(): print error
-- tools/ploop: allow T suffix for blockdev size
-- ploop_grow_delta_offline(): use delta.version
-- tune_fs(): drop absolute path to tune2fs
- Documentation:
-- ploop init usage: add -v VERSION
-- ploop --help: rm -P from ploop mount syntax
-- ploop(8): add -v for ploop init
-- ploop(8): add ploop resize to SYNOPSYS
-- ploop(8): add ploop convert
-- ploop(8): add -F for ploop mount

* Mon Jun 10 2013 Kir Kolyshkin <kir@openvz.org> 1.7.1-1
- Fixes:
-- default image format is V1, unless specified explicitly
-- tmpfiles.d file added for /var/lock/ploop (#2493)
-- fixed creating strange directories under ./ (#2623)

* Fri May 31 2013 Kir Kolyshkin <kir@openvz.org> 1.7-1
- New functionality:
-- Large ploop image format support
--- Now image size limit is 64 TB (was 2TB)
--- Kernel >= 042stab078 is required
-- Move ploop_grow* functions from tools to lib
-- ploop grow: add DiskDescriptor.xml support
-- ploop init, ploop_create_image(): add FS blocksize parameter
- Improvements:
-- make_fs(): create ext4fs with lazy_itable_init
--- 3x smaller size and 3x faster creation time for 20GB image
-- lib/ploop.h: "unexport" some internal functions
-- Use /proc/self/mountinfo to get mount point by device
-- More clear errors on parsing DiskDescriptor.xml
-- print_output(): generalize print_lsof(), improve
-- add_delta(): print more diags if EBUSY
-- extend_delta_array(): print errors, return SYSEXIT_*
-- run_prg(): print error if execvp() failed
-- lib/balloon.c: print file name in an error message
-- Introduce and use p_memalign(), fix errno handling
-- Improvements and fixes to ploop_grow_*() to be used from library
-- ploop_read_disk_descr(): set *di to NULL in case of error
-- ploop_find_dev(): always assume ploop cookie is supported
-- resize_fs(): try harder to find resize2fs binary
-- Makefile.inc: ability to add CFLAGS
- Fixes:
-- lib/lock.c: create_file(): make sure dir exists (#2493, #2597)
-- lib/fsutils.c: use ploop_execvp, drop absolute paths to binaries (#2595)
-- ploop_log(): fix loglevel checking for file logging
-- ploop_snapshot_switch_param: guids are const
-- Recreate ploopXpY devices on ploop mount
-- ploop_find_dev(): treat ENODEV as ENOENT on /sys reads
-- use basename() to strip device from path
-- ploop list: check for extra arguments
-- ploop balloon: fix -f option processing
-- Fixed lots of memory leaks, mostly on error paths
-- open_delta(): simplify error handling
-- Fixes for other issues big and small, reported by Coverity

* Mon Dec 31 2012 Kir Kolyshkin <kir@openvz.org> 1.6-1
- New functionality:
- * offline image shrink support
- * tools: added snapshot-list functionality
- * extend switch snapshot functionality: ploop_switch_snapshot_ex()
- * ploop.spec: disable udev iosched config for ploop devices
- * ploop list: added functionality to list mount points
- Bug fixes:
- * ploop_mount_fs(): use mount_data for first mount
- * ploop_mount(): do not allow to use ploop on fs w/o extents
- * ploop_{create,resize}_image(): fixed size checks and rounding
- * ploop_create_image(): fix memory leak on error path
- * ploop_get_info(): fix reported disk size after switching snapshot
- * ploop_get_info(): fix when ploop device is not mounted
- * ploop_{umount,resize}_image() and many others: do not return -1
- Improvements:
- * much faster resize when using resize2fs with EXT4_IOC_RESIZE_FS support
- * ploop discard: add cancellation support
- * ploop_resize_image(): use real blocksize
- * parse_xml(): deny processing DiskDescriptor.xml with several <Storage>
- * do not auto-generate dynload.h, instead check if it's uptodate
- * create_image(): display error message for incorrect parameters case
- * introduce/use SYSEXIT_DEV_NOT_MOUNTED and SYSEXIT_FSCK errors
- * alloc_diskdescriptor(): log error if calloc() fails
- * ploop.spec: require util-linux, e2fsprogs etc.
- * ploop.spec: require libs of the proper arch

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
