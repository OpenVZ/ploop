.. contents:: Table of contents
   :depth: 3

Overview
========

Ploop library provides API to manage image files in **ploop** or **qcow2** format.
Device mapper layer is used to crate block device and work with image as a device,

Mount
=================

The mount action maps image to block device.

ploop
-----
* Create block device on ploop image

  $ dmsetup create <DEV> --table "0 <size> <block_size> [falloc_new_clu] ploop <fd> [... <fd>]"

* Load CBT if present (see `Set CBT for device`_)

qcow2
-----
* Create block device on qcow2 image

  $ dmsetup create <DEV> --table "0 <size> qcow2 <fd>"

* Load CBT if present (see `Store/load dirty bitmap to/from qcow2 image`_)

Unmount
=======

Sync data to image file and remove block device.

ploop
-----

* Store CBT if present (see `Get CBT from device`_)
* Remove device

  $ dmsetup remove <DEV>

qcow2
-----

* Store CBT if present (see `Move bitmap from ploop to qcow2`_)
* Remove device

  $ dmsetup remoe <DEV>

Resize
======

Grow
----

* Grow device
* resize GPT partition if exists
* resize file system

Shrink
------
* Get balloon file fd

  fd = ioctl(fd, XFS_IOC_OPEN_BALLOON, 0) 

  fd = ioctl(fd, EXT4_IOC_OPEN_BALLOON, 0

* Inflate balloon file

  fallocate(fd, size)


Create snapshot
===============

Create a checkpoint and start new changes from that point.
This allows to revert to that point in time.

ploop
-----

The create snapshot action adds extra image on top of the active 
image and set it as active, the previous active image became 'ro'

* Create new image
* Suspend device

  $ dmsetup suspend <DEV>

* Reload device with new image

  $ dmsetup reload <DEV> --table "0 <size> ploop <block_size> <fd> ... <new_fd>"

* resume

qcow2
-----
* Suspend device

  $ dmsetup suspend <DEV>

* Create image snapshot

  $ qemu-img snapshot -c <UUID> driver=qcow2,file.driver=file,file.filename=<IMAGE>,file.locking=off

* Reload device to apply new changes

  $ dmsetup reload <DEV> --table "0 <size> qcow2 <fd>"

* Resume

  $ dmsetup resume DEV

Delete snaphot
==============

ploop
-----

The delete snapshot action merges data from child to parent image.
There are three cases of online snapshot deletion

1. Child and parent images are 'ro'

 * Copy changed blocks from child to parent.
 * Reload device without child image
 * Remove child image

2. Child is TOP image and there are more than two images.

 * Merge TOP image
 
   $ dmsetup message DEV 0 merge

 * Remove TOP image

3. There only 2 images the BASE an the TOP.

 * Switch the BASE image to 'rw' mode
 * Set deny to resume flag on device
 
   $ dmsetup message <DEV> 0 set_noresume 1

 * Suspend device
 * Mark base image in 'zeroed' transition state
 * Zero clusters in BAT of the BASE image which preset in the TOP image
 * Swap images, BASE will be TOP
   
   $ dmsetup message <DEV> 0 flip_upper_deltas

 * Drop deny to resume flag

   $ dmsetup message <DEV> 0 set_noresume 0

 * Resume device
 * Merge TOP image

   $ dmsetup message DEV 0 merge

 * Remove TOP image

qcow2
_____

* Suspend device

  $ dmsetup suspend <DEV>

* Delete image snapshot

  $ qemu-img snapshot -d <ID> <IMAGE>

* Reload device

  $ dmsetup reload <DEV> --table "0 <size> qcow2 <fd>

* Resume device

  $ dmsetup resume <DEV>

Switch snapshot
===============

Revert to a previously created snapshot.

ploop
------

* Suspend device

  $ dmsetup suspend <DEV>

* Switch image snapshot

  1. create new TOP image
  2. add TOP image on top of image with snapshot ID we switched on

* Reload device

  $ dmsetup reload <DEV> --table "0 <size> qcow2 <fd> [... <top_fd>]

* Resume device

  $ dmsetup resume <DEV>

qcow2
-----

* Suspend device

  $ dmsetup suspend <DEV>

* Switch image snapshot

  $ qemu-img snapshot -a <ID> <IMAGE>

* Reload device

  $ dmsetup reload <DEV> --table "0 <size> qcow2 <fd>

* Resume device

  $ dmsetup resume <DEV>


Store/load dirty bitmap to/from qcow2 image
===========================================
qemu-kvm is used to manage dirty bitmap in qcow2 image.

Start QEMU
----------

Start QEMU with two block devices: raw ploop device, so that QEMU can get CBT by ioctl and qcow2 node (so that QEMU can store bitmaps to it). We know, that ploop is backed by same qcow2 file, but QEMU doesn't know it and consider them as different files.

To pass different files we define two different fd sets.

qemu-kvm -add-fd fd=10,set=1,opaque="qcow2-path" -add-fd fd=11,set=2,opaque="ploop"
::

 qemu-kvm -S -nodefaults -nographic \
    -add-fd fd=14,set=1,opaque="ro:/path/to/ploop/device" \  # FD of ploop device. It will be used only call ioctl to get the CBT
    -add-fd fd=15,set=2,opaque="rw:/path/to/disk.qcow2" \ # FD of qcow2. It will be used to store the CBT into it
    -blockdev '{"node-name": "vz-ploop", "driver": "host_device", "filename": "/dev/fdset/1"}' \  # block-node of ploop
    -blockdev '{"node-name": "vz-protocol-node", "driver": "file", "filename": "/dev/fdset/2", "locking": "off"} \  # protocol node of qcow2 file. Note locking=off, as lock is held by ploop utility. Used only to create qcow2 node on top of it, we'll not manipulate with protocol node directly
    -blockdev '{"node-name": "vz-qcow2-node", "driver": "qcow2", "file": "vz-protocol-node", "__vz_keep-dirty-bit": true} # format node of qcow2 file.

Note:

* we disable locking on qcow2 file 
* we use __vz_keep-dirty-bit=true so that Qemu don't touch qcow2 dirty bit: don't check on start, don't reset it neither on start nor on stop.
* driver: host_device is used for opening the device, not driver: file, like for regular files.

Move bitmap from ploop to qcow2
-------------------------------

`start QEMU`_

move CBT by qmp command
::

    qmp transaction {
      block-dirty-bitmap-add {"node": "vz-qcow2-node", "name": "UUID", "persistent": true}
      block-dirty-bitmap-merge { "node": "vz-qcow2-node", "target": "UUID", "bitmaps": [{"node": "vz-ploop", "name": "UUID", "__vz_pull": true}]}
    }

Note:

* persistent=true - this means that bitmap should be saved on Qemu stop.

Move bitmap from qcow2 to ploop node
------------------------------------

`Start QEMU`_

start CBT and set it by command:
::

    qmp: block-dirty-bitmap-merge { "node": "my-ploop", "target": "name-of-dirty-bitmap", "__vz_push": true, "bitmaps": [{"node": "my-qcow2-node", "name": "UUID"}]}

Kernal interface to manage CBT
==============================

Set CBT for device
------------------

1. Start CBT
::

 ioctl(fd, BLKCBTSTART, struct blk_user_cbt_info*ci)
      ci.ci_blksize is block size (usually 64K).
      ci.ci_uuid is CBT.
      The rest ci fields has to be zeroed.

 ERRORS: Any error is critical.

2. Load CBT mask
::

 ioctl(fd, BLKCBTSET, struct blk_user_cbt_info *ci)
      ci.ci_extent_count = CBT_MAX_EXTENTS (ci.ci_extent_count is number of passed extents)
      ci.ci_mapped_extents is equal to ci.ci_extent_count 
      ci.ci_extents are array of dirty extents you want to pass
      ci.ci_uuid is the same as in BLKCBTSTART
      The rest of fields has to be zeroed.

 ERRORS: Any error is critical (we should either drop CBT from image or break start).

Get CBT from device
-------------------

1, Merge CBT snapshot back. It exists in case of there was failed backup,
::

 ioctl(fd, BLKCBTMISC, struct blk_user_cbt_misc_info *cmi)
      cmi.action = CBT_SNAP_MERGE_BACK;
      cmi.uuid = uuid;

 ERRORS:

  -ENODEV is not critical, it means (there is no a snapshot).

  The rest of errors are critical (we stop CT without saving CBT).

2. Get CBT mask.
::

 ioctl(fd, BLKCBTGET, struct blk_user_cbt_info *ci):
      ci.ci_extent_count is number of extents (max is CBT_MAX_EXTENTS == 512)
      ci.ci_start is start of range you interested in bytes
      ci.ci_length is length of that range

   On exit the ioctl returns extents in ci.ci_extents and populates ci.ci_uuid.

ERRORS: Any error is critical

3. Stop CBT
::

 ioctl(fd, BLKCBTSTOP, NULL)

 ERRORS: Errors are not critical


Online image migration
======================

Online image migration logic consist from  3 stages

 1. start tracking and copy allocated blocks
 2. iteratively copy changed blocks
 3. suspend device and copy changed blocks

Block allocation information is taken from image header.
Chaned block tracking is based based on dm-tracking driver.

Tracking API:

  * create tracking device

    dmsetup create tracking_dev --table "0 <device_size_secs> tracking <clu_size_secs> DEV"

  * start tracking

    dmsetup supend tracking_dev

    dmsetup message tracking_dev 0 tracking_start

    dmsetup resume tracking_dev

  * stop tracking

    dmsetup message tracking_dev 0 tracking_stop

  * get next changed cluster

    dmsetup message tracking_dev 0 tracking_get_next





