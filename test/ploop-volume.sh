#!/bin/bash
set -e -x

TEST_DIR=$1
IMAGES=$TEST_DIR/images/
PLOOP_VOLUME='unshare -m ./tools/ploop-volume'

mkdir -p $IMAGES
mkdir -p $TEST_DIR/vol1-mnt
mkdir -p $TEST_DIR/vol2-mnt
mkdir -p $TEST_DIR/snap1-mnt
mkdir -p $TEST_DIR/snap2-mnt
 
# Create
$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1/ -s 10G
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1/
$PLOOP_VOLUME snapshot $TEST_DIR/vol1/ $TEST_DIR/snap2/
$PLOOP_VOLUME delete $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/snap1
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml 
$PLOOP_VOLUME delete $TEST_DIR/vol1

$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 11G
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/vol1
$PLOOP_VOLUME delete $TEST_DIR/snap1

$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 12G
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/snap1
$PLOOP_VOLUME delete $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/vol1

$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 13G
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/vol1
$PLOOP_VOLUME delete $TEST_DIR/snap1
$PLOOP_VOLUME delete $TEST_DIR/snap2

$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 14G
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/vol1
$PLOOP_VOLUME delete $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/snap1

$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 15G
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
$PLOOP_VOLUME snapshot $TEST_DIR/vol1/ $TEST_DIR/snap1/
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap2/
$PLOOP_VOLUME clone $TEST_DIR/snap1/ $TEST_DIR/vol2/
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml
$PLOOP_VOLUME delete $TEST_DIR/vol1/
$PLOOP_VOLUME delete $TEST_DIR/snap2/
$PLOOP_VOLUME delete $TEST_DIR/vol2/
$PLOOP_VOLUME delete $TEST_DIR/snap1/
 
$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 16G
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1
$PLOOP_VOLUME clone $TEST_DIR/snap1 $TEST_DIR/vol2
# A snapshot with child volumes can't be deleted
$PLOOP_VOLUME delete $TEST_DIR/snap1 && exit 1 || true
$PLOOP_VOLUME delete $TEST_DIR/vol2
test -d $TEST_DIR/vol2 && exit 1 || true
$PLOOP_VOLUME clone $TEST_DIR/snap1 $TEST_DIR/vol2
$PLOOP_VOLUME delete $TEST_DIR/vol2
$PLOOP_VOLUME delete $TEST_DIR/snap1
$PLOOP_VOLUME delete $TEST_DIR/vol1
test -d $TEST_DIR/vol1 && exit 1 || true
test -f $IMAGES/vol1 && exit 1 || true
 
$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 17G
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
touch $TEST_DIR/vol1-mnt/test_file
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1
mkdir -p $TEST_DIR/snap1-mnt
./tools/ploop mount $TEST_DIR/snap1/DiskDescriptor.xml -m $TEST_DIR/snap1-mnt
touch $TEST_DIR/snap1-mnt/test_file && exit 1 || true # snapshot mount is read-only
$PLOOP_VOLUME clone $TEST_DIR/snap1 $TEST_DIR/vol2
mkdir -p $TEST_DIR/vol2-mnt
$PLOOP_VOLUME snapshot $TEST_DIR/vol2 $TEST_DIR/snap2
./tools/ploop mount $TEST_DIR/vol2/DiskDescriptor.xml -m $TEST_DIR/vol2-mnt
test -f $TEST_DIR/vol2-mnt/test_file
touch $TEST_DIR/vol1-mnt/test_file2
test -f $TEST_DIR/vol1-mnt/test_file
test -f $TEST_DIR/vol2-mnt/test_file

./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml
$PLOOP_VOLUME delete $TEST_DIR/snap2
./tools/ploop umount $TEST_DIR/vol2/DiskDescriptor.xml
$PLOOP_VOLUME delete $TEST_DIR/vol2
./tools/ploop umount $TEST_DIR/snap1/DiskDescriptor.xml
$PLOOP_VOLUME delete $TEST_DIR/snap1
$PLOOP_VOLUME delete $TEST_DIR/vol1
 
 # switch
$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 10G
$PLOOP_VOLUME clone $TEST_DIR/vol1 $TEST_DIR/vol2
$PLOOP_VOLUME switch $TEST_DIR/vol1 $TEST_DIR/vol2 || true
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
$PLOOP_VOLUME switch $TEST_DIR/vol2 $TEST_DIR/vol1
./tools/ploop mount $TEST_DIR/vol2/DiskDescriptor.xml -m $TEST_DIR/vol2-mnt
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml
./tools/ploop umount $TEST_DIR/vol2/DiskDescriptor.xml
$PLOOP_VOLUME delete $TEST_DIR/vol2
$PLOOP_VOLUME delete $TEST_DIR/vol1
 
$PLOOP_VOLUME create --image $IMAGES/vol1 $TEST_DIR/vol1 -s 11G
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
touch $TEST_DIR/vol1-mnt/snap1
$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap1
touch $TEST_DIR/vol1-mnt/snap2
./tools/ploop mount $TEST_DIR/snap1/DiskDescriptor.xml -m $TEST_DIR/snap1-mnt
test -f $TEST_DIR/snap1-mnt/snap1
test -f $TEST_DIR/snap1-mnt/snap2 || true
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml 

$PLOOP_VOLUME switch $TEST_DIR/vol1 $TEST_DIR/snap1
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
test -f $TEST_DIR/vol1-mnt/snap1
test -f $TEST_DIR/vol1-mnt/snap2 || true
touch $TEST_DIR/vol1-mnt/snap2
 
$PLOOP_VOLUME switch $TEST_DIR/vol1 $TEST_DIR/snap1 || true
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml

$PLOOP_VOLUME snapshot $TEST_DIR/vol1 $TEST_DIR/snap2
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
test -f $TEST_DIR/vol1-mnt/snap1
test -f $TEST_DIR/vol1-mnt/snap2
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml
./tools/ploop umount $TEST_DIR/snap1/DiskDescriptor.xml

$PLOOP_VOLUME switch $TEST_DIR/vol1 $TEST_DIR/snap1
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
test -f $TEST_DIR/vol1-mnt/snap1
test -f $TEST_DIR/vol1-mnt/snap2 || true
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml

$PLOOP_VOLUME switch $TEST_DIR/vol1 $TEST_DIR/snap2
./tools/ploop mount $TEST_DIR/vol1/DiskDescriptor.xml -m $TEST_DIR/vol1-mnt
test -f $TEST_DIR/vol1-mnt/snap1
test -f $TEST_DIR/vol1-mnt/snap2
./tools/ploop umount $TEST_DIR/vol1/DiskDescriptor.xml
$PLOOP_VOLUME delete $TEST_DIR/snap2
$PLOOP_VOLUME delete $TEST_DIR/snap1
$PLOOP_VOLUME delete $TEST_DIR/vol1
 
 exit 0
