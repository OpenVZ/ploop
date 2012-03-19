/*
 *  Copyright (C) 2008-2012, Parallels, Inc. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __PLOOP1_IMAGE_H__
#define __PLOOP1_IMAGE_H__ 1

/* Definition of PVD (Parallels Virtual Disk) format
 *
 * 1. All the data are in ?little-endian? format.
 * 2. All the data except for the first cluster are aligned and padded
 *    to size of cluster. First cluster is exception - it combines
 *    PVD header (first 64 bytes of the cluster) with L2 index table
 *    (L2 index table is an array of indices of blocks)
 * 3. Image size must be multiple of cluster size. If it is not,
 *    we assume it is the result of image extension failed in the
 *    middle of transaction, therefore new allocations start at
 *    size rounded down to cluster size.
 * 4. Update of indices must be done only after data clusters
 *    are committed to reliable storage. If we fail to update index,
 *    we can get an unused and, maybe, uninitialized or partially
 *    initialized data cluster. It is lost, forgotten and ignored
 *    until repair or image rebuild.
 */

/*
 * copy/paste of IMAGE_PARAMETERS from DiskImageComp.h
 */
struct ploop_pvd_header
{
	__u8  m_Sig[16];          /* Signature */
	__u32 m_Type;             /* Disk type */
	__u32 m_Heads;            /* heads count */
	__u32 m_Cylinders;        /* tracks count */
	__u32 m_Sectors;          /* Sectors per track count */
	__u32 m_Size;             /* Size of disk in tracks */
	__u32 m_SizeInSectors;    /* Size of disk in 512-byte sectors */
	__u32 Unused;             /* Unused for now */
	__u32 m_DiskInUse;        /* Disk in use */
	__u32 m_FirstBlockOffset; /* First data block offset (in sectors) */
	__u32 m_Flags;            /* Misc flags */
	__u8  m_Reserved[8];      /* Reserved */
};

/* Compressed disk (version 1) */
#define PRL_IMAGE_COMPRESSED		2

/* Compressed disk v1 signature */
#define SIGNATURE_STRUCTURED_DISK "WithoutFreeSpace"

/* Sign that the disk is in "using" state */
#define SIGNATURE_DISK_IN_USE		0x746F6E59

/**
 * Compressed disk image flags
 */
#define	CIF_NoFlags		0x00000000 /* No any flags */
#define	CIF_Empty		0x00000001 /* No any data was written */
#define	CIF_Invalid		0xFFFFFFFF /* Invalid flag */


#define PLOOP1_SECTOR_LOG	9
#define PLOOP1_DEF_CLUSTER_LOG	9 /* 256K cluster-block */
#define DEF_CLUSTER (1UL << (PLOOP1_DEF_CLUSTER_LOG + PLOOP1_SECTOR_LOG))

/* Helpers to generate PVD-header based on requested bdsize */

#define DEFAULT_HEADS_COUNT   16
#define DEFAULT_SECTORS_COUNT 63
#define SECTOR_SIZE (1 << 9)

struct CHSData
{
	__u32 Sectors;
	__u32 Heads;
	__u32 Cylinders;
};

/*
 * Try to count disk sectors per track value
 */
static inline __u32
CalcSectors(const __u64 uiSize)
{
	/* Try to determine sector count */
	if (!(uiSize % DEFAULT_SECTORS_COUNT))
		return DEFAULT_SECTORS_COUNT;

	if (!(uiSize % 32))
		return 32;

	if (!(uiSize % 16))
		return 16;

	if (!(uiSize % 8))
		return 8;

	return ~0;
}

/*
 * Try to count disk heads value
 */
static inline __u32
CalcHeads(const __u64 uiSize)
{
	/* Try to determine heads count */
	if (!(uiSize % DEFAULT_HEADS_COUNT))
		return DEFAULT_HEADS_COUNT;

	if (!(uiSize % 8))
		return 8;

	if (!(uiSize % 4))
		return 4;

	if (!(uiSize % 2))
		return 2;

	return ~0;
}

/*
 * Convert size to CHS for disks from 504 Mb to 8 Gb
 */
static inline void
ConvertToCHSLow(__u64 From, struct CHSData *chs)
{
	chs->Sectors = DEFAULT_SECTORS_COUNT;
	chs->Heads = DEFAULT_HEADS_COUNT;
	chs->Cylinders = From / ( DEFAULT_SECTORS_COUNT * DEFAULT_HEADS_COUNT);
}

/*
 * Convert size to pure LBA config
 */
static inline void
ConvertToPureLBA(__u64 From, struct CHSData *chs)
{
	chs->Sectors = 1;
	chs->Heads = 1;
	chs->Cylinders = From;
}

static inline void
ConvertToCHS(__u64 From, struct CHSData *chs)
{
	__u64 Size;

	/*
	 * According to ATA2 specs:
	 *  - If the device is above 1,032,192 sectors then the value should be 63.
	 *    This value does not exceed 63 (3Fh). But note, that if device size
	 *    above 16,777,216 the HDD reports proper 'magic' number in CHS values,
	 *    so the situation in the middle must be handled separately
	 */
	if ((From > 1032192) && (From < 16777216))
	{
		ConvertToCHSLow(From, chs);
		return;
	}

	Size = From;

	/* Store size */
	chs->Sectors = CalcSectors(Size);

	if (chs->Sectors == (__u32)~0)
		goto PureLBA;

	Size /= chs->Sectors;

	chs->Heads = CalcHeads(Size);

	if (chs->Heads == (__u32)~0)
		goto PureLBA;

	Size /= chs->Heads;

	chs->Cylinders = Size;

	return;

PureLBA:
	ConvertToPureLBA(From, chs);
}

static inline __u32
GetHeaderSize(__u32 m_Size)
{
	__u32 Size = sizeof(struct ploop_pvd_header);

	/* Add BAT */
	Size += m_Size * sizeof(__u32);
	/* Align to size of sector */
	Size = (Size + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);

	return Size;
}

/*
 * Returns: "size to fill" (in bytes)
 *
 * NB: m_Flags and m_DiskInUse are being kept as is; our caller
 * should take care of them.
 */
static inline __u32
generate_pvd_header(struct ploop_pvd_header *vh, off_t bdsize, __u32 blocksize)
{
	struct CHSData chs;
	__u32 SizeToFill;
	__u32 uiAlignmentSize;

	memcpy(vh->m_Sig, SIGNATURE_STRUCTURED_DISK, sizeof(vh->m_Sig));
	vh->m_Type = PRL_IMAGE_COMPRESSED;

	/* Round up to block size */
	vh->m_SizeInSectors = bdsize + blocksize - 1;
	vh->m_SizeInSectors /= blocksize;
	vh->m_SizeInSectors *= blocksize;

	ConvertToCHS(vh->m_SizeInSectors, &chs);

	vh->m_Sectors = blocksize;
	vh->m_Heads = chs.Heads;
	vh->m_Cylinders = chs.Cylinders;

	vh->m_Size = vh->m_SizeInSectors / blocksize;

	uiAlignmentSize = blocksize << 9;
	SizeToFill = GetHeaderSize(vh->m_Size);
	/* Align to block size */
	if (SizeToFill % uiAlignmentSize)
		SizeToFill += uiAlignmentSize - (SizeToFill % uiAlignmentSize);

	vh->m_FirstBlockOffset = SizeToFill >> 9;

	return SizeToFill;
}


/* Translation of sector number to offset in image */

#if 0

/* Those function are not really used */

/* Calculate virtual cluster number from virtual sector number */

static inline __u32
ploop1_cluster(struct ploop_img_header * info, __u64 sector)
{
	return sector >> info->cluster_log;
}

/* Get amount of clusters covered by one L2 table, 32K by default,
 * which can map 4G of data
 */
static inline __u32
ploop1_clusters_per_l2(struct ploop_img_header * info)
{
	return 1 << (info->cluster_log + info->sector_log - 2);
}

/* Calculate index in L1 table mapping a cluster. */

static inline __u32
ploop1_l1_index(struct ploop_img_header * info, __u32 cluster)
{
	return cluster >> (info->cluster_log + info->sector_log - 2);
}

/* Calculate index in L2 table mapping a cluster. */

static inline __u32
ploop1_l2_index(struct ploop_img_header * info, __u32 cluster)
{
	return cluster & (ploop1_clusters_per_l2(info) - 1);
}

/* That's all, simple and stupid */

#endif

#endif /* __PLOOP1_IMAGE_H__ */
