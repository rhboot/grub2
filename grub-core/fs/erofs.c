/* erofs.c - Enhanced Read-Only File System */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/fshelp.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/safemath.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define EROFS_SUPER_OFFSET	1024
#define EROFS_MAGIC		0xE0F5E1E2
#define EROFS_ISLOTBITS		5

#define EROFS_FEATURE_INCOMPAT_CHUNKED_FILE	0x00000004
#define EROFS_ALL_FEATURE_INCOMPAT		EROFS_FEATURE_INCOMPAT_CHUNKED_FILE

struct grub_erofs_super
{
  grub_uint32_t		magic;
  grub_uint32_t		checksum;
  grub_uint32_t		feature_compat;
  grub_uint8_t		log2_blksz;
  grub_uint8_t		sb_extslots;

  grub_uint16_t		root_nid;
  grub_uint64_t		inos;

  grub_uint64_t		build_time;
  grub_uint32_t		build_time_nsec;
  grub_uint32_t		blocks;
  grub_uint32_t		meta_blkaddr;
  grub_uint32_t		xattr_blkaddr;
  grub_packed_guid_t	uuid;
  grub_uint8_t		volume_name[16];
  grub_uint32_t		feature_incompat;

  union
  {
    grub_uint16_t	available_compr_algs;
    grub_uint16_t	lz4_max_distance;
  } GRUB_PACKED u1;

  grub_uint16_t		extra_devices;
  grub_uint16_t		devt_slotoff;
  grub_uint8_t		log2_dirblksz;
  grub_uint8_t		xattr_prefix_count;
  grub_uint32_t		xattr_prefix_start;
  grub_uint64_t		packed_nid;
  grub_uint8_t		reserved2[24];
} GRUB_PACKED;

#define EROFS_INODE_LAYOUT_COMPACT	0
#define EROFS_INODE_LAYOUT_EXTENDED	1

#define EROFS_INODE_FLAT_PLAIN		0
#define EROFS_INODE_COMPRESSED_FULL	1
#define EROFS_INODE_FLAT_INLINE		2
#define EROFS_INODE_COMPRESSED_COMPACT	3
#define EROFS_INODE_CHUNK_BASED		4

#define EROFS_I_VERSION_MASKS		0x01
#define EROFS_I_DATALAYOUT_MASKS	0x07

#define EROFS_I_VERSION_BIT	0
#define EROFS_I_DATALAYOUT_BIT	1

struct grub_erofs_inode_chunk_info
{
  grub_uint16_t		format;
  grub_uint16_t		reserved;
} GRUB_PACKED;

#define EROFS_CHUNK_FORMAT_BLKBITS_MASK	0x001F
#define EROFS_CHUNK_FORMAT_INDEXES	0x0020

#define EROFS_BLOCK_MAP_ENTRY_SIZE	4
#define EROFS_MAP_MAPPED		0x02

#define EROFS_NULL_ADDR			1
#define EROFS_NAME_LEN			255
#define EROFS_PATH_LEN			4096
#define EROFS_MIN_LOG2_BLOCK_SIZE	9
#define EROFS_MAX_LOG2_BLOCK_SIZE	16

struct grub_erofs_inode_chunk_index
{
  grub_uint16_t		advise;
  grub_uint16_t		device_id;
  grub_uint32_t		blkaddr;
};

union grub_erofs_inode_i_u
{
  grub_uint32_t				compressed_blocks;
  grub_uint32_t				raw_blkaddr;

  grub_uint32_t				rdev;

  struct grub_erofs_inode_chunk_info	c;
};

struct grub_erofs_inode_compact
{
  grub_uint16_t			i_format;

  grub_uint16_t			i_xattr_icount;
  grub_uint16_t			i_mode;
  grub_uint16_t			i_nlink;
  grub_uint32_t			i_size;
  grub_uint32_t			i_reserved;

  union grub_erofs_inode_i_u	i_u;

  grub_uint32_t			i_ino;
  grub_uint16_t			i_uid;
  grub_uint16_t			i_gid;
  grub_uint32_t			i_reserved2;
} GRUB_PACKED;

struct grub_erofs_inode_extended
{
  grub_uint16_t			i_format;

  grub_uint16_t			i_xattr_icount;
  grub_uint16_t			i_mode;
  grub_uint16_t			i_reserved;
  grub_uint64_t			i_size;

  union grub_erofs_inode_i_u	i_u;

  grub_uint32_t			i_ino;

  grub_uint32_t			i_uid;
  grub_uint32_t			i_gid;
  grub_uint64_t			i_mtime;
  grub_uint32_t			i_mtime_nsec;
  grub_uint32_t			i_nlink;
  grub_uint8_t			i_reserved2[16];
} GRUB_PACKED;

union grub_erofs_inode
{
  struct grub_erofs_inode_compact	c;
  struct grub_erofs_inode_extended	e;
} GRUB_PACKED;

#define EROFS_FT_UNKNOWN	0
#define EROFS_FT_REG_FILE	1
#define EROFS_FT_DIR		2
#define EROFS_FT_CHRDEV		3
#define EROFS_FT_BLKDEV		4
#define EROFS_FT_FIFO		5
#define EROFS_FT_SOCK		6
#define EROFS_FT_SYMLINK	7

struct grub_erofs_dirent
{
  grub_uint64_t		nid;
  grub_uint16_t		nameoff;
  grub_uint8_t		file_type;
  grub_uint8_t		reserved;
} GRUB_PACKED;

struct grub_erofs_map_blocks
{
  grub_uint64_t		m_pa;    /* physical address */
  grub_uint64_t		m_la;    /* logical address */
  grub_uint64_t		m_plen;  /* physical length */
  grub_uint64_t		m_llen;  /* logical length */
  grub_uint32_t		m_flags;
};

struct grub_erofs_xattr_ibody_header
{
  grub_uint32_t		h_reserved;
  grub_uint8_t		h_shared_count;
  grub_uint8_t		h_reserved2[7];
  grub_uint32_t		h_shared_xattrs[0];
};

struct grub_fshelp_node
{
  struct grub_erofs_data	*data;
  union grub_erofs_inode	inode;

  grub_uint64_t			ino;
  grub_uint8_t			inode_type;
  grub_uint8_t			inode_datalayout;

  /* If the inode has been read into memory? */
  bool				inode_loaded;
};

struct grub_erofs_data
{
  grub_disk_t			disk;
  struct grub_erofs_super	sb;

  struct grub_fshelp_node	inode;
};

#define erofs_blocksz(data) (((grub_uint32_t) 1) << data->sb.log2_blksz)

static grub_size_t
grub_erofs_strnlen (const char *s, grub_size_t n)
{
  const char *p = s;

  if (n == 0)
    return 0;

  while (n-- && *p)
    p++;

  return p - s;
}

static grub_uint64_t
erofs_iloc (grub_fshelp_node_t node)
{
  struct grub_erofs_super *sb = &node->data->sb;

  return ((grub_uint64_t) grub_le_to_cpu32 (sb->meta_blkaddr) << sb->log2_blksz) +
	 (node->ino << EROFS_ISLOTBITS);
}

static grub_err_t
erofs_read_inode (struct grub_erofs_data *data, grub_fshelp_node_t node)
{
  union grub_erofs_inode *di;
  grub_err_t err;
  grub_uint16_t i_format;
  grub_uint64_t addr = erofs_iloc (node);

  di = (union grub_erofs_inode *) &node->inode;

  err = grub_disk_read (data->disk, addr >> GRUB_DISK_SECTOR_BITS,
			addr & (GRUB_DISK_SECTOR_SIZE - 1),
			sizeof (struct grub_erofs_inode_compact), &di->c);
  if (err != GRUB_ERR_NONE)
    return err;

  i_format = grub_le_to_cpu16 (di->c.i_format);
  node->inode_type = (i_format >> EROFS_I_VERSION_BIT) & EROFS_I_VERSION_MASKS;
  node->inode_datalayout = (i_format >> EROFS_I_DATALAYOUT_BIT) & EROFS_I_DATALAYOUT_MASKS;

  switch (node->inode_type)
    {
    case EROFS_INODE_LAYOUT_EXTENDED:
      addr += sizeof (struct grub_erofs_inode_compact);
      err = grub_disk_read (data->disk, addr >> GRUB_DISK_SECTOR_BITS,
                            addr & (GRUB_DISK_SECTOR_SIZE - 1),
                            sizeof (struct grub_erofs_inode_extended) - sizeof (struct grub_erofs_inode_compact),
                            (grub_uint8_t *) di + sizeof (struct grub_erofs_inode_compact));
      if (err != GRUB_ERR_NONE)
	return err;
      break;
    case EROFS_INODE_LAYOUT_COMPACT:
      break;
    default:
      return grub_error (GRUB_ERR_BAD_FS, "invalid type %u @ inode %" PRIuGRUB_UINT64_T,
			 node->inode_type, node->ino);
    }

  node->inode_loaded = true;

  return 0;
}

static grub_uint64_t
erofs_inode_size (grub_fshelp_node_t node)
{
  return node->inode_type == EROFS_INODE_LAYOUT_COMPACT
	     ? sizeof (struct grub_erofs_inode_compact)
	     : sizeof (struct grub_erofs_inode_extended);
}

static grub_uint64_t
erofs_inode_file_size (grub_fshelp_node_t node)
{
  union grub_erofs_inode *di = (union grub_erofs_inode *) &node->inode;

  return node->inode_type == EROFS_INODE_LAYOUT_COMPACT
	     ? grub_le_to_cpu32 (di->c.i_size)
	     : grub_le_to_cpu64 (di->e.i_size);
}

static grub_uint32_t
erofs_inode_xattr_ibody_size (grub_fshelp_node_t node)
{
  grub_uint16_t cnt = grub_le_to_cpu16 (node->inode.e.i_xattr_icount);

  if (cnt == 0)
    return 0;

  return sizeof (struct grub_erofs_xattr_ibody_header) + ((cnt - 1) * sizeof (grub_uint32_t));
}

static grub_uint64_t
erofs_inode_mtime (grub_fshelp_node_t node)
{
  return node->inode_type == EROFS_INODE_LAYOUT_COMPACT
	     ? grub_le_to_cpu64 (node->data->sb.build_time)
	     : grub_le_to_cpu64 (node->inode.e.i_mtime);
}

static grub_err_t
erofs_map_blocks_flatmode (grub_fshelp_node_t node,
			   struct grub_erofs_map_blocks *map)
{
  grub_uint64_t nblocks, lastblk, file_size;
  bool tailendpacking = (node->inode_datalayout == EROFS_INODE_FLAT_INLINE);
  grub_uint64_t blocksz = erofs_blocksz (node->data);

  /* `file_size` is checked by caller and cannot be zero, hence nblocks > 0. */
  file_size = erofs_inode_file_size (node);
  if (grub_add (file_size, blocksz - 1, &nblocks))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "nblocks overflow");
  nblocks >>= node->data->sb.log2_blksz;
  lastblk = nblocks - tailendpacking;

  map->m_flags = EROFS_MAP_MAPPED;

  /* No overflow as (lastblk <= nblocks) && (nblocks * blocksz <= UINT64_MAX - blocksz + 1). */
  if (map->m_la < (lastblk * blocksz))
    {
      if (grub_mul ((grub_uint64_t) grub_le_to_cpu32 (node->inode.e.i_u.raw_blkaddr), blocksz, &map->m_pa) ||
	  grub_add (map->m_pa, map->m_la, &map->m_pa))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, "m_pa overflow");
      if (grub_sub (lastblk * blocksz, map->m_la, &map->m_plen))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, "m_plen underflow");
    }
  else if (tailendpacking)
    {
      if (grub_add (erofs_iloc (node), erofs_inode_size (node), &map->m_pa) ||
	  grub_add (map->m_pa, erofs_inode_xattr_ibody_size (node), &map->m_pa) ||
	  grub_add (map->m_pa, map->m_la & (blocksz - 1), &map->m_pa))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, "m_pa overflow when handling tailpacking");
      if (grub_sub (file_size, map->m_la, &map->m_plen))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, "m_plen overflow when handling tailpacking");

      /* No overflow as map->m_plen <= UINT64_MAX - blocksz + 1. */
      if (((map->m_pa & (blocksz - 1)) + map->m_plen) > blocksz)
	return grub_error (GRUB_ERR_BAD_FS,
                           "inline data cross block boundary @ inode %" PRIuGRUB_UINT64_T,
                           node->ino);
    }
  else
    return grub_error (GRUB_ERR_BAD_FS,
		       "invalid map->m_la=%" PRIuGRUB_UINT64_T
		       " @ inode %" PRIuGRUB_UINT64_T,
		       map->m_la, node->ino);

  map->m_llen = map->m_plen;
  return GRUB_ERR_NONE;
}

static grub_err_t
erofs_map_blocks_chunkmode (grub_fshelp_node_t node,
			    struct grub_erofs_map_blocks *map)
{
  grub_uint16_t chunk_format = grub_le_to_cpu16 (node->inode.e.i_u.c.format);
  grub_uint64_t unit, pos, chunknr, blkaddr;
  grub_uint8_t chunkbits;
  grub_err_t err;

  if (chunk_format & EROFS_CHUNK_FORMAT_INDEXES)
    unit = sizeof (struct grub_erofs_inode_chunk_index);
  else
    unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

  chunkbits = node->data->sb.log2_blksz + (chunk_format & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
  if (chunkbits > 63)
    return grub_error (GRUB_ERR_BAD_FS, "invalid chunkbits %u @ inode %" PRIuGRUB_UINT64_T,
		       chunkbits, node->ino);

  chunknr = map->m_la >> chunkbits;

  if (grub_add (erofs_iloc (node), erofs_inode_size (node), &pos))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "chunkmap position overflow when adding inode size");

  if (grub_add (pos, erofs_inode_xattr_ibody_size (node), &pos))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "chunkmap position overflow when adding xattr size");

  if (ALIGN_UP_OVF (pos, unit, &pos))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "position overflow when seeking at the start of chunkmap");

  /* No overflow for multiplication as chunkbits >= 9 and sizeof(unit) <= 8. */
  if (grub_add (pos, chunknr * unit, &pos))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "chunkmap position overflow when finding the specific chunk");

  map->m_la = chunknr << chunkbits;

  if (grub_sub (erofs_inode_file_size (node), map->m_la, &map->m_plen))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "m_plen underflow");
  map->m_plen = grub_min (((grub_uint64_t) 1) << chunkbits,
			  ALIGN_UP (map->m_plen, erofs_blocksz (node->data)));

  if (chunk_format & EROFS_CHUNK_FORMAT_INDEXES)
    {
      struct grub_erofs_inode_chunk_index idx;

      err = grub_disk_read (node->data->disk, pos >> GRUB_DISK_SECTOR_BITS,
			    pos & (GRUB_DISK_SECTOR_SIZE - 1), unit, &idx);
      if (err != GRUB_ERR_NONE)
	return err;

      blkaddr = grub_le_to_cpu32 (idx.blkaddr);
    }
  else
    {
      grub_uint32_t blkaddr_le;

      err = grub_disk_read (node->data->disk, pos >> GRUB_DISK_SECTOR_BITS,
			    pos & (GRUB_DISK_SECTOR_SIZE - 1), unit, &blkaddr_le);
      if (err != GRUB_ERR_NONE)
	return err;

      blkaddr = grub_le_to_cpu32 (blkaddr_le);
    }

  if (blkaddr == EROFS_NULL_ADDR)
    {
      map->m_pa = 0;
      map->m_flags = 0;
    }
  else
    {
      map->m_pa = blkaddr << node->data->sb.log2_blksz;
      map->m_flags = EROFS_MAP_MAPPED;
    }

  map->m_llen = map->m_plen;
  return GRUB_ERR_NONE;
}

static grub_err_t
erofs_map_blocks (grub_fshelp_node_t node, struct grub_erofs_map_blocks *map)
{
  if (map->m_la >= erofs_inode_file_size (node))
    {
      map->m_llen = map->m_plen = 0;
      map->m_pa = 0;
      map->m_flags = 0;
      return GRUB_ERR_NONE;
    }

  if (node->inode_datalayout != EROFS_INODE_CHUNK_BASED)
    return erofs_map_blocks_flatmode (node, map);
  else
    return erofs_map_blocks_chunkmode (node, map);
}

static grub_err_t
erofs_read_raw_data (grub_fshelp_node_t node, grub_uint8_t *buf, grub_uint64_t size,
		     grub_uint64_t offset, grub_uint64_t *bytes)
{
  struct grub_erofs_map_blocks map = {0};
  grub_uint64_t cur;
  grub_err_t err;

  if (bytes)
    *bytes = 0;

  if (node->inode_loaded == false)
    {
      err = erofs_read_inode (node->data, node);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  cur = offset;
  while (cur < offset + size)
    {
      grub_uint8_t *const estart = buf + cur - offset;
      grub_uint64_t eend, moff = 0;

      map.m_la = cur;
      err = erofs_map_blocks (node, &map);
      if (err != GRUB_ERR_NONE)
	return err;

      if (grub_add(map.m_la, map.m_llen, &eend))
	return grub_error (GRUB_ERR_OUT_OF_RANGE, "eend overflow");

      eend = grub_min (eend, offset + size);
      if (!(map.m_flags & EROFS_MAP_MAPPED))
	{
	  if (!map.m_llen)
	    {
	      /* Reached EOF. */
	      grub_memset (estart, 0, offset + size - cur);
	      cur = offset + size;
	      continue;
	    }

	  /* It's a hole. */
	  grub_memset (estart, 0, eend - cur);
	  if (bytes)
	    *bytes += eend - cur;
	  cur = eend;
	  continue;
	}

      if (cur > map.m_la)
	{
	  moff = cur - map.m_la;
	  map.m_la = cur;
	}

      err = grub_disk_read (node->data->disk,
			    (map.m_pa + moff) >> GRUB_DISK_SECTOR_BITS,
			    (map.m_pa + moff) & (GRUB_DISK_SECTOR_SIZE - 1),
			    eend - map.m_la, estart);
      if (err != GRUB_ERR_NONE)
	return err;

      if (bytes)
	*bytes += eend - map.m_la;

      cur = eend;
    }

  return GRUB_ERR_NONE;
}

static int
erofs_iterate_dir (grub_fshelp_node_t dir, grub_fshelp_iterate_dir_hook_t hook,
		   void *hook_data)
{
  grub_uint64_t offset = 0, file_size;
  grub_uint32_t blocksz = erofs_blocksz (dir->data);
  grub_uint8_t *buf;
  grub_err_t err;

  if (dir->inode_loaded == false)
    {
      err = erofs_read_inode (dir->data, dir);
      if (err != GRUB_ERR_NONE)
	return 0;
    }

  file_size = erofs_inode_file_size (dir);
  buf = grub_malloc (blocksz);
  if (buf == NULL)
    return 0;

  while (offset < file_size)
    {
      grub_uint64_t maxsize = grub_min (blocksz, file_size - offset);
      struct grub_erofs_dirent *de = (void *) buf, *end;
      grub_uint16_t nameoff;

      err = erofs_read_raw_data (dir, buf, maxsize, offset, NULL);
      if (err != GRUB_ERR_NONE)
	goto not_found;

      nameoff = grub_le_to_cpu16 (de->nameoff);
      if (nameoff < sizeof (struct grub_erofs_dirent) || nameoff >= maxsize)
	{
	  grub_error (GRUB_ERR_BAD_FS,
		      "invalid nameoff %u @ inode %" PRIuGRUB_UINT64_T,
		      nameoff, dir->ino);
	  goto not_found;
	}

      end = (struct grub_erofs_dirent *) ((grub_uint8_t *) de + nameoff);
      while (de < end)
	{
	  struct grub_fshelp_node *fdiro;
	  enum grub_fshelp_filetype type;
	  char filename[EROFS_NAME_LEN + 1];
	  grub_size_t de_namelen;
	  const char *de_name;

	  fdiro = grub_malloc (sizeof (struct grub_fshelp_node));
	  if (fdiro == NULL)
	    goto not_found;

	  fdiro->data = dir->data;
	  fdiro->ino = grub_le_to_cpu64 (de->nid);
	  fdiro->inode_loaded = false;

	  nameoff = grub_le_to_cpu16 (de->nameoff);
	  if (nameoff < sizeof (struct grub_erofs_dirent) || nameoff >= maxsize)
	    {
	      grub_error (GRUB_ERR_BAD_FS,
			  "invalid nameoff %u @ inode %" PRIuGRUB_UINT64_T,
			  nameoff, dir->ino);
	      grub_free (fdiro);
	      goto not_found;
	    }

	  de_name = (char *) buf + nameoff;
	  if (de + 1 >= end)
	    de_namelen = grub_erofs_strnlen (de_name, maxsize - nameoff);
	  else
	    {
	      if (grub_sub (grub_le_to_cpu16 (de[1].nameoff), nameoff, &de_namelen))
		{
		  grub_error (GRUB_ERR_OUT_OF_RANGE, "de_namelen underflow");
		  grub_free (fdiro);
		  goto not_found;
		}
	    }

	  if (nameoff + de_namelen > maxsize || de_namelen > EROFS_NAME_LEN)
	    {
	      grub_error (GRUB_ERR_BAD_FS,
			  "invalid de_namelen %" PRIuGRUB_SIZE
			  " @ inode %" PRIuGRUB_UINT64_T,
			  de_namelen, dir->ino);
	      grub_free (fdiro);
	      goto not_found;
	    }

	  grub_memcpy (filename, de_name, de_namelen);
	  filename[de_namelen] = '\0';

	  switch (grub_le_to_cpu16 (de->file_type))
	    {
	    case EROFS_FT_REG_FILE:
	    case EROFS_FT_BLKDEV:
	    case EROFS_FT_CHRDEV:
	    case EROFS_FT_FIFO:
	    case EROFS_FT_SOCK:
	      type = GRUB_FSHELP_REG;
	      break;
	    case EROFS_FT_DIR:
	      type = GRUB_FSHELP_DIR;
	      break;
	    case EROFS_FT_SYMLINK:
	      type = GRUB_FSHELP_SYMLINK;
	      break;
	    case EROFS_FT_UNKNOWN:
	    default:
	      type = GRUB_FSHELP_UNKNOWN;
	    }

	  if (hook (filename, type, fdiro, hook_data))
	    {
	      grub_free (buf);
	      return 1;
	    }

	  ++de;
	}

      offset += maxsize;
    }

 not_found:
  grub_free (buf);
  return 0;
}

static char *
erofs_read_symlink (grub_fshelp_node_t node)
{
  char *symlink;
  grub_size_t sz, lsz;
  grub_err_t err;

  if (node->inode_loaded == false)
    {
      err = erofs_read_inode (node->data, node);
      if (err != GRUB_ERR_NONE)
	return NULL;
    }

  sz = erofs_inode_file_size (node);
  if (sz >= EROFS_PATH_LEN)
    {
      grub_error (GRUB_ERR_BAD_FS,
		  "symlink too long @ inode %" PRIuGRUB_UINT64_T, node->ino);
      return NULL;
    }

  if (grub_add (sz, 1, &lsz))
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("symlink size overflow"));
      return NULL;
    }
  symlink = grub_malloc (lsz);
  if (symlink == NULL)
    return NULL;

  err = erofs_read_raw_data (node, (grub_uint8_t *) symlink, sz, 0, NULL);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (symlink);
      return NULL;
    }

  symlink[sz] = '\0';
  return symlink;
}

static struct grub_erofs_data *
erofs_mount (grub_disk_t disk, bool read_root)
{
  struct grub_erofs_super sb;
  grub_err_t err;
  struct grub_erofs_data *data;
  grub_uint32_t feature;

  err = grub_disk_read (disk, EROFS_SUPER_OFFSET >> GRUB_DISK_SECTOR_BITS, 0,
			sizeof (sb), &sb);
  if (err != GRUB_ERR_NONE)
    return NULL;
  if (sb.magic != grub_cpu_to_le32_compile_time (EROFS_MAGIC) ||
      grub_le_to_cpu32 (sb.log2_blksz) < EROFS_MIN_LOG2_BLOCK_SIZE ||
      grub_le_to_cpu32 (sb.log2_blksz) > EROFS_MAX_LOG2_BLOCK_SIZE)
    {
      grub_error (GRUB_ERR_BAD_FS, "not a valid erofs filesystem");
      return NULL;
    }

  feature = grub_le_to_cpu32 (sb.feature_incompat);
  if (feature & ~EROFS_ALL_FEATURE_INCOMPAT)
    {
      grub_error (GRUB_ERR_BAD_FS, "unsupported features: 0x%x",
		  feature & ~EROFS_ALL_FEATURE_INCOMPAT);
      return NULL;
    }

  data = grub_malloc (sizeof (*data));
  if (data == NULL)
    return NULL;

  data->disk = disk;
  data->sb = sb;

  if (read_root)
    {
      data->inode.data = data;
      data->inode.ino = grub_le_to_cpu16 (sb.root_nid);
      err = erofs_read_inode (data, &data->inode);
      if (err != GRUB_ERR_NONE)
	{
	  grub_free (data);
	  return NULL;
	}
    }

  return data;
}

/* Context for grub_erofs_dir. */
struct grub_erofs_dir_ctx
{
  grub_fs_dir_hook_t hook;
  void *hook_data;
  struct grub_erofs_data *data;
};

/* Helper for grub_erofs_dir. */
static int
erofs_dir_iter (const char *filename, enum grub_fshelp_filetype filetype,
		grub_fshelp_node_t node, void *data)
{
  struct grub_erofs_dir_ctx *ctx = data;
  struct grub_dirhook_info info = {0};
  grub_err_t err;

  if (node->inode_loaded == false)
    {
      err = erofs_read_inode (ctx->data, node);
      if (err != GRUB_ERR_NONE)
        return 0;
    }

  if (node->inode_loaded == true)
    {
      info.mtimeset = 1;
      info.mtime = erofs_inode_mtime (node);
    }

  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return ctx->hook (filename, &info, ctx->hook_data);
}

static grub_err_t
grub_erofs_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook,
		void *hook_data)
{
  grub_fshelp_node_t fdiro = NULL;
  grub_err_t err;
  struct grub_erofs_dir_ctx ctx = {
      .hook = hook,
      .hook_data = hook_data
  };

  ctx.data = erofs_mount (device->disk, true);
  if (ctx.data == NULL)
    goto fail;

  err = grub_fshelp_find_file (path, &ctx.data->inode, &fdiro, erofs_iterate_dir,
			       erofs_read_symlink, GRUB_FSHELP_DIR);
  if (err != GRUB_ERR_NONE)
    goto fail;

  erofs_iterate_dir (fdiro, erofs_dir_iter, &ctx);

 fail:
  if (fdiro != &ctx.data->inode)
    grub_free (fdiro);
  grub_free (ctx.data);

  return grub_errno;
}

static grub_err_t
grub_erofs_open (grub_file_t file, const char *name)
{
  struct grub_erofs_data *data;
  struct grub_fshelp_node *fdiro = NULL;
  grub_err_t err;

  data = erofs_mount (file->device->disk, true);
  if (data == NULL)
    {
      err = grub_errno;
      goto fail;
    }

  err = grub_fshelp_find_file (name, &data->inode, &fdiro, erofs_iterate_dir,
			       erofs_read_symlink, GRUB_FSHELP_REG);
  if (err != GRUB_ERR_NONE)
    goto fail;

  if (fdiro->inode_loaded == false)
    {
      err = erofs_read_inode (data, fdiro);
      if (err != GRUB_ERR_NONE)
	goto fail;
    }

  grub_memcpy (&data->inode, fdiro, sizeof (*fdiro));
  grub_free (fdiro);

  file->data = data;
  file->size = erofs_inode_file_size (&data->inode);

  return GRUB_ERR_NONE;

 fail:
  if (fdiro != &data->inode)
    grub_free (fdiro);
  grub_free (data);

  return err;
}

static grub_ssize_t
grub_erofs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_erofs_data *data = file->data;
  struct grub_fshelp_node *inode = &data->inode;
  grub_off_t off = file->offset;
  grub_uint64_t ret = 0, file_size;
  grub_err_t err;

  if (inode->inode_loaded == false)
    {
      err = erofs_read_inode (data, inode);
      if (err != GRUB_ERR_NONE)
	return -1;
    }

  file_size = erofs_inode_file_size (inode);

  if (off > file_size)
    {
      grub_error (GRUB_ERR_IO, "read past EOF @ inode %" PRIuGRUB_UINT64_T, inode->ino);
      return -1;
    }
  if (off == file_size)
    return 0;

  if (off + len > file_size)
    len = file_size - off;

  err = erofs_read_raw_data (inode, (grub_uint8_t *) buf, len, off, &ret);
  if (err != GRUB_ERR_NONE)
    return -1;

  return ret;
}

static grub_err_t
grub_erofs_close (grub_file_t file)
{
  grub_free (file->data);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_erofs_uuid (grub_device_t device, char **uuid)
{
  struct grub_erofs_data *data;

  data = erofs_mount (device->disk, false);
  if (data == NULL)
    {
      *uuid = NULL;
      return grub_errno;
    }

  *uuid = grub_xasprintf ("%pG", &data->sb.uuid);

  grub_free (data);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_erofs_label (grub_device_t device, char **label)
{
  struct grub_erofs_data *data;

  data = erofs_mount (device->disk, false);
  if (data == NULL)
    {
      *label = NULL;
      return grub_errno;
    }

  *label = grub_strndup ((char *) data->sb.volume_name, sizeof (data->sb.volume_name));
  grub_free (data);

  if (*label == NULL)
    return grub_errno;
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_erofs_mtime (grub_device_t device, grub_int64_t *tm)
{
  struct grub_erofs_data *data;

  data = erofs_mount (device->disk, false);
  if (data == NULL)
    {
      *tm = 0;
      return grub_errno;
    }

  *tm = grub_le_to_cpu64 (data->sb.build_time);

  grub_free (data);

  return GRUB_ERR_NONE;
}

static struct grub_fs grub_erofs_fs = {
    .name = "erofs",
    .fs_dir = grub_erofs_dir,
    .fs_open = grub_erofs_open,
    .fs_read = grub_erofs_read,
    .fs_close = grub_erofs_close,
    .fs_uuid = grub_erofs_uuid,
    .fs_label = grub_erofs_label,
    .fs_mtime = grub_erofs_mtime,
#ifdef GRUB_UTIL
    .reserved_first_sector = 1,
    .blocklist_install = 0,
#endif
    .next = 0,
};

GRUB_MOD_INIT (erofs)
{
  grub_erofs_fs.mod = mod;
  grub_fs_register (&grub_erofs_fs);
}

GRUB_MOD_FINI (erofs)
{
  grub_fs_unregister (&grub_erofs_fs);
}
