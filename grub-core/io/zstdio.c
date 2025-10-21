/* zstdio.c - decompression support for zstd */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025  Free Software Foundation, Inc.
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

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

#include "zstd.h"

#define STREAM_HEADER_SIZE 16

struct zstdio
{
  grub_file_t file;
  ZSTD_DCtx *dctx;
  grub_size_t insize;
  grub_size_t outsize;

  ZSTD_outBuffer output;
  ZSTD_inBuffer input;

  grub_off_t saved_offset;
  grub_uint8_t bufs[];
};
typedef struct zstdio *zstdio_t;

static struct grub_fs zstdio_fs;

static bool
test_header (grub_file_t file)
{
  zstdio_t zstdio = file->data;
  size_t zret;

  zstdio->input.pos = 0;
  zstdio->output.pos = 0;
  zstdio->output.size = zstdio->outsize;
  zstdio->input.size = grub_file_read (zstdio->file, zstdio->bufs,
                                       STREAM_HEADER_SIZE);
  if (zstdio->input.size != STREAM_HEADER_SIZE)
    return false;

  zret = ZSTD_decompressStream (zstdio->dctx, &zstdio->output, &zstdio->input);
  if (ZSTD_isError (zret))
    return false;

  return true;
}

static grub_file_t
grub_zstdio_open (grub_file_t io, enum grub_file_type type)
{
  grub_file_t file;
  zstdio_t zstdio;

  if (type & GRUB_FILE_TYPE_NO_DECOMPRESS)
    return io;

  file = (grub_file_t) grub_zalloc (sizeof (*file));
  if (file == NULL)
    return NULL;

  zstdio = grub_zalloc (sizeof (zstdio_t) + ZSTD_DStreamInSize () +
                        ZSTD_DStreamOutSize ());
  if (zstdio == NULL)
    {
      grub_free (file);
      return NULL;
    }

  zstdio->file = io;
  zstdio->insize = ZSTD_DStreamInSize ();
  zstdio->outsize = ZSTD_DStreamOutSize ();
  zstdio->input.src = zstdio->bufs;
  zstdio->output.dst = &zstdio->bufs[zstdio->insize];

  file->device = io->device;
  file->data = zstdio;
  file->fs = &zstdio_fs;
  file->size = GRUB_FILE_SIZE_UNKNOWN;
  file->not_easily_seekable = 1;

  if (grub_file_tell (zstdio->file) != 0)
    if (grub_file_seek (zstdio->file, 0) == (grub_off_t) -1)
      {
	grub_free (file);
	grub_free (zstdio);
	return NULL;
      }

  zstdio->dctx = ZSTD_createDCtx ();
  if (zstdio->dctx == NULL)
    {
      grub_free (file);
      grub_free (zstdio);
      return NULL;
    }

  if (test_header (file) == false)
    {
      grub_errno = GRUB_ERR_NONE;
      if (grub_file_seek (io, 0) == (grub_off_t) -1)
	{
	  grub_free (file);
	  grub_free (zstdio);
	  return NULL;
	}

      ZSTD_freeDCtx (zstdio->dctx);
      grub_free (zstdio);
      grub_free (file);

      return io;
    }

  return file;
}

static grub_ssize_t
grub_zstdio_read (grub_file_t file, char *buf, grub_size_t len)
{
  zstdio_t zstdio = file->data;
  grub_ssize_t ret = 0;
  grub_ssize_t readret;
  grub_off_t current_offset;
  grub_off_t new_offset;
  grub_size_t delta;
  grub_size_t zret;

  /* If seek backward need to reset decoder and start from beginning of file. */
  if (file->offset < zstdio->saved_offset)
    {
      ZSTD_initDStream (zstdio->dctx);
      zstdio->input.pos = 0;
      zstdio->input.size = 0;
      zstdio->output.pos = 0;
      zstdio->saved_offset = 0;
      grub_file_seek (zstdio->file, 0);
    }

  current_offset = zstdio->saved_offset;

  while (len > 0)
    {
      zstdio->output.size = file->offset + ret + len - current_offset;
      if (zstdio->output.size > zstdio->outsize)
        zstdio->output.size = zstdio->outsize;
      if (zstdio->input.pos == zstdio->input.size)
        {
          readret = grub_file_read (zstdio->file, zstdio->bufs,
                                    zstdio->insize);
          if (readret < 0)
            return -1;

          zstdio->input.size = readret;
          zstdio->input.pos = 0;
        }

      zret = ZSTD_decompressStream (zstdio->dctx, &zstdio->output,
                                    &zstdio->input);
      if (ZSTD_isError (zret))
        {
          grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
                      N_("zstd file corrupted or unsupported block options"));
          return -1;
        }

      new_offset = current_offset + zstdio->output.pos;

      /* Store first chunk of data in buffer.  */
      if (file->offset <= new_offset)
        {
          delta = new_offset - (file->offset + ret);
          grub_memmove (buf, (grub_uint8_t *) zstdio->output.dst +
                        (zstdio->output.pos - delta),
                        delta);
          len -= delta;
          buf += delta;
          ret += delta;
        }
        current_offset = new_offset;

        zstdio->output.pos = 0;

        if (zstdio->input.pos == 0 && zstdio->output.pos == 0)
          break;
    }

  if (ret >= 0)
    zstdio->saved_offset = file->offset + ret;

  return ret;
}

/* Release everything, including the underlying file object.  */
static grub_err_t
grub_zstdio_close (grub_file_t file)
{
  zstdio_t zstdio = file->data;

  ZSTD_freeDCtx (zstdio->dctx);

  grub_file_close (zstdio->file);
  grub_free (zstdio);

  /* Device must not be closed twice.  */
  file->device = 0;
  file->name = 0;
  return grub_errno;
}

static struct grub_fs zstdio_fs = {
  .name = "zstdio",
  .fs_dir = 0,
  .fs_open = 0,
  .fs_read = grub_zstdio_read,
  .fs_close = grub_zstdio_close,
  .fs_label = 0,
  .next = 0
};

GRUB_MOD_INIT (zstdio)
{
  grub_file_filter_register (GRUB_FILE_FILTER_ZSTDIO, grub_zstdio_open);
}

GRUB_MOD_FINI (zstdio)
{
  grub_file_filter_unregister (GRUB_FILE_FILTER_ZSTDIO);
}
