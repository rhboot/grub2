/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007  Free Software Foundation, Inc.
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

#ifndef GRUB_BITMAP_HEADER
#define GRUB_BITMAP_HEADER	1

#include <grub/err.h>
#include <grub/symbol.h>
#include <grub/types.h>
#include <grub/video.h>
#include <grub/safemath.h>

#define IMAGE_HW_MAX_PX		16384

struct grub_video_bitmap
{
  /* Bitmap format description.  */
  struct grub_video_mode_info mode_info;

  /* Pointer to bitmap data formatted according to mode_info.  */
  void *data;
};

struct grub_video_bitmap_reader
{
  /* File extension for this bitmap type (including dot).  */
  const char *extension;

  /* Reader function to load bitmap.  */
  grub_err_t (*reader) (struct grub_video_bitmap **bitmap,
                        const char *filename);

  /* Next reader.  */
  struct grub_video_bitmap_reader *next;
};
typedef struct grub_video_bitmap_reader *grub_video_bitmap_reader_t;

void EXPORT_FUNC (grub_video_bitmap_reader_register) (grub_video_bitmap_reader_t reader);
void EXPORT_FUNC (grub_video_bitmap_reader_unregister) (grub_video_bitmap_reader_t reader);

grub_err_t EXPORT_FUNC (grub_video_bitmap_create) (struct grub_video_bitmap **bitmap,
						   unsigned int width, unsigned int height,
						   enum grub_video_blit_format blit_format);

grub_err_t EXPORT_FUNC (grub_video_bitmap_destroy) (struct grub_video_bitmap *bitmap);

grub_err_t EXPORT_FUNC (grub_video_bitmap_load) (struct grub_video_bitmap **bitmap,
						 const char *filename);

/* Return bitmap width.  */
static inline unsigned int
grub_video_bitmap_get_width (struct grub_video_bitmap *bitmap)
{
  if (!bitmap)
    return 0;

  return bitmap->mode_info.width;
}

/* Return bitmap height.  */
static inline unsigned int
grub_video_bitmap_get_height (struct grub_video_bitmap *bitmap)
{
  if (!bitmap)
    return 0;

  return bitmap->mode_info.height;
}

/*
 * Calculate and store the size of data buffer of 1bit bitmap in result.
 * Equivalent to "*result = (width * height + 7) / 8" if no overflow occurs.
 * Return true when overflow occurs or false if there is no overflow.
 * This function is intentionally implemented as a macro instead of
 * an inline function. Although a bit awkward, it preserves data types for
 * safemath macros and reduces macro side effects as much as possible.
 *
 * XXX: Will report false overflow if width * height > UINT64_MAX.
 */
#define grub_video_bitmap_calc_1bpp_bufsz(width, height, result) \
({ \
  grub_uint64_t _bitmap_pixels; \
  grub_mul ((width), (height), &_bitmap_pixels) ? 1 : \
    grub_cast (_bitmap_pixels / GRUB_CHAR_BIT + !!(_bitmap_pixels % GRUB_CHAR_BIT), (result)); \
})

void EXPORT_FUNC (grub_video_bitmap_get_mode_info) (struct grub_video_bitmap *bitmap,
						    struct grub_video_mode_info *mode_info);

void *EXPORT_FUNC (grub_video_bitmap_get_data) (struct grub_video_bitmap *bitmap);

#endif /* ! GRUB_BITMAP_HEADER */
