/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009, 2010  Free Software Foundation, Inc.
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

#ifndef GRUB_POSIX_STDLIB_H
#define GRUB_POSIX_STDLIB_H	1

#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/safemath.h>

static inline void 
free (void *ptr)
{
  grub_free (ptr);
}

static inline void *
malloc (grub_size_t size)
{
  return grub_malloc (size);
}

static inline void *
calloc (grub_size_t size, grub_size_t nelem)
{
  grub_size_t sz;

  if (grub_mul (size, nelem, &sz))
    return NULL;

  return grub_zalloc (sz);
}

static inline void *
realloc (void *ptr, grub_size_t size)
{
  return grub_realloc (ptr, size);
}

static inline int
abs (int c)
{
  return (c >= 0) ? c : -c;
}

#define strtol grub_strtol

/* for libgcrypt */
#define HAVE_STRTOUL
#define strtoul grub_strtoul

#define strtoull grub_strtoull

#endif
