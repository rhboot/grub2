/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
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

#ifndef GRUB_LIBNVPAIR_UTIL_HEADER
#define GRUB_LIBNVPAIR_UTIL_HEADER 1

#include <config.h>

#ifdef HAVE_LIBNVPAIR_H
#include <libnvpair.h>
#else /* ! HAVE_LIBNVPAIR_H */

#include <stdio.h>	/* FILE */

typedef void nvlist_t;

#ifdef GRUB_UTIL_NVPAIR_IS_PREFIXED
#define NVLIST(x) opensolaris_nvlist_ ## x
#else
#define NVLIST(x) nvlist_ ## x
#endif

int NVLIST(lookup_string) (nvlist_t *, const char *, char **);
int NVLIST(lookup_nvlist) (nvlist_t *, const char *, nvlist_t **);
int NVLIST(lookup_nvlist_array) (nvlist_t *, const char *, nvlist_t ***, unsigned int *);

#endif /* ! HAVE_LIBNVPAIR_H */

#endif
