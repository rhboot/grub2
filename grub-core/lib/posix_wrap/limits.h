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

#ifndef GRUB_POSIX_LIMITS_H
#define GRUB_POSIX_LIMITS_H

#include <grub/types.h>

#define UCHAR_MAX GRUB_UCHAR_MAX
#define USHRT_MAX GRUB_USHRT_MAX
#define UINT_MAX GRUB_UINT_MAX
#define ULONG_MAX GRUB_ULONG_MAX
#define SIZE_MAX GRUB_SIZE_MAX

#define SCHAR_MIN GRUB_SCHAR_MIN
#define SCHAR_MAX GRUB_SCHAR_MAX
#define SHRT_MIN GRUB_SHRT_MIN
#define SHRT_MAX GRUB_SHRT_MAX
#define INT_MIN GRUB_INT_MIN
#define INT_MAX GRUB_INT_MAX
#define LONG_MIN GRUB_LONG_MIN
#define LONG_MAX GRUB_LONG_MAX

#define CHAR_BIT 8
#define WORD_BIT 32

#endif
