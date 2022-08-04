/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  Free Software Foundation, Inc.
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
 *
 *  Arithmetic operations that protect against overflow.
 */

#ifndef GRUB_SAFEMATH_H
#define GRUB_SAFEMATH_H 1

#include <grub/compiler.h>

/* These appear in gcc 5.1 and clang 8.0. */
#if GNUC_PREREQ(5, 1) || CLANG_PREREQ(8, 0)

#define grub_add(a, b, res)	__builtin_add_overflow(a, b, res)
#define grub_sub(a, b, res)	__builtin_sub_overflow(a, b, res)
#define grub_mul(a, b, res)	__builtin_mul_overflow(a, b, res)

#define grub_cast(a, res)	grub_add ((a), 0, (res))

#else
#error gcc 5.1 or newer or clang 8.0 or newer is required
#endif

#endif /* GRUB_SAFEMATH_H */
