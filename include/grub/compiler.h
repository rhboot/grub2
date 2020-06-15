/* compiler.h - macros for various compiler features */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2005,2006,2007,2008,2009,2010,2014  Free Software Foundation, Inc.
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

#ifndef GRUB_COMPILER_HEADER
#define GRUB_COMPILER_HEADER	1

/* GCC version checking borrowed from glibc. */
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#  define GNUC_PREREQ(maj,min) \
	((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#  define GNUC_PREREQ(maj,min) 0
#endif

/* Does this compiler support compile-time error attributes? */
#if GNUC_PREREQ(4,3)
#  define ATTRIBUTE_ERROR(msg) \
	__attribute__ ((__error__ (msg)))
#else
#  define ATTRIBUTE_ERROR(msg) __attribute__ ((noreturn))
#endif

#if GNUC_PREREQ(4,4)
#  define GNU_PRINTF gnu_printf
#else
#  define GNU_PRINTF printf
#endif

#if GNUC_PREREQ(3,4)
#  define WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#  define WARN_UNUSED_RESULT
#endif

#if defined(__clang__) && defined(__clang_major__) && defined(__clang_minor__)
#  define CLANG_PREREQ(maj,min) \
          ((__clang_major__ > (maj)) || \
	   (__clang_major__ == (maj) && __clang_minor__ >= (min)))
#else
#  define CLANG_PREREQ(maj,min) 0
#endif

#include "types.h"

union component64
{
  grub_uint64_t full;
  struct
  {
#ifdef GRUB_CPU_WORDS_BIGENDIAN
    grub_uint32_t high;
    grub_uint32_t low;
#else
    grub_uint32_t low;
    grub_uint32_t high;
#endif
  };
};

#if defined (__powerpc__)
grub_uint64_t EXPORT_FUNC (__lshrdi3) (grub_uint64_t u, int b);
grub_uint64_t EXPORT_FUNC (__ashrdi3) (grub_uint64_t u, int b);
grub_uint64_t EXPORT_FUNC (__ashldi3) (grub_uint64_t u, int b);
int EXPORT_FUNC(__ucmpdi2) (grub_uint64_t a, grub_uint64_t b);
void EXPORT_FUNC (_restgpr_14_x) (void);
void EXPORT_FUNC (_restgpr_15_x) (void);
void EXPORT_FUNC (_restgpr_16_x) (void);
void EXPORT_FUNC (_restgpr_17_x) (void);
void EXPORT_FUNC (_restgpr_18_x) (void);
void EXPORT_FUNC (_restgpr_19_x) (void);
void EXPORT_FUNC (_restgpr_20_x) (void);
void EXPORT_FUNC (_restgpr_21_x) (void);
void EXPORT_FUNC (_restgpr_22_x) (void);
void EXPORT_FUNC (_restgpr_23_x) (void);
void EXPORT_FUNC (_restgpr_24_x) (void);
void EXPORT_FUNC (_restgpr_25_x) (void);
void EXPORT_FUNC (_restgpr_26_x) (void);
void EXPORT_FUNC (_restgpr_27_x) (void);
void EXPORT_FUNC (_restgpr_28_x) (void);
void EXPORT_FUNC (_restgpr_29_x) (void);
void EXPORT_FUNC (_restgpr_30_x) (void);
void EXPORT_FUNC (_restgpr_31_x) (void);
void EXPORT_FUNC (_savegpr_14) (void);
void EXPORT_FUNC (_savegpr_15) (void);
void EXPORT_FUNC (_savegpr_16) (void);
void EXPORT_FUNC (_savegpr_17) (void);
void EXPORT_FUNC (_savegpr_18) (void);
void EXPORT_FUNC (_savegpr_19) (void);
void EXPORT_FUNC (_savegpr_20) (void);
void EXPORT_FUNC (_savegpr_21) (void);
void EXPORT_FUNC (_savegpr_22) (void);
void EXPORT_FUNC (_savegpr_23) (void);
void EXPORT_FUNC (_savegpr_24) (void);
void EXPORT_FUNC (_savegpr_25) (void);
void EXPORT_FUNC (_savegpr_26) (void);
void EXPORT_FUNC (_savegpr_27) (void);
void EXPORT_FUNC (_savegpr_28) (void);
void EXPORT_FUNC (_savegpr_29) (void);
void EXPORT_FUNC (_savegpr_30) (void);
void EXPORT_FUNC (_savegpr_31) (void);

#endif

#endif /* ! GRUB_COMPILER_HEADER */
