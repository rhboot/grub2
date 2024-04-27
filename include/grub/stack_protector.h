/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2021  Free Software Foundation, Inc.
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

#ifndef GRUB_STACK_PROTECTOR_H
#define GRUB_STACK_PROTECTOR_H	1

#include <grub/symbol.h>
#include <grub/types.h>

#ifdef GRUB_STACK_PROTECTOR
extern grub_addr_t EXPORT_VAR (__stack_chk_guard);
extern void __attribute__ ((noreturn)) EXPORT_FUNC (__stack_chk_fail) (void);
#if defined(_WIN64) && !defined(__CYGWIN__) /* MinGW, Windows 64-bit target. */
static grub_addr_t __attribute__ ((weakref("__stack_chk_guard"))) EXPORT_VAR (_stack_chk_guard);
static void __attribute__ ((noreturn, weakref("__stack_chk_fail"))) EXPORT_FUNC (_stack_chk_fail) (void);
#endif

extern grub_addr_t grub_stack_protector_init (void);

static inline __attribute__((__always_inline__))
void grub_update_stack_guard (void)
{
  grub_addr_t guard;

  guard = grub_stack_protector_init ();
  if (guard)
     __stack_chk_guard = guard;
}
#endif

#endif /* GRUB_STACK_PROTECTOR_H */
