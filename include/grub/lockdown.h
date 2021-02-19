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
 */

#ifndef GRUB_LOCKDOWN_H
#define GRUB_LOCKDOWN_H 1

#include <grub/symbol.h>

#define GRUB_LOCKDOWN_DISABLED       0
#define GRUB_LOCKDOWN_ENABLED        1

#ifdef GRUB_MACHINE_EFI
extern void
EXPORT_FUNC (grub_lockdown) (void);
extern int
EXPORT_FUNC (grub_is_lockdown) (void);
#else
static inline void
grub_lockdown (void)
{
}

static inline int
grub_is_lockdown (void)
{
  return GRUB_LOCKDOWN_DISABLED;
}
#endif
#endif /* ! GRUB_LOCKDOWN_H */
