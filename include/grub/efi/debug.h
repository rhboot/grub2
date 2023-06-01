/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022  Free Software Foundation, Inc.
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
/* debug.h - declare variables and functions for EFI debugging support */

#ifndef GRUB_EFI_DEBUG_HEADER
#define GRUB_EFI_DEBUG_HEADER	1

#include <grub/efi/efi.h>
#include <grub/misc.h>


void grub_efi_register_debug_commands (void);

static inline void
grub_efi_print_gdb_info (void)
{
  grub_addr_t text;

  text = grub_efi_section_addr (".text");
  if (!text)
    return;

  grub_printf ("dynamic_load_symbols %p\n", (void *)text);
}

#endif /* ! GRUB_EFI_DEBUG_HEADER */
