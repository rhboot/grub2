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
/* debug.c - aides for debugging the EFI application */

#include <grub/efi/debug.h>
#include <grub/command.h>
#include <grub/i18n.h>

static grub_err_t
grub_cmd_gdbinfo (struct grub_command *cmd __attribute__ ((unused)),
		  int argc __attribute__ ((unused)),
		  char **args __attribute__ ((unused)))
{
  grub_efi_print_gdb_info ();
  return 0;
}

void
grub_efi_register_debug_commands (void)
{
  grub_register_command ("gdbinfo", grub_cmd_gdbinfo, 0,
			 N_("Print infomation useful for GDB debugging"));
}
