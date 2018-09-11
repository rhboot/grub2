/* version.c - Command to print the grub version and build info. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007,2008  Free Software Foundation, Inc.
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

#include <grub/dl.h>
#include <grub/term.h>
#include <grub/time.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_version (grub_command_t cmd UNUSED, int argc, char **args UNUSED)
{
  if (argc != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("no arguments expected"));

  grub_printf (_("GNU GRUB  version %s\n"), PACKAGE_VERSION);
  grub_printf (_("Platform %s-%s\n"), GRUB_TARGET_CPU, GRUB_PLATFORM);
  if (grub_strlen(GRUB_RPM_VERSION) != 0)
    grub_printf (_("RPM package version %s\n"), GRUB_RPM_VERSION);
  grub_printf (_("Compiler version %s\n"), __VERSION__);

  return 0;
}

static grub_command_t cmd;

GRUB_MOD_INIT(version)
{
  cmd = grub_register_command ("version", grub_cmd_version, NULL,
			       N_("Print version and build information."));
}

GRUB_MOD_FINI(version)
{
  grub_unregister_command (cmd);
}
