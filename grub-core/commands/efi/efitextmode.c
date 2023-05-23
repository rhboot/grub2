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
 *
 *  Set/Get UEFI text output mode resolution.
 */

#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/efi/efi.h>
#include <grub/efi/api.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_efi_set_mode (grub_efi_simple_text_output_interface_t *o,
		   grub_efi_int32_t mode)
{
  grub_efi_status_t status;

  if (mode != o->mode->mode)
    {
      status = o->set_mode (o, mode);
      if (status == GRUB_EFI_SUCCESS)
	;
      else if (status == GRUB_EFI_DEVICE_ERROR)
	return grub_error (GRUB_ERR_BAD_DEVICE,
			   N_("device error: could not set requested mode"));
      else if (status == GRUB_EFI_UNSUPPORTED)
	return grub_error (GRUB_ERR_OUT_OF_RANGE,
			   N_("invalid mode: number not valid"));
      else
	return grub_error (GRUB_ERR_BAD_FIRMWARE,
			   N_("unexpected EFI error number: `%u'"),
			   (unsigned) status);
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_efitextmode (grub_command_t cmd __attribute__ ((unused)),
		      int argc, char **args)
{
  grub_efi_simple_text_output_interface_t *o = grub_efi_system_table->con_out;
  unsigned long mode;
  const char *p = NULL;
  grub_err_t err;
  grub_efi_uintn_t columns, rows;
  grub_efi_int32_t i;

  if (o == NULL)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("no UEFI output console interface"));

  if (o->mode == NULL)
    return grub_error (GRUB_ERR_BUG, N_("no mode struct for UEFI output console"));

  if (argc > 2)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("at most two arguments expected"));

  if (argc == 0)
    {
      grub_printf_ (N_("Available modes for console output device.\n"));

      for (i = 0; i < o->mode->max_mode; i++)
	if (GRUB_EFI_SUCCESS == o->query_mode (o, i, &columns, &rows))
	  grub_printf_ (N_(" [%" PRIuGRUB_EFI_UINT32_T "]  Col %5"
			   PRIuGRUB_EFI_UINTN_T " Row %5" PRIuGRUB_EFI_UINTN_T
			   " %c\n"),
			i, columns, rows, (i == o->mode->mode) ? '*' : ' ');
    }
  else if (argc == 1)
    {
      if (grub_strcmp (args[0], "min") == 0)
	mode = 0;
      else if (grub_strcmp (args[0], "max") == 0)
	mode = o->mode->max_mode - 1;
      else
	{
	  mode = grub_strtoul (args[0], &p, 0);

	  if (*args[0] == '\0' || *p != '\0')
	    return grub_error (GRUB_ERR_BAD_ARGUMENT,
			       N_("non-numeric or invalid mode `%s'"), args[0]);
	}

      if (mode < (unsigned long) o->mode->max_mode)
	{
	  err = grub_efi_set_mode (o, (grub_efi_int32_t) mode);
	  if (err != GRUB_ERR_NONE)
	    return err;
	}
      else
	return grub_error (GRUB_ERR_BAD_ARGUMENT,
			   N_("invalid mode: `%lu' is greater than maximum mode `%lu'"),
			   mode, (unsigned long) o->mode->max_mode);
    }
  else if (argc == 2)
    {
      grub_efi_uintn_t u_columns, u_rows;

      u_columns = (grub_efi_uintn_t) grub_strtoul (args[0], &p, 0);

      if (*args[0] == '\0' || *p != '\0')
	return grub_error (GRUB_ERR_BAD_ARGUMENT,
			   N_("non-numeric or invalid columns number `%s'"), args[0]);

      u_rows = (grub_efi_uintn_t) grub_strtoul (args[1], &p, 0);

      if (*args[1] == '\0' || *p != '\0')
	return grub_error (GRUB_ERR_BAD_ARGUMENT,
			   N_("non-numeric or invalid rows number `%s'"), args[1]);

      for (i = 0; i < o->mode->max_mode; i++)
	if (GRUB_EFI_SUCCESS == o->query_mode (o, i, &columns, &rows))
	  if (u_columns == columns && u_rows == rows)
	    return grub_efi_set_mode (o, (grub_efi_int32_t) i);

      return grub_error (GRUB_ERR_BAD_ARGUMENT,
			 N_("no mode found with requested columns and rows"));
    }

  return GRUB_ERR_NONE;
}

static grub_command_t cmd;
GRUB_MOD_INIT (efitextmode)
{
  cmd = grub_register_command ("efitextmode", grub_cmd_efitextmode,
			       N_("[min | max | <mode_num> | <cols> <rows>]"),
			       N_("Get or set EFI text mode."));
}

GRUB_MOD_FINI (efitextmode)
{
  grub_unregister_command (cmd);
}
