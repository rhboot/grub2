/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024 IBM Corporation
 *  Copyright (C) 2024 Free Software Foundation, Inc.
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

#include <grub/types.h>
#include <grub/tpm.h>
#include <grub/ieee1275/tpm.h>
#include <grub/mm.h>
#include <grub/misc.h>

grub_ieee1275_ihandle_t grub_ieee1275_tpm_ihandle = GRUB_IEEE1275_IHANDLE_INVALID;

grub_err_t
grub_ieee1275_tpm_init (void)
{
  static bool init_tried = false;
  grub_ieee1275_phandle_t vtpm;
  char buffer[20];

  if (init_tried == false)
    {
      init_tried = true;

      if (grub_ieee1275_open ("/vdevice/vtpm", &grub_ieee1275_tpm_ihandle) < 0 ||
	  grub_ieee1275_finddevice ("/vdevice/vtpm", &vtpm) ||
	  grub_ieee1275_get_property (vtpm, "compatible", buffer, sizeof (buffer), NULL) ||
	  grub_strcmp (buffer, "IBM,vtpm20"))
	{
	  if (grub_ieee1275_tpm_ihandle != GRUB_IEEE1275_IHANDLE_INVALID)
	    grub_ieee1275_close (grub_ieee1275_tpm_ihandle);

	  grub_ieee1275_tpm_ihandle = GRUB_IEEE1275_IHANDLE_INVALID;
	}
    }

  if (grub_ieee1275_tpm_ihandle == GRUB_IEEE1275_IHANDLE_INVALID)
    return GRUB_ERR_UNKNOWN_DEVICE;

  return GRUB_ERR_NONE;
}
