/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022  Free Software Foundation, Inc.
 *  Copyright (C) 2022  IBM Corporation
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
 *  IBM vTPM support code.
 */

#include <grub/err.h>
#include <grub/types.h>
#include <grub/tpm.h>
#include <grub/ieee1275/ieee1275.h>
#include <grub/ieee1275/tpm.h>
#include <grub/mm.h>
#include <grub/misc.h>

static grub_err_t
tpm2_log_event (unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		const char *description)
{
  static int error_displayed = 0;
  grub_err_t err;

  err = grub_ieee1275_ibmvtpm_2hash_ext_log (pcr, EV_IPL,
					     description, grub_strlen(description) + 1,
					     buf, size);
  if (err != GRUB_ERR_NONE && !error_displayed)
    {
      error_displayed++;
      return err;
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm_measure (unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		  const char *description)
{
  grub_dprintf ("tpm", "log_event, pcr = %d, size = 0x%" PRIxGRUB_SIZE ", %s\n",
		pcr, size, description);

  if (grub_ieee1275_tpm_ihandle != GRUB_IEEE1275_IHANDLE_INVALID)
    return tpm2_log_event (buf, size, pcr, description);

  return GRUB_ERR_NONE;
}

int
grub_tpm_present (void)
{
  /*
   * Call tpm_init() "late" rather than from GRUB_MOD_INIT() so that device nodes
   * can be found.
   */
  return grub_ieee1275_tpm_init() == GRUB_ERR_NONE;
}
