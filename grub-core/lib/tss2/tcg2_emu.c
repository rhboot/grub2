/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024 SUSE LLC
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

#include <grub/mm.h>
#include <grub/emu/misc.h>

#include <tss2_buffer.h>
#include <tss2_structs.h>
#include <tpm2_cmd.h>
#include <tcg2.h>

grub_err_t
grub_tcg2_get_max_output_size (grub_size_t *size)
{
  if (size == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  *size = GRUB_TPM2_BUFFER_CAPACITY;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tcg2_submit_command (grub_size_t input_size, grub_uint8_t *input,
			  grub_size_t output_size, grub_uint8_t *output)
{
  if (grub_util_tpm_write (input, input_size) != input_size)
    return GRUB_ERR_BAD_DEVICE;

  if (grub_util_tpm_read (output, output_size) < sizeof (TPM_RESPONSE_HEADER_t))
    return GRUB_ERR_BAD_DEVICE;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tcg2_cap_pcr (grub_uint8_t pcr)
{
  TPMS_AUTH_COMMAND_t authCmd = {
    .sessionHandle = TPM_RS_PW,
  };
  TPM2B_EVENT_t data = {
    .size = 4,
  };
  TPM_RC_t rc;

  /* Submit an EV_SEPARATOR event, i.e. an event with 4 zero-bytes */
  rc = grub_tpm2_pcr_event (pcr, &authCmd, &data, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("cannot cap PCR %u"), pcr);

  return GRUB_ERR_NONE;
}
