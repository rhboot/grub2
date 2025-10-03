/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Microsoft Corporation
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

#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/tpm.h>
#include <grub/mm.h>

#include <tss2_types.h>
#include <tcg2.h>

static grub_err_t
tcg2_get_caps (grub_efi_tpm2_protocol_t *protocol, int *tpm2, grub_size_t *max_output_size)
{
  grub_efi_status_t status;
  static bool has_caps = 0;
  static EFI_TCG2_BOOT_SERVICE_CAPABILITY caps =
  {
    .Size = (grub_uint8_t) sizeof (caps)
  };

  if (has_caps)
    goto exit;

  status = protocol->get_capability (protocol, &caps);
  if (status != GRUB_EFI_SUCCESS || !caps.TPMPresentFlag)
    return GRUB_ERR_FILE_NOT_FOUND;

  has_caps = 1;

 exit:
  if (tpm2 != NULL)
    *tpm2 = caps.TPMPresentFlag;
  if (max_output_size != NULL)
    *max_output_size = caps.MaxResponseSize;

  return GRUB_ERR_NONE;
}

static grub_err_t
tcg2_get_protocol (grub_efi_tpm2_protocol_t **protocol)
{
  static grub_guid_t tpm2_guid = EFI_TPM2_GUID;
  static grub_efi_tpm2_protocol_t *tpm2_protocol = NULL;
  int tpm2;
  grub_efi_handle_t *handles;
  grub_efi_uintn_t num_handles;
  grub_efi_handle_t tpm2_handle;
  grub_err_t err = GRUB_ERR_FILE_NOT_FOUND;

  if (tpm2_protocol != NULL)
    {
      *protocol = tpm2_protocol;
      return GRUB_ERR_NONE;
    }

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &tpm2_guid, NULL,
				    &num_handles);
  if (handles == NULL || num_handles == 0)
    return err;

  tpm2_handle = handles[0];

  tpm2_protocol = grub_efi_open_protocol (tpm2_handle, &tpm2_guid,
					  GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (tpm2_protocol == NULL)
    goto exit;

  err = tcg2_get_caps (tpm2_protocol, &tpm2, NULL);
  if (err != GRUB_ERR_NONE || tpm2 == 0)
    goto exit;

  *protocol = tpm2_protocol;
  err = GRUB_ERR_NONE;

 exit:
  grub_free (handles);
  return err;
}

grub_err_t
grub_tcg2_get_max_output_size (grub_size_t *size)
{
  grub_err_t err;
  grub_size_t max;
  grub_efi_tpm2_protocol_t *protocol;

  if (size == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  err = tcg2_get_protocol (&protocol);
  if (err != GRUB_ERR_NONE)
    return err;

  err = tcg2_get_caps (protocol, NULL, &max);
  if (err != GRUB_ERR_NONE)
    return err;

  *size = max;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tcg2_submit_command (grub_size_t input_size,
			  grub_uint8_t *input,
			  grub_size_t output_size,
			  grub_uint8_t *output)
{
  grub_err_t err;
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *protocol;

  if (input_size == 0  || input == NULL ||
      output_size == 0 || output == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  err = tcg2_get_protocol (&protocol);
  if (err != GRUB_ERR_NONE)
    return err;

  status = protocol->submit_command (protocol, input_size, input,
				     output_size, output);
  if (status != GRUB_EFI_SUCCESS)
    return GRUB_ERR_INVALID_COMMAND;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tcg2_cap_pcr (grub_uint8_t pcr)
{
  grub_err_t err;
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *protocol;
  EFI_TCG2_EVENT *event;
  grub_uint8_t separator[4] = {0};

  if (pcr >= TPM_MAX_PCRS)
    return GRUB_ERR_BAD_ARGUMENT;

  err = tcg2_get_protocol (&protocol);
  if (err != GRUB_ERR_NONE)
    return err;

  event = grub_zalloc (sizeof (EFI_TCG2_EVENT) + sizeof (separator));
  if (event == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("cannot allocate TPM event buffer"));

  event->Header.HeaderSize = sizeof (EFI_TCG2_EVENT_HEADER);
  event->Header.HeaderVersion = 1;
  event->Header.PCRIndex = pcr;
  event->Header.EventType = GRUB_EV_SEPARATOR;
  event->Size = sizeof (*event) - sizeof (event->Event) + sizeof (separator);
  grub_memcpy (event->Event, separator, sizeof (separator));

  status = protocol->hash_log_extend_event (protocol, 0,
					    (grub_addr_t) separator,
					    sizeof (separator), event);
  grub_free (event);

  if (status != GRUB_EFI_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("cannot cap PCR %u"), pcr);

  return GRUB_ERR_NONE;
}
