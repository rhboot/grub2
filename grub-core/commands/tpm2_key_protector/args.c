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

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>

#include "tpm2_args.h"

grub_err_t
grub_tpm2_protector_parse_pcrs (char *value, grub_uint8_t *pcrs,
				grub_uint8_t *pcr_count)
{
  char *current_pcr = value;
  char *next_pcr;
  const char *pcr_end;
  grub_uint64_t pcr;
  grub_uint8_t i;

  if (grub_strlen (value) == 0)
    return GRUB_ERR_BAD_ARGUMENT;

  *pcr_count = 0;
  for (i = 0; i < TPM_MAX_PCRS; i++)
    {
      next_pcr = grub_strchr (current_pcr, ',');
      if (next_pcr == current_pcr)
	return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("empty entry in PCR list"));
      if (next_pcr != NULL)
	*next_pcr = '\0';

      pcr = grub_strtoul (current_pcr, &pcr_end, 10);
      if (*current_pcr == '\0' || *pcr_end != '\0')
	return grub_error (GRUB_ERR_BAD_NUMBER, N_("entry '%s' in PCR list is not a number"), current_pcr);

      if (pcr > TPM_MAX_PCRS - 1)
	return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("entry %llu in PCR list is too large to be a PCR number, PCR numbers range from 0 to %u"), (unsigned long long)pcr, TPM_MAX_PCRS - 1);

      pcrs[i] = (grub_uint8_t) pcr;
      ++(*pcr_count);

      if (next_pcr == NULL)
	break;

      current_pcr = next_pcr + 1;
      if (*current_pcr == '\0')
	return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("trailing comma at the end of PCR list"));
    }

  if (i == TPM_MAX_PCRS)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("too many PCRs in PCR list, the maximum number of PCRs is %u"), TPM_MAX_PCRS);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2_protector_parse_asymmetric (const char *value,
				      grub_srk_type_t *srk_type)
{
  if (grub_strcasecmp (value, "ECC") == 0 ||
      grub_strcasecmp (value, "ECC_NIST_P256") == 0)
    {
      srk_type->type = TPM_ALG_ECC;
      srk_type->detail.ecc_curve = TPM_ECC_NIST_P256;
    }
  else if (grub_strcasecmp (value, "RSA") == 0 ||
	   grub_strcasecmp (value, "RSA2048") == 0)
    {
      srk_type->type = TPM_ALG_RSA;
      srk_type->detail.rsa_bits = 2048;
    }
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("value '%s' is not a valid asymmetric key type"), value);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2_protector_parse_bank (const char *value, TPM_ALG_ID_t *bank)
{
  if (grub_strcasecmp (value, "SHA1") == 0)
    *bank = TPM_ALG_SHA1;
  else if (grub_strcasecmp (value, "SHA256") == 0)
    *bank = TPM_ALG_SHA256;
  else if (grub_strcasecmp (value, "SHA384") == 0)
    *bank = TPM_ALG_SHA384;
  else if (grub_strcasecmp (value, "SHA512") == 0)
    *bank = TPM_ALG_SHA512;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("value '%s' is not a valid PCR bank"), value);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2_protector_parse_tpm_handle (const char *value, TPM_HANDLE_t *handle)
{
  grub_uint64_t num;
  const char *str_end;

  num = grub_strtoul (value, &str_end, 0);
  if (*value == '\0' || *str_end != '\0')
    return grub_error (GRUB_ERR_BAD_NUMBER, N_("TPM handle value '%s' is not a number"), value);

  if (num > GRUB_UINT_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("value %llu is too large to be a TPM handle, TPM handles are unsigned 32-bit integers"), (unsigned long long)num);

  *handle = (TPM_HANDLE_t) num;

  return GRUB_ERR_NONE;
}
