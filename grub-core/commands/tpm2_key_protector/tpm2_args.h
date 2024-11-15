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

#ifndef GRUB_TPM2_INTERNAL_ARGS_HEADER
#define GRUB_TPM2_INTERNAL_ARGS_HEADER 1

#include <grub/err.h>

#include "tpm2.h"

struct grub_srk_type
{
  TPMI_ALG_PUBLIC_t type;
  union {
    TPM_KEY_BITS_t rsa_bits;
    TPM_ECC_CURVE_t ecc_curve;
  } detail;
};
typedef struct grub_srk_type grub_srk_type_t;

extern grub_err_t
grub_tpm2_protector_parse_pcrs (char *value, grub_uint8_t *pcrs, grub_uint8_t *pcr_count);

extern grub_err_t
grub_tpm2_protector_parse_asymmetric (const char *value, grub_srk_type_t *srk_type);

extern grub_err_t
grub_tpm2_protector_parse_bank (const char *value, TPM_ALG_ID_t *bank);

extern grub_err_t
grub_tpm2_protector_parse_tpm_handle (const char *value, TPM_HANDLE_t *handle);

#endif /* ! GRUB_TPM2_INTERNAL_ARGS_HEADER */
