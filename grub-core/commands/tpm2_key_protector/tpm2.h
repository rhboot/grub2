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

#ifndef GRUB_TPM2_TPM2_HEADER
#define GRUB_TPM2_TPM2_HEADER 1

#include <tss2_types.h>
#include <tss2_structs.h>
#include <tpm2_cmd.h>

/* Well-Known Windows SRK handle */
#define TPM2_SRK_HANDLE 0x81000001

struct tpm2_sealed_key {
  TPM2B_PUBLIC_t  public;
  TPM2B_PRIVATE_t private;
};
typedef struct tpm2_sealed_key tpm2_sealed_key_t;

#endif /* ! GRUB_TPM2_TPM2_HEADER */
