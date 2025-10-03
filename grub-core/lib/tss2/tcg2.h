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

#ifndef GRUB_TPM2_TCG2_HEADER
#define GRUB_TPM2_TCG2_HEADER 1

#include <grub/err.h>
#include <grub/types.h>

#define GRUB_EV_SEPARATOR 0x04

extern grub_err_t
grub_tcg2_get_max_output_size (grub_size_t *size);

extern grub_err_t
grub_tcg2_submit_command (grub_size_t input_size,
			  grub_uint8_t *input,
			  grub_size_t output_size,
			  grub_uint8_t *output);

extern grub_err_t
grub_tcg2_cap_pcr (grub_uint8_t pcr);

#endif /* ! GRUB_TPM2_TCG2_HEADER */
