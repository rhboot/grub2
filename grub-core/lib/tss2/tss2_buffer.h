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

#ifndef GRUB_TPM2_BUFFER_HEADER
#define GRUB_TPM2_BUFFER_HEADER 1

#include <grub/types.h>

#define GRUB_TPM2_BUFFER_CAPACITY 4096

struct grub_tpm2_buffer
{
  grub_uint8_t data[GRUB_TPM2_BUFFER_CAPACITY];
  grub_size_t size;
  grub_size_t offset;
  grub_size_t cap;
  bool error;
};
typedef struct grub_tpm2_buffer *grub_tpm2_buffer_t;

extern void
grub_tpm2_buffer_init (grub_tpm2_buffer_t buffer);

extern void
grub_tpm2_buffer_pack (grub_tpm2_buffer_t buffer, const void *data, grub_size_t size);

extern void
grub_tpm2_buffer_pack_u8 (grub_tpm2_buffer_t buffer, grub_uint8_t value);

extern void
grub_tpm2_buffer_pack_u16 (grub_tpm2_buffer_t buffer, grub_uint16_t value);

extern void
grub_tpm2_buffer_pack_u32 (grub_tpm2_buffer_t buffer, grub_uint32_t value);

extern void
grub_tpm2_buffer_unpack (grub_tpm2_buffer_t buffer, void *data, grub_size_t size);

extern void
grub_tpm2_buffer_unpack_u8 (grub_tpm2_buffer_t buffer, grub_uint8_t *value);

extern void
grub_tpm2_buffer_unpack_u16 (grub_tpm2_buffer_t buffer, grub_uint16_t *value);

extern void
grub_tpm2_buffer_unpack_u32 (grub_tpm2_buffer_t buffer, grub_uint32_t *value);

#endif /* ! GRUB_TPM2_BUFFER_HEADER */
