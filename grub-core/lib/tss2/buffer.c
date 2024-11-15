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

#include <grub/misc.h>

#include <tss2_buffer.h>

void grub_tpm2_buffer_init (grub_tpm2_buffer_t buffer)
{
  grub_memset (buffer->data, 0, sizeof (buffer->data));
  buffer->size = 0;
  buffer->offset = 0;
  buffer->cap = sizeof (buffer->data);
  buffer->error = 0;
}

void
grub_tpm2_buffer_pack (grub_tpm2_buffer_t buffer, const void *data, grub_size_t size)
{
  grub_uint32_t r = buffer->cap - buffer->size;

  if (buffer->error)
    return;

  if (size > r)
    {
      buffer->error = 1;
      return;
    }

  grub_memcpy (&buffer->data[buffer->size], (void *) data, size);
  buffer->size += size;
}

void
grub_tpm2_buffer_pack_u8 (grub_tpm2_buffer_t buffer, grub_uint8_t value)
{
  grub_tpm2_buffer_pack (buffer, (const void *) &value, sizeof (value));
}

void
grub_tpm2_buffer_pack_u16 (grub_tpm2_buffer_t buffer, grub_uint16_t value)
{
  grub_uint16_t tmp = grub_cpu_to_be16 (value);

  grub_tpm2_buffer_pack (buffer, (const void *) &tmp, sizeof (tmp));
}

void
grub_tpm2_buffer_pack_u32 (grub_tpm2_buffer_t buffer, grub_uint32_t value)
{
  grub_uint32_t tmp = grub_cpu_to_be32 (value);

  grub_tpm2_buffer_pack (buffer, (const void *) &tmp, sizeof (tmp));
}

void
grub_tpm2_buffer_unpack (grub_tpm2_buffer_t buffer, void *data, grub_size_t size)
{
  grub_uint32_t r = buffer->size - buffer->offset;

  if (buffer->error)
    return;

  if (size > r)
    {
      buffer->error = 1;
      return;
    }

  grub_memcpy (data, &buffer->data[buffer->offset], size);
  buffer->offset += size;
}

void
grub_tpm2_buffer_unpack_u8 (grub_tpm2_buffer_t buffer, grub_uint8_t *value)
{
  grub_uint32_t r = buffer->size - buffer->offset;

  if (buffer->error)
    return;

  if (sizeof (*value) > r)
    {
      buffer->error = 1;
      return;
    }

  grub_memcpy (value, &buffer->data[buffer->offset], sizeof (*value));
  buffer->offset += sizeof (*value);
}

void
grub_tpm2_buffer_unpack_u16 (grub_tpm2_buffer_t buffer, grub_uint16_t *value)
{
  grub_uint16_t tmp;
  grub_uint32_t r = buffer->size - buffer->offset;

  if (buffer->error)
    return;

  if (sizeof (tmp) > r)
    {
      buffer->error = 1;
      return;
    }

  grub_memcpy (&tmp, &buffer->data[buffer->offset], sizeof (tmp));
  buffer->offset += sizeof (tmp);
  *value = grub_be_to_cpu16 (tmp);
}

void
grub_tpm2_buffer_unpack_u32 (grub_tpm2_buffer_t buffer, grub_uint32_t *value)
{
  grub_uint32_t tmp;
  grub_uint32_t r = buffer->size - buffer->offset;

  if (buffer->error)
    return;

  if (sizeof (tmp) > r)
    {
      buffer->error = 1;
      return;
    }

  grub_memcpy (&tmp, &buffer->data[buffer->offset], sizeof (tmp));
  buffer->offset += sizeof (tmp);
  *value = grub_be_to_cpu32 (tmp);
}
