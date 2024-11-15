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

#ifndef GRUB_PROTECTOR_HEADER
#define GRUB_PROTECTOR_HEADER 1

#include <grub/err.h>
#include <grub/types.h>

struct grub_key_protector
{
  struct grub_key_protector *next;
  struct grub_key_protector **prev;

  const char *name;

  grub_err_t (*recover_key) (grub_uint8_t **key, grub_size_t *key_size);
};

grub_err_t
grub_key_protector_register (struct grub_key_protector *protector);

grub_err_t
grub_key_protector_unregister (struct grub_key_protector *protector);

grub_err_t
grub_key_protector_recover_key (const char *protector,
				grub_uint8_t **key,
				grub_size_t *key_size);

#endif /* ! GRUB_PROTECTOR_HEADER */
