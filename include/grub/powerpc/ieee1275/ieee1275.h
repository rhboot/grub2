/* ieee1275.h - Access the Open Firmware client interface.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2007  Free Software Foundation, Inc.
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

#ifndef GRUB_IEEE1275_MACHINE_HEADER
#define GRUB_IEEE1275_MACHINE_HEADER	1

#include <grub/types.h>

#define GRUB_IEEE1275_CELL_SIZEOF 4
typedef grub_uint32_t grub_ieee1275_cell_t;

#define PRIxGRUB_IEEE1275_CELL_T	PRIxGRUB_UINT32_T
#define PRIuGRUB_IEEE1275_CELL_T	PRIuGRUB_UINT32_T

#ifdef __powerpc__
/* The maximum object size interface name for a PKS object. */
#define GRUB_PKS_MAX_OBJ_INTERFACE    "pks-max-object-size"

/* PKS read object and read sbvar interface name. */
#define GRUB_PKS_READ_OBJ_INTERFACE   "pks-read-object"
#define GRUB_PKS_READ_SBVAR_INTERFACE "pks-read-sbvar"

/* PKS read object label for secure boot version. */
#define GRUB_SB_VERSION_KEY_NAME      "SB_VERSION"
#define GRUB_SB_VERSION_KEY_LEN       (sizeof (GRUB_SB_VERSION_KEY_NAME) - 1)

/* PKS consumer type for firmware. */
#define GRUB_PKS_CONSUMER_FW          ((grub_uint32_t) 1)

/* PKS read secure boot variable request type for db and dbx. */
#define GRUB_PKS_SBVAR_DB             ((grub_uint32_t) 1)
#define GRUB_PKS_SBVAR_DBX            ((grub_uint32_t) 2)

extern grub_int32_t
grub_ieee1275_test (const char *interface_name);

extern grub_int32_t
grub_ieee1275_pks_max_object_size (grub_uint32_t *result);

extern grub_int32_t
grub_ieee1275_pks_read_object (const grub_uint32_t consumer, const char *label,
                               const grub_uint32_t label_len, const grub_uint32_t buffer_len,
                               grub_uint8_t *buffer, grub_uint32_t *data_len,
                               grub_uint32_t *policies);

extern grub_int32_t
grub_ieee1275_pks_read_sbvar (const grub_uint32_t sbvar_flags, const grub_uint32_t sbvar_type,
                              const grub_uint32_t buffer_len, grub_uint8_t *buffer,
                              grub_size_t *data_len);
#endif /* __powerpc__ */
#endif /* ! GRUB_IEEE1275_MACHINE_HEADER */
