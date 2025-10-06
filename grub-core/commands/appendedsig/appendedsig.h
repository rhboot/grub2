/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2022, 2025 IBM Corporation
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

#include <libtasn1.h>

extern asn1_node grub_gnutls_gnutls_asn;
extern asn1_node grub_gnutls_pkix_asn;

/* Do libtasn1 init. */
extern int
grub_asn1_init (void);

/*
 * Read a value from an ASN1 node, allocating memory to store it. It will work
 * for anything where the size libtasn1 returns is right:
 *  - Integers
 *  - Octet strings
 *  - DER encoding of other structures
 *
 * It will _not_ work for things where libtasn1 size requires adjustment:
 *  - Strings that require an extra null byte at the end
 *  - Bit strings because libtasn1 returns the length in bits, not bytes.
 *
 * If the function returns a non-NULL value, the caller must free it.
 */
extern void *
grub_asn1_allocate_and_read (asn1_node node, const char *name, const char *friendly_name,
                             grub_int32_t *content_size);
