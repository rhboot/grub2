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

#include <grub/crypto.h>
#include <libtasn1.h>

extern asn1_node grub_gnutls_gnutls_asn;
extern asn1_node grub_gnutls_pkix_asn;

#define GRUB_MAX_OID_LEN         32

/* A PKCS#7 signed data signer info. */
struct pkcs7_signer
{
  const gcry_md_spec_t *hash;
  gcry_mpi_t sig_mpi;
};
typedef struct pkcs7_signer grub_pkcs7_signer_t;

/*
 * A PKCS#7 signed data message. We make no attempt to match intelligently, so
 * we don't save any info about the signer.
 */
struct pkcs7_data
{
  grub_int32_t signer_count;
  grub_pkcs7_signer_t *signers;
};
typedef struct pkcs7_data grub_pkcs7_data_t;

/*
 * Parse a PKCS#7 message, which must be a signed data message. The message must
 * be in 'sigbuf' and of size 'data_size'. The result is placed in 'msg', which
 * must already be allocated.
 */
extern grub_err_t
grub_pkcs7_data_parse (const void *sigbuf, grub_size_t data_size, grub_pkcs7_data_t *msg);

/*
 * Release all the storage associated with the PKCS#7 message. If the caller
 * dynamically allocated the message, it must free it.
 */
extern void
grub_pkcs7_data_release (grub_pkcs7_data_t *msg);

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
