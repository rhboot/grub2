/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  IBM Corporation.
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
#include <grub/libtasn1.h>

extern asn1_node _gnutls_gnutls_asn;
extern asn1_node _gnutls_pkix_asn;

#define MAX_OID_LEN 32

/*
 * One or more x509 certificates.
 *
 * We do limited parsing: extracting only the serial, CN and RSA public key.
 */
struct x509_certificate
{
  struct x509_certificate *next;

  grub_uint8_t *serial;
  grub_size_t serial_len;

  char *subject;
  grub_size_t subject_len;

  /* We only support RSA public keys. This encodes [modulus, publicExponent] */
  gcry_mpi_t mpis[2];
};

/*
 * A PKCS#7 signedData message.
 *
 * We make no attempt to match intelligently, so we don't save any info about
 * the signer. We also support only 1 signerInfo, so we only store a single
 * MPI for the signature.
 */
struct pkcs7_signedData
{
  const gcry_md_spec_t *hash;
  gcry_mpi_t sig_mpi;
};


/* Do libtasn1 init */
int asn1_init (void);

/*
 * Import a DER-encoded certificate at 'data', of size 'size'.
 *
 * Place the results into 'results', which must be already allocated.
 */
grub_err_t
certificate_import (void *data, grub_size_t size,
		    struct x509_certificate *results);

/*
 * Release all the storage associated with the x509 certificate.
 * If the caller dynamically allocated the certificate, it must free it.
 * The caller is also responsible for maintenance of the linked list.
 */
void certificate_release (struct x509_certificate *cert);

/*
 * Parse a PKCS#7 message, which must be a signedData message.
 *
 * The message must be in 'sigbuf' and of size 'data_size'. The result is
 * placed in 'msg', which must already be allocated.
 */
grub_err_t
parse_pkcs7_signedData (void *sigbuf, grub_size_t data_size,
			struct pkcs7_signedData *msg);

/*
 * Release all the storage associated with the PKCS#7 message.
 * If the caller dynamically allocated the message, it must free it.
 */
void pkcs7_signedData_release (struct pkcs7_signedData *msg);

/*
 * Read a value from an ASN1 node, allocating memory to store it.
 *
 * It will work for anything where the size libtasn1 returns is right:
 *  - Integers
 *  - Octet strings
 *  - DER encoding of other structures
 * It will _not_ work for things where libtasn1 size requires adjustment:
 *  - Strings that require an extra NULL byte at the end
 *  - Bit strings because libtasn1 returns the length in bits, not bytes.
 *
 * If the function returns a non-NULL value, the caller must free it.
 */
void *grub_asn1_allocate_and_read (asn1_node node, const char *name,
				   const char *friendly_name,
				   int *content_size);
