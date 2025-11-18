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

/* RSA public key. */
#define GRUB_MAX_MPI             2
#define GRUB_RSA_PK_MODULUS      0
#define GRUB_RSA_PK_EXPONENT     1

/* Certificate fingerprint. */
#define GRUB_MAX_FINGERPRINT     3
#define GRUB_FINGERPRINT_SHA256  0
#define GRUB_FINGERPRINT_SHA384  1
#define GRUB_FINGERPRINT_SHA512  2

/* Max size of hash data. */
#define GRUB_MAX_HASH_LEN        64

/*
 * One or more x509 certificates. We do limited parsing:
 * extracting only the version, serial, issuer, subject, RSA public key
 * and key size.
 * Also, hold the sha256, sha384, and sha512 fingerprint of the certificate.
 */
struct x509_certificate
{
  struct x509_certificate *next;
  grub_uint8_t version;
  grub_uint8_t *serial;
  grub_size_t serial_len;
  char *issuer;
  grub_size_t issuer_len;
  char *subject;
  grub_size_t subject_len;
  /* We only support RSA public keys. This encodes [modulus, publicExponent]. */
  gcry_mpi_t mpis[GRUB_MAX_MPI];
  grub_int32_t modulus_size;
  grub_uint8_t fingerprint[GRUB_MAX_FINGERPRINT][GRUB_MAX_HASH_LEN];
};
typedef struct x509_certificate grub_x509_cert_t;

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
 * Import a DER-encoded certificate at 'data', of size 'size'. Place the results
 * into 'results', which must be already allocated.
 */
extern grub_err_t
grub_x509_cert_parse (const void *data, grub_size_t size, grub_x509_cert_t *results);

/*
 * Release all the storage associated with the x509 certificate. If the caller
 * dynamically allocated the certificate, it must free it. The caller is also
 * responsible for maintenance of the linked list.
 */
extern void
grub_x509_cert_release (grub_x509_cert_t *cert);

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
