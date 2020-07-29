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

#include "appendedsig.h"
#include <grub/misc.h>
#include <grub/crypto.h>
#include <grub/gcrypt/gcrypt.h>


static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

/*
 * RFC 5652 s 5.1
 */
const char *signedData_oid = "1.2.840.113549.1.7.2";

/*
 * RFC 4055 s 2.1
 */
const char *sha256_oid = "2.16.840.1.101.3.4.2.1";
const char *sha512_oid = "2.16.840.1.101.3.4.2.3";

static grub_err_t
process_content (grub_uint8_t * content, int size,
		 struct pkcs7_signedData *msg)
{
  int res;
  asn1_node signed_part;
  grub_err_t err = GRUB_ERR_NONE;
  char algo_oid[MAX_OID_LEN];
  int algo_oid_size = sizeof (algo_oid);
  int algo_count;
  char version;
  int version_size = sizeof (version);
  grub_uint8_t *result_buf;
  int result_size = 0;
  int crls_size = 0;
  gcry_error_t gcry_err;

  res = asn1_create_element (_gnutls_pkix_asn, "PKIX1.pkcs-7-SignedData",
			     &signed_part);
  if (res != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Could not create ASN.1 structure for PKCS#7 signed part.");
    }

  res = asn1_der_decoding2 (&signed_part, content, &size,
			    ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (res != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Error reading PKCS#7 signed data: %s", asn1_error);
      goto cleanup_signed_part;
    }

  /* SignedData ::= SEQUENCE {
   *     version CMSVersion,
   *     digestAlgorithms DigestAlgorithmIdentifiers,
   *     encapContentInfo EncapsulatedContentInfo,
   *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
   *     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
   *     signerInfos SignerInfos }
   */

  /* version per the algo in 5.1, must be 1 */
  res = asn1_read_value (signed_part, "version", &version, &version_size);
  if (res != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Error reading signedData version: %s",
		    asn1_strerror (res));
      goto cleanup_signed_part;
    }

  if (version != 1)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Unexpected signature version v%d, only v1 supported",
		    version);
      goto cleanup_signed_part;
    }

  /*
   * digestAlgorithms DigestAlgorithmIdentifiers
   *
   * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
   * DigestAlgorithmIdentifer is an X.509 AlgorithmIdentifier (10.1.1)
   * 
   * RFC 4055 s 2.1:
   * sha256Identifier  AlgorithmIdentifier  ::=  { id-sha256, NULL }
   * sha512Identifier  AlgorithmIdentifier  ::=  { id-sha512, NULL }
   *
   * We only support 1 element in the set, and we do not check parameters atm.
   */
  res =
    asn1_number_of_elements (signed_part, "digestAlgorithms", &algo_count);
  if (res != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Error counting number of digest algorithms: %s",
		    asn1_strerror (res));
      goto cleanup_signed_part;
    }

  if (algo_count != 1)
    {
      err =
	grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		    "Only 1 digest algorithm is supported");
      goto cleanup_signed_part;
    }

  res =
    asn1_read_value (signed_part, "digestAlgorithms.?1.algorithm", algo_oid,
		     &algo_oid_size);
  if (res != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Error reading digest algorithm: %s",
		    asn1_strerror (res));
      goto cleanup_signed_part;
    }

  if (grub_strncmp (sha512_oid, algo_oid, algo_oid_size) == 0)
    {
      msg->hash = grub_crypto_lookup_md_by_name ("sha512");
    }
  else if (grub_strncmp (sha256_oid, algo_oid, algo_oid_size) == 0)
    {
      msg->hash = grub_crypto_lookup_md_by_name ("sha256");
    }
  else
    {
      err =
	grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		    "Only SHA-256 and SHA-512 hashes are supported, found OID %s",
		    algo_oid);
      goto cleanup_signed_part;
    }

  if (!msg->hash)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Hash algorithm for OID %s not loaded", algo_oid);
      goto cleanup_signed_part;
    }

  /*
   * We ignore the certificates, but we don't permit CRLs.
   * A CRL entry might be revoking the certificate we're using, and we have
   * no way of dealing with that at the moment.
   */
  res = asn1_read_value (signed_part, "crls", NULL, &crls_size);
  if (res != ASN1_ELEMENT_NOT_FOUND)
    {
      err =
	grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		    "PKCS#7 messages with embedded CRLs are not supported");
      goto cleanup_signed_part;
    }

  /* read the signature */
  result_buf =
    grub_asn1_allocate_and_read (signed_part, "signerInfos.?1.signature",
				 "signature data", &result_size);
  if (!result_buf)
    {
      err = grub_errno;
      goto cleanup_signed_part;
    }

  gcry_err =
    gcry_mpi_scan (&(msg->sig_mpi), GCRYMPI_FMT_USG, result_buf, result_size,
		   NULL);
  if (gcry_err != GPG_ERR_NO_ERROR)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Error loading signature into MPI structure: %d",
		    gcry_err);
      goto cleanup_result;
    }

cleanup_result:
  grub_free (result_buf);
cleanup_signed_part:
  asn1_delete_structure (&signed_part);

  return err;
}

grub_err_t
parse_pkcs7_signedData (void *sigbuf, grub_size_t data_size,
			struct pkcs7_signedData *msg)
{
  int res;
  asn1_node content_info;
  grub_err_t err = GRUB_ERR_NONE;
  char content_oid[MAX_OID_LEN];
  grub_uint8_t *content;
  int content_size;
  int content_oid_size = sizeof (content_oid);
  int size;

  if (data_size > GRUB_INT_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       "Cannot parse a PKCS#7 message where data size > INT_MAX");
  size = (int) data_size;

  res = asn1_create_element (_gnutls_pkix_asn,
			     "PKIX1.pkcs-7-ContentInfo", &content_info);
  if (res != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Could not create ASN.1 structure for PKCS#7 data: %s",
			 asn1_strerror (res));
    }

  res = asn1_der_decoding2 (&content_info, sigbuf, &size,
			    ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (res != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Error decoding PKCS#7 message DER: %s", asn1_error);
      goto cleanup;
    }

  /*
   * ContentInfo ::= SEQUENCE {
   *     contentType ContentType,
   *     content [0] EXPLICIT ANY DEFINED BY contentType }
   *
   * ContentType ::= OBJECT IDENTIFIER
   */
  res =
    asn1_read_value (content_info, "contentType", content_oid,
		     &content_oid_size);
  if (res != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Error reading PKCS#7 content type: %s",
		    asn1_strerror (res));
      goto cleanup;
    }

  /* OID for SignedData defined in 5.1 */
  if (grub_strncmp (signedData_oid, content_oid, content_oid_size) != 0)
    {
      err =
	grub_error (GRUB_ERR_BAD_SIGNATURE,
		    "Unexpected content type in PKCS#7 message: OID %s",
		    content_oid);
      goto cleanup;
    }

  content =
    grub_asn1_allocate_and_read (content_info, "content",
				 "PKCS#7 message content", &content_size);
  if (!content)
    {
      err = grub_errno;
      goto cleanup;
    }

  err = process_content (content, content_size, msg);
  grub_free (content);

cleanup:
  asn1_delete_structure (&content_info);
  return err;
}

/*
 * Release all the storage associated with the PKCS#7 message.
 * If the caller dynamically allocated the message, it must free it.
 */
void
pkcs7_signedData_release (struct pkcs7_signedData *msg)
{
  gcry_mpi_release (msg->sig_mpi);
}
