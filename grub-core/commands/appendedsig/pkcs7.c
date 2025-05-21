/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2022 IBM Corporation
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
#include <sys/types.h>

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

/*
 * RFC 5652 s 5.1
 */
static const char *signedData_oid = "1.2.840.113549.1.7.2";

/*
 * RFC 4055 s 2.1
 */
static const char *sha256_oid = "2.16.840.1.101.3.4.2.1";
static const char *sha512_oid = "2.16.840.1.101.3.4.2.3";

static grub_err_t
process_content (grub_uint8_t *content, int size, struct pkcs7_signedData *msg)
{
  int res;
  asn1_node signed_part;
  grub_err_t err = GRUB_ERR_NONE;
  char algo_oid[MAX_OID_LEN];
  int algo_oid_size = sizeof (algo_oid);
  int algo_count;
  int signer_count;
  int i;
  char version;
  int version_size = sizeof (version);
  grub_uint8_t *result_buf;
  int result_size = 0;
  int crls_size = 0;
  gcry_error_t gcry_err;
  bool sha256_in_da, sha256_in_si, sha512_in_da, sha512_in_si;
  char *da_path;
  char *si_sig_path;
  char *si_da_path;

  res = asn1_create_element (_gnutls_pkix_asn, "PKIX1.pkcs-7-SignedData", &signed_part);
  if (res != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "Could not create ASN.1 structure for PKCS#7 signed part.");

  res = asn1_der_decoding2 (&signed_part, content, &size,
                            ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (res != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "Error reading PKCS#7 signed data: %s", asn1_error);
      goto cleanup_signed_part;
    }

  /*
   * SignedData ::= SEQUENCE {
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
      err = grub_error (GRUB_ERR_BAD_SIGNATURE, "Error reading signedData version: %s",
                        asn1_strerror (res));
      goto cleanup_signed_part;
    }

  if (version != 1)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "Unexpected signature version v%d, only v1 supported", version);
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
  res = asn1_number_of_elements (signed_part, "digestAlgorithms", &algo_count);
  if (res != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE, "Error counting number of digest algorithms: %s",
                        asn1_strerror (res));
      goto cleanup_signed_part;
    }

  if (algo_count <= 0)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "A minimum of 1 digest algorithm is required");
      goto cleanup_signed_part;
    }

  if (algo_count > 2)
    {
      err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                        "A maximum of 2 digest algorithms is supported");
      goto cleanup_signed_part;
    }

  sha256_in_da = false;
  sha512_in_da = false;

  for (i = 0; i < algo_count; i++)
    {
      da_path = grub_xasprintf ("digestAlgorithms.?%d.algorithm", i + 1);
      if (!da_path)
        {
          err = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                            "Could not allocate path for digest algorithm "
                            "parsing path");
          goto cleanup_signed_part;
        }

      algo_oid_size = sizeof (algo_oid);
      res = asn1_read_value (signed_part, da_path, algo_oid, &algo_oid_size);
      if (res != ASN1_SUCCESS)
        {
          err = grub_error (GRUB_ERR_BAD_SIGNATURE, "Error reading digest algorithm: %s",
                            asn1_strerror (res));
          grub_free (da_path);
          goto cleanup_signed_part;
        }

      if (grub_strncmp (sha512_oid, algo_oid, algo_oid_size) == 0)
        {
          if (!sha512_in_da)
            sha512_in_da = true;
          else
            {
              err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                                "SHA-512 specified twice in digest algorithm list");
              grub_free (da_path);
              goto cleanup_signed_part;
            }
        }
      else if (grub_strncmp (sha256_oid, algo_oid, algo_oid_size) == 0)
        {
          if (!sha256_in_da)
            sha256_in_da = true;
          else
            {
              err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                                "SHA-256 specified twice in digest algorithm list");
              grub_free (da_path);
              goto cleanup_signed_part;
            }
        }
      else
        {
          err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "Only SHA-256 and SHA-512 hashes are supported, found OID %s",
                            algo_oid);
          grub_free (da_path);
          goto cleanup_signed_part;
        }

      grub_free (da_path);
    }

  /* at this point, at least one of sha{256,512}_in_da must be true */

  /*
   * We ignore the certificates, but we don't permit CRLs.
   * A CRL entry might be revoking the certificate we're using, and we have
   * no way of dealing with that at the moment.
   */
  res = asn1_read_value (signed_part, "crls", NULL, &crls_size);
  if (res != ASN1_ELEMENT_NOT_FOUND)
    {
      err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                        "PKCS#7 messages with embedded CRLs are not supported");
      goto cleanup_signed_part;
    }

  /* read the signatures */

  res = asn1_number_of_elements (signed_part, "signerInfos", &signer_count);
  if (res != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE, "Error counting number of signers: %s",
                        asn1_strerror (res));
      goto cleanup_signed_part;
    }

  if (signer_count <= 0)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE, "A minimum of 1 signer is required");
      goto cleanup_signed_part;
    }

  msg->signerInfos = grub_calloc (signer_count, sizeof (struct pkcs7_signerInfo));
  if (!msg->signerInfos)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                        "Could not allocate space for %d signers", signer_count);
      goto cleanup_signed_part;
    }

  msg->signerInfo_count = 0;
  for (i = 0; i < signer_count; i++)
    {
      si_da_path = grub_xasprintf ("signerInfos.?%d.digestAlgorithm.algorithm", i + 1);
      if (!si_da_path)
        {
          err = grub_error (GRUB_ERR_OUT_OF_MEMORY, "Could not allocate path for signer %d's digest algorithm parsing path",
                            i);
          goto cleanup_signerInfos;
        }

      algo_oid_size = sizeof (algo_oid);
      res = asn1_read_value (signed_part, si_da_path, algo_oid, &algo_oid_size);
      if (res != ASN1_SUCCESS)
        {
          err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                            "Error reading signer %d's digest algorithm: %s", i,
                            asn1_strerror (res));
          grub_free (si_da_path);
          goto cleanup_signerInfos;
        }

      grub_free (si_da_path);

      if (grub_strncmp (sha512_oid, algo_oid, algo_oid_size) == 0)
        {
          if (!sha512_in_da)
            {
              err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                                "Signer %d claims a SHA-512 signature which was not specified in the outer DigestAlgorithms",
                                i);
              goto cleanup_signerInfos;
            }
          else
            {
              sha512_in_si = true;
              msg->signerInfos[i].hash = grub_crypto_lookup_md_by_name ("sha512");
            }
        }
      else if (grub_strncmp (sha256_oid, algo_oid, algo_oid_size) == 0)
        {
          if (!sha256_in_da)
            {
              err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                                "Signer %d claims a SHA-256 signature which was not specified in the outer DigestAlgorithms",
                                i);
              goto cleanup_signerInfos;
            }
          else
            {
              sha256_in_si = true;
              msg->signerInfos[i].hash = grub_crypto_lookup_md_by_name ("sha256");
            }
        }
      else
        {
          err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                            "Only SHA-256 and SHA-512 hashes are supported, found OID %s",
                            algo_oid);
          goto cleanup_signerInfos;
        }

      if (!msg->signerInfos[i].hash)
        {
          err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                            "Hash algorithm for signer %d (OID %s) not loaded", i, algo_oid);
          goto cleanup_signerInfos;
        }

      si_sig_path = grub_xasprintf ("signerInfos.?%d.signature", i + 1);
      if (!si_sig_path)
        {
          err = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                            "Could not allocate path for signer %d's signature parsing path", i);
          goto cleanup_signerInfos;
        }

      result_buf = grub_asn1_allocate_and_read (signed_part, si_sig_path,
                                                "signature data", &result_size);
      grub_free (si_sig_path);

      if (!result_buf)
        {
          err = grub_errno;
          goto cleanup_signerInfos;
        }

      gcry_err = gcry_mpi_scan (&(msg->signerInfos[i].sig_mpi), GCRYMPI_FMT_USG,
                                result_buf, result_size, NULL);

      grub_free (result_buf);

      if (gcry_err != GPG_ERR_NO_ERROR)
        {
          err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                            "Error loading signature %d into MPI structure: %d",
                            i, gcry_err);
          goto cleanup_signerInfos;
        }

      /*
       * use msg->signerInfo_count to track fully populated signerInfos so we
       * know how many we need to clean up
       */
      msg->signerInfo_count++;
    }

  /*
   * Final consistency check of signerInfo.*.digestAlgorithm vs
   * digestAlgorithms.*.algorithm. An algorithm must be present in both
   * digestAlgorithms and signerInfo or in neither. We have already checked
   * for an algorithm in signerInfo that is not in digestAlgorithms, here we
   * check for algorithms in digestAlgorithms but not in signerInfos.
   */
  if (sha512_in_da && !sha512_in_si)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "SHA-512 specified in DigestAlgorithms but did not "
                        "appear in SignerInfos");
      goto cleanup_signerInfos;
    }

  if (sha256_in_da && !sha256_in_si)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "SHA-256 specified in DigestAlgorithms but did not "
                        "appear in SignerInfos");
      goto cleanup_signerInfos;
    }

  asn1_delete_structure (&signed_part);
  return GRUB_ERR_NONE;

cleanup_signerInfos:
  for (i = 0; i < msg->signerInfo_count; i++)
    gcry_mpi_release (msg->signerInfos[i].sig_mpi);
  grub_free (msg->signerInfos);
cleanup_signed_part:
  asn1_delete_structure (&signed_part);
  return err;
}

grub_err_t
parse_pkcs7_signedData (const void *sigbuf, grub_size_t data_size, struct pkcs7_signedData *msg)
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
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "Cannot parse a PKCS#7 message "
                                              "where data size > INT_MAX");
  size = (int) data_size;

  res = asn1_create_element (_gnutls_pkix_asn, "PKIX1.pkcs-7-ContentInfo", &content_info);
  if (res != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "Could not create ASN.1 structure for PKCS#7 data: %s",
                       asn1_strerror (res));

  res = asn1_der_decoding2 (&content_info, sigbuf, &size,
                            ASN1_DECODE_FLAG_STRICT_DER | ASN1_DECODE_FLAG_ALLOW_PADDING,
                            asn1_error);
  if (res != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
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
  res = asn1_read_value (content_info, "contentType", content_oid, &content_oid_size);
  if (res != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE, "Error reading PKCS#7 content type: %s",
                        asn1_strerror (res));
      goto cleanup;
    }

  /* OID for SignedData defined in 5.1 */
  if (grub_strncmp (signedData_oid, content_oid, content_oid_size) != 0)
    {
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "Unexpected content type in PKCS#7 message: OID %s", content_oid);
      goto cleanup;
    }

  content = grub_asn1_allocate_and_read (content_info, "content",
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
  grub_ssize_t i;

  for (i = 0; i < msg->signerInfo_count; i++)
    gcry_mpi_release (msg->signerInfos[i].sig_mpi);

  grub_free (msg->signerInfos);
}
