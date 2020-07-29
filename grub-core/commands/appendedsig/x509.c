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

#include <grub/libtasn1.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/crypto.h>
#include <grub/gcrypt/gcrypt.h>

#include "appendedsig.h"

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

/*
 * RFC 3279 2.3.1  RSA Keys
 */
const char *rsaEncryption_oid = "1.2.840.113549.1.1.1";

/*
 * RFC 5280 Appendix A
 */
const char *commonName_oid = "2.5.4.3";

/*
 * RFC 5280 4.2.1.3 Key Usage
 */
const char *keyUsage_oid = "2.5.29.15";

/*
 * RFC 5280 4.2.1.9 Basic Constraints
 */
const char *basicConstraints_oid = "2.5.29.19";

/*
 * RFC 3279 2.3.1
 *
 *  The RSA public key MUST be encoded using the ASN.1 type RSAPublicKey:
 *
 *     RSAPublicKey ::= SEQUENCE {
 *        modulus            INTEGER,    -- n
 *        publicExponent     INTEGER  }  -- e
 *
 *  where modulus is the modulus n, and publicExponent is the public
 *  exponent e.
 */
static grub_err_t
grub_parse_rsa_pubkey (grub_uint8_t * der, int dersize,
		       struct x509_certificate *certificate)
{
  int result;
  asn1_node spk = ASN1_TYPE_EMPTY;
  grub_uint8_t *m_data, *e_data;
  int m_size, e_size;
  grub_err_t err = GRUB_ERR_NONE;
  gcry_error_t gcry_err;

  result =
    asn1_create_element (_gnutls_gnutls_asn, "GNUTLS.RSAPublicKey", &spk);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Cannot create storage for public key ASN.1 data");
    }

  result = asn1_der_decoding2 (&spk, der, &dersize,
			       ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Cannot decode certificate public key DER: %s",
		    asn1_error);
      goto cleanup;
    }

  m_data =
    grub_asn1_allocate_and_read (spk, "modulus", "RSA modulus", &m_size);
  if (!m_data)
    {
      err = grub_errno;
      goto cleanup;
    }

  e_data =
    grub_asn1_allocate_and_read (spk, "publicExponent", "RSA public exponent",
				 &e_size);
  if (!e_data)
    {
      err = grub_errno;
      goto cleanup_m_data;
    }

  /*
   * convert m, e to mpi
   *
   * nscanned is not set for FMT_USG, it's only set for FMT_PGP, 
   * so we can't verify it
   */
  gcry_err =
    gcry_mpi_scan (&certificate->mpis[0], GCRYMPI_FMT_USG, m_data, m_size,
		   NULL);
  if (gcry_err != GPG_ERR_NO_ERROR)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error loading RSA modulus into MPI structure: %d",
		    gcry_err);
      goto cleanup_e_data;
    }

  gcry_err =
    gcry_mpi_scan (&certificate->mpis[1], GCRYMPI_FMT_USG, e_data, e_size,
		   NULL);
  if (gcry_err != GPG_ERR_NO_ERROR)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error loading RSA exponent into MPI structure: %d",
		    gcry_err);
      goto cleanup_m_mpi;
    }

  grub_free (e_data);
  grub_free (m_data);
  asn1_delete_structure (&spk);
  return GRUB_ERR_NONE;

cleanup_m_mpi:
  gcry_mpi_release (certificate->mpis[0]);
cleanup_e_data:
  grub_free (e_data);
cleanup_m_data:
  grub_free (m_data);
cleanup:
  asn1_delete_structure (&spk);
  return err;
}


/*
 * RFC 5280:
 *   SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING  }
 *
 * AlgorithmIdentifiers come from RFC 3279, we are not strictly compilant as we
 * only support RSA Encryption.
 */

static grub_err_t
grub_x509_read_subject_public_key (asn1_node asn,
				   struct x509_certificate *results)
{
  int result;
  grub_err_t err;
  const char *algo_name =
    "tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm";
  const char *params_name =
    "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters";
  const char *pk_name =
    "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey";
  char algo_oid[MAX_OID_LEN];
  int algo_size = sizeof (algo_oid);
  char params_value[2];
  int params_size = sizeof (params_value);
  grub_uint8_t *key_data = NULL;
  int key_size = 0;
  unsigned int key_type;

  /* algorithm: see notes for rsaEncryption_oid */
  result = asn1_read_value (asn, algo_name, algo_oid, &algo_size);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Error reading x509 public key algorithm: %s",
			 asn1_strerror (result));
    }

  if (grub_strncmp (algo_oid, rsaEncryption_oid, sizeof (rsaEncryption_oid))
      != 0)
    {
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			 "Unsupported x509 public key algorithm: %s",
			 algo_oid);
    }

  /* 
   * RFC 3279 2.3.1
   * The rsaEncryption OID is intended to be used in the algorithm field
   * of a value of type AlgorithmIdentifier.  The parameters field MUST
   * have ASN.1 type NULL for this algorithm identifier.
   */
  result = asn1_read_value (asn, params_name, params_value, &params_size);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Error reading x509 public key parameters: %s",
			 asn1_strerror (result));
    }

  if (params_value[0] != ASN1_TAG_NULL)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Invalid x509 public key parameters: expected NULL");
    }

  /*
   * RFC 3279 2.3.1:  The DER encoded RSAPublicKey is the value of the BIT
   * STRING subjectPublicKey.
   */
  result = asn1_read_value_type (asn, pk_name, NULL, &key_size, &key_type);
  if (result != ASN1_MEM_ERROR)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Error reading size of x509 public key: %s",
			 asn1_strerror (result));
    }
  if (key_type != ASN1_ETYPE_BIT_STRING)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Unexpected ASN.1 type when reading x509 public key: %x",
			 key_type);
    }

  /* length is in bits */
  key_size = (key_size + 7) / 8;

  key_data = grub_malloc (key_size);
  if (!key_data)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Out of memory for x509 public key");
    }

  result = asn1_read_value (asn, pk_name, key_data, &key_size);
  if (result != ASN1_SUCCESS)
    {
      grub_free (key_data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Error reading public key data");
    }
  key_size = (key_size + 7) / 8;

  err = grub_parse_rsa_pubkey (key_data, key_size, results);
  grub_free (key_data);

  return err;
}

/* Decode a string as defined in Appendix A */
static grub_err_t
decode_string (char *der, int der_size, char **string,
	       grub_size_t * string_size)
{
  asn1_node strasn;
  int result;
  char *choice;
  int choice_size = 0;
  int tmp_size = 0;
  grub_err_t err = GRUB_ERR_NONE;

  result =
    asn1_create_element (_gnutls_pkix_asn, "PKIX1.DirectoryString", &strasn);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Could not create ASN.1 structure for certificate: %s",
			 asn1_strerror (result));
    }

  result = asn1_der_decoding2 (&strasn, der, &der_size,
			       ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Could not parse DER for DirectoryString: %s",
		    asn1_error);
      goto cleanup;
    }

  choice =
    grub_asn1_allocate_and_read (strasn, "", "DirectoryString choice",
				 &choice_size);
  if (!choice)
    {
      err = grub_errno;
      goto cleanup;
    }

  if (grub_strncmp ("utf8String", choice, choice_size) == 0)
    {
      result = asn1_read_value (strasn, "utf8String", NULL, &tmp_size);
      if (result != ASN1_MEM_ERROR)
	{
	  err =
	    grub_error (GRUB_ERR_BAD_FILE_TYPE,
			"Error reading size of UTF-8 string: %s",
			asn1_strerror (result));
	  goto cleanup_choice;
	}
    }
  else if (grub_strncmp("printableString", choice, choice_size) == 0)
    {
      result = asn1_read_value (strasn, "printableString", NULL, &tmp_size);
      if (result != ASN1_MEM_ERROR)
	{
	  err =
	    grub_error (GRUB_ERR_BAD_FILE_TYPE,
			"Error reading size of UTF-8 string: %s",
			asn1_strerror (result));
	  goto cleanup_choice;
	}
    }
  else
    {
      err =
	grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		    "Only UTF-8 and printable DirectoryStrings are supported, got %s",
		    choice);
      goto cleanup_choice;
    }

  /* read size does not include trailing null */
  tmp_size++;

  *string = grub_malloc (tmp_size);
  if (!*string)
    {
      err =
	grub_error (GRUB_ERR_OUT_OF_MEMORY,
		    "Cannot allocate memory for DirectoryString contents");
      goto cleanup_choice;
    }

  result = asn1_read_value (strasn, choice, *string, &tmp_size);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error reading out %s in DirectoryString: %s",
		    choice, asn1_strerror (result));
      grub_free (*string);
      goto cleanup_choice;
    }
  *string_size = tmp_size + 1;
  (*string)[tmp_size] = '\0';

cleanup_choice:
  grub_free (choice);
cleanup:
  asn1_delete_structure (&strasn);
  return err;
}

/*
 * TBSCertificate  ::=  SEQUENCE  {
 *       version         [0]  EXPLICIT Version DEFAULT v1,
 * ...
 * 
 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static grub_err_t
check_version (asn1_node certificate)
{
  int rc;
  const char *name = "tbsCertificate.version";
  grub_uint8_t version;
  int len = 1;

  rc = asn1_read_value (certificate, name, &version, &len);

  /* require version 3 */
  if (rc != ASN1_SUCCESS || len != 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
		       "Error reading certificate version");

  if (version != 0x02)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
		       "Invalid x509 certificate version, expected v3 (0x02), got 0x%02x",
		       version);

  return GRUB_ERR_NONE;
}

/*
 * This is an X.501 Name, which is complex.
 *
 * For simplicity, we extract only the CN.
 */
static grub_err_t
read_name (asn1_node asn, const char *name_path, char **name,
	   grub_size_t * name_size)
{
  int seq_components, set_components;
  int result;
  int i, j;
  char *top_path, *set_path, *type_path, *val_path;
  char type[MAX_OID_LEN];
  int type_len = sizeof (type);
  int string_size = 0;
  char *string_der;
  grub_err_t err;

  *name = NULL;

  top_path = grub_xasprintf ("%s.rdnSequence", name_path);
  if (!top_path)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       "Could not allocate memory for %s name parsing path",
		       name_path);

  result = asn1_number_of_elements (asn, top_path, &seq_components);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error counting name components: %s",
		    asn1_strerror (result));
      goto cleanup;
    }

  for (i = 1; i <= seq_components; i++)
    {
      set_path = grub_xasprintf ("%s.?%d", top_path, i);
      if (!set_path)
	{
	  err =
	    grub_error (GRUB_ERR_OUT_OF_MEMORY,
			"Could not allocate memory for %s name set parsing path",
			name_path);
	  goto cleanup_set;
	}
      /* this brings us, hopefully, to a set */
      result = asn1_number_of_elements (asn, set_path, &set_components);
      if (result != ASN1_SUCCESS)
	{
	  err =
	    grub_error (GRUB_ERR_BAD_FILE_TYPE,
			"Error counting name sub-components components (element %d): %s",
			i, asn1_strerror (result));
	  goto cleanup_set;
	}
      for (j = 1; j <= set_components; j++)
	{
	  type_path = grub_xasprintf ("%s.?%d.?%d.type", top_path, i, j);
	  if (!type_path)
	    {
	      err =
		grub_error (GRUB_ERR_OUT_OF_MEMORY,
			    "Could not allocate memory for %s name component type path",
			    name_path);
	      goto cleanup_set;
	    }
	  type_len = sizeof (type);
	  result = asn1_read_value (asn, type_path, type, &type_len);
	  if (result != ASN1_SUCCESS)
	    {
	      err =
		grub_error (GRUB_ERR_BAD_FILE_TYPE,
			    "Error reading %s name component type: %s",
			    name_path, asn1_strerror (result));
	      goto cleanup_type;
	    }

	  if (grub_strncmp (type, commonName_oid, type_len) != 0)
	    {
	      grub_free (type_path);
	      continue;
	    }

	  val_path = grub_xasprintf ("%s.?%d.?%d.value", top_path, i, j);
	  if (!val_path)
	    {
	      err =
		grub_error (GRUB_ERR_OUT_OF_MEMORY,
			    "Could not allocate memory for %s name component value path",
			    name_path);
	      goto cleanup_set;
	    }

	  string_der =
	    grub_asn1_allocate_and_read (asn, val_path, name_path,
					 &string_size);
	  if (!string_der)
	    {
	      err = grub_errno;
	      goto cleanup_val_path;
	    }

	  err = decode_string (string_der, string_size, name, name_size);
	  if (err)
	    goto cleanup_string;

	  grub_free (string_der);
	  grub_free (type_path);
	  grub_free (val_path);
	  break;
	}
      grub_free (set_path);

      if (*name)
	break;
    }

  return GRUB_ERR_NONE;

cleanup_string:
  grub_free (string_der);
cleanup_val_path:
  grub_free (val_path);
cleanup_type:
  grub_free (type_path);
cleanup_set:
  grub_free (set_path);
cleanup:
  grub_free (top_path);
  return err;
}

/*
 * details here
 */
static grub_err_t
verify_key_usage (grub_uint8_t * value, int value_size)
{
  asn1_node usageasn;
  int result;
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint8_t usage = 0xff;
  int usage_size = 1;

  result =
    asn1_create_element (_gnutls_pkix_asn, "PKIX1.KeyUsage", &usageasn);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Could not create ASN.1 structure for key usage");
    }

  result = asn1_der_decoding2 (&usageasn, value, &value_size,
			       ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error parsing DER for Key Usage: %s", asn1_error);
      goto cleanup;
    }

  result = asn1_read_value (usageasn, "", &usage, &usage_size);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error reading Key Usage value: %s",
		    asn1_strerror (result));
      goto cleanup;
    }

  /* Only the first bit is permitted to be set */
  if (usage != 0x80)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE, "Unexpected Key Usage value: %x",
		    usage);
      goto cleanup;
    }

cleanup:
  asn1_delete_structure (&usageasn);
  return err;
}

/*
 * BasicConstraints ::= SEQUENCE {
 *       cA                      BOOLEAN DEFAULT FALSE,
 *       pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
static grub_err_t
verify_basic_constraints (grub_uint8_t * value, int value_size)
{
  asn1_node basicasn;
  int result;
  grub_err_t err = GRUB_ERR_NONE;
  char cA[6];			/* FALSE or TRUE */
  int cA_size = sizeof (cA);

  result =
    asn1_create_element (_gnutls_pkix_asn, "PKIX1.BasicConstraints",
			 &basicasn);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Could not create ASN.1 structure for Basic Constraints");
    }

  result = asn1_der_decoding2 (&basicasn, value, &value_size,
			       ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error parsing DER for Basic Constraints: %s",
		    asn1_error);
      goto cleanup;
    }

  result = asn1_read_value (basicasn, "cA", cA, &cA_size);
  if (result == ASN1_ELEMENT_NOT_FOUND)
    {
      /* Not present, default is False, so this is OK */
      err = GRUB_ERR_NONE;
      goto cleanup;
    }
  else if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Error reading Basic Constraints cA value: %s",
		    asn1_strerror (result));
      goto cleanup;
    }

  /* The certificate must not be a CA certificate */
  if (grub_strncmp ("FALSE", cA, cA_size) != 0)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "Unexpected CA value: %s",
			cA);
      goto cleanup;
    }

cleanup:
  asn1_delete_structure (&basicasn);
  return err;
}


/*
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension  ::=  SEQUENCE  {
 *      extnID      OBJECT IDENTIFIER,
 *      critical    BOOLEAN DEFAULT FALSE,
 *      extnValue   OCTET STRING
 *                  -- contains the DER encoding of an ASN.1 value
 *                  -- corresponding to the extension type identified
 *                  -- by extnID
 * }
 *
 * We require that a certificate:
 *  - contain the Digital Signature usage only
 *  - not be a CA
 *  - MUST not contain any other critical extensions (RFC 5280 s 4.2)
 */
static grub_err_t
verify_extensions (asn1_node cert)
{
  int result;
  int ext, num_extensions = 0;
  int usage_present = 0, constraints_present = 0;
  char *oid_path, *critical_path, *value_path;
  char extnID[MAX_OID_LEN];
  int extnID_size;
  grub_err_t err;
  char critical[6];		/* we get either "TRUE" or "FALSE" */
  int critical_size;
  grub_uint8_t *value;
  int value_size;

  result =
    asn1_number_of_elements (cert, "tbsCertificate.extensions",
			     &num_extensions);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Error counting number of extensions: %s",
			 asn1_strerror (result));
    }

  if (num_extensions < 2)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Insufficient number of extensions for certificate, need at least 2, got %d",
			 num_extensions);
    }

  for (ext = 1; ext <= num_extensions; ext++)
    {
      oid_path = grub_xasprintf ("tbsCertificate.extensions.?%d.extnID", ext);

      extnID_size = sizeof (extnID);
      result = asn1_read_value (cert, oid_path, extnID, &extnID_size);
      if (result != GRUB_ERR_NONE)
	{
	  err =
	    grub_error (GRUB_ERR_BAD_FILE_TYPE,
			"Error reading extension OID: %s",
			asn1_strerror (result));
	  goto cleanup_oid_path;
	}

      critical_path =
	grub_xasprintf ("tbsCertificate.extensions.?%d.critical", ext);
      critical_size = sizeof (critical);
      result =
	asn1_read_value (cert, critical_path, critical, &critical_size);
      if (result == ASN1_ELEMENT_NOT_FOUND)
	{
	  critical[0] = '\0';
	}
      else if (result != ASN1_SUCCESS)
	{
	  err =
	    grub_error (GRUB_ERR_BAD_FILE_TYPE,
			"Error reading extension criticality: %s",
			asn1_strerror (result));
	  goto cleanup_critical_path;
	}

      value_path =
	grub_xasprintf ("tbsCertificate.extensions.?%d.extnValue", ext);
      value =
	grub_asn1_allocate_and_read (cert, value_path,
				     "certificate extension value",
				     &value_size);
      if (!value)
	{
	  err = grub_errno;
	  goto cleanup_value_path;
	}

      /*
       * Now we must see if we recognise the OID.
       * If we have an unrecognised critical extension we MUST bail.
       */
      if (grub_strncmp (keyUsage_oid, extnID, extnID_size) == 0)
	{
	  err = verify_key_usage (value, value_size);
	  if (err != GRUB_ERR_NONE)
	    {
	      goto cleanup_value;
	    }
	  usage_present++;
	}
      else if (grub_strncmp (basicConstraints_oid, extnID, extnID_size) == 0)
	{
	  err = verify_basic_constraints (value, value_size);
	  if (err != GRUB_ERR_NONE)
	    {
	      goto cleanup_value;
	    }
	  constraints_present++;
	}
      else if (grub_strncmp ("TRUE", critical, critical_size) == 0)
	{
	  /*
	   * per the RFC, we must not process a certificate with
	   * a critical extension we do not understand.
	   */
	  err =
	    grub_error (GRUB_ERR_BAD_FILE_TYPE,
			"Unhandled critical x509 extension with OID %s",
			extnID);
	  goto cleanup_value;
	}

      grub_free (value);
      grub_free (value_path);
      grub_free (critical_path);
      grub_free (oid_path);
    }

  if (usage_present != 1)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Unexpected number of Key Usage extensions - expected 1, got %d",
			 usage_present);
    }
  if (constraints_present != 1)
    {
      return grub_error (GRUB_ERR_BAD_FILE_TYPE,
			 "Unexpected number of basic constraints extensions - expected 1, got %d",
			 constraints_present);
    }
  return GRUB_ERR_NONE;

cleanup_value:
  grub_free (value);
cleanup_value_path:
  grub_free (value_path);
cleanup_critical_path:
  grub_free (critical_path);
cleanup_oid_path:
  grub_free (oid_path);
  return err;
}

/*
 * Parse a certificate whose DER-encoded form is in @data, of size @data_size.
 * Return the results in @results, which must point to an allocated x509 certificate.
 */
grub_err_t
certificate_import (void *data, grub_size_t data_size,
		    struct x509_certificate *results)
{
  int result = 0;
  asn1_node cert;
  grub_err_t err;
  int size;
  int tmp_size;

  if (data_size > GRUB_INT_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       "Cannot parse a certificate where data size > INT_MAX");
  size = (int) data_size;

  result = asn1_create_element (_gnutls_pkix_asn, "PKIX1.Certificate", &cert);
  if (result != ASN1_SUCCESS)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "Could not create ASN.1 structure for certificate: %s",
			 asn1_strerror (result));
    }

  result = asn1_der_decoding2 (&cert, data, &size,
			       ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err =
	grub_error (GRUB_ERR_BAD_FILE_TYPE,
		    "Could not parse DER for certificate: %s", asn1_error);
      goto cleanup;
    }

  /* 
   * TBSCertificate  ::=  SEQUENCE {
   *     version         [0]  EXPLICIT Version DEFAULT v1
   */
  err = check_version (cert);
  if (err != GRUB_ERR_NONE)
    {
      goto cleanup;
    }

  /*
   * serialNumber         CertificateSerialNumber,
   *
   * CertificateSerialNumber  ::=  INTEGER
   */
  results->serial =
    grub_asn1_allocate_and_read (cert, "tbsCertificate.serialNumber",
				 "certificate serial number", &tmp_size);
  if (!results->serial)
    {
      err = grub_errno;
      goto cleanup;
    }
  /*
   * It's safe to cast the signed int to an unsigned here, we know
   * length is non-negative
   */
  results->serial_len = tmp_size;

  /* 
   * signature            AlgorithmIdentifier,
   *
   * We don't load the signature or issuer at the moment,
   * as we don't attempt x509 verification.
   */

  /*
   * issuer               Name,
   *
   * The RFC only requires the serial number to be unique within
   * issuers, so to avoid ambiguity we _technically_ ought to make
   * this available.
   */

  /*
   * validity             Validity,
   *
   * Validity ::= SEQUENCE {
   *     notBefore      Time,
   *     notAfter       Time }
   *
   * We can't validate this reasonably, we have no true time source on several
   * platforms. For now we do not parse them.
   */

  /*
   * subject              Name,
   * 
   * This is an X501 name, we parse out just the CN.
   */
  err =
    read_name (cert, "tbsCertificate.subject", &results->subject,
	       &results->subject_len);
  if (err != GRUB_ERR_NONE)
    goto cleanup_serial;

  /*
   * TBSCertificate  ::=  SEQUENCE  {
   *    ...
   *    subjectPublicKeyInfo SubjectPublicKeyInfo,
   *    ...
   */
  err = grub_x509_read_subject_public_key (cert, results);
  if (err != GRUB_ERR_NONE)
    goto cleanup_name;

  /*
   * TBSCertificate  ::=  SEQUENCE  {
   *    ...
   *    extensions      [3]  EXPLICIT Extensions OPTIONAL
   *                         -- If present, version MUST be v3
   * }
   */

  err = verify_extensions (cert);
  if (err != GRUB_ERR_NONE)
    goto cleanup_name;


  /*
   * We do not read or check the signature on the certificate:
   * as discussed we do not try to validate the certificate but trust
   * it implictly.
   */

  asn1_delete_structure (&cert);
  return GRUB_ERR_NONE;


cleanup_name:
  grub_free (results->subject);
cleanup_serial:
  grub_free (results->serial);
cleanup:
  asn1_delete_structure (&cert);
  return err;
}

/*
 * Release all the storage associated with the x509 certificate.
 * If the caller dynamically allocated the certificate, it must free it.
 * The caller is also responsible for maintenance of the linked list.
 */
void
certificate_release (struct x509_certificate *cert)
{
  grub_free (cert->subject);
  grub_free (cert->serial);
  gcry_mpi_release (cert->mpis[0]);
  gcry_mpi_release (cert->mpis[1]);
}
