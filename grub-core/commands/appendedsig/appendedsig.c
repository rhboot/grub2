/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2021, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2021, 2022 IBM Corporation
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

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/command.h>
#include <grub/crypto.h>
#include <grub/pkcs1_v15.h>
#include <grub/i18n.h>
#include <grub/gcrypt/gcrypt.h>
#include <grub/kernel.h>
#include <grub/extcmd.h>
#include <grub/verify.h>
#include <grub/libtasn1.h>
#include <grub/env.h>
#include <grub/lockdown.h>
#include <grub/powerpc/ieee1275/platform_keystore.h>
#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

const char magic[] = "~Module signature appended~\n";

/*
 * This structure is extracted from scripts/sign-file.c in the linux kernel
 * source. It was licensed as LGPLv2.1+, which is GPLv3+ compatible.
 */
struct module_signature
{
  grub_uint8_t algo;       /* Public-key crypto algorithm [0] */
  grub_uint8_t hash;       /* Digest algorithm [0] */
  grub_uint8_t id_type;    /* Key identifier type [PKEY_ID_PKCS7] */
  grub_uint8_t signer_len; /* Length of signer's name [0] */
  grub_uint8_t key_id_len; /* Length of key identifier [0] */
  grub_uint8_t __pad[3];
  grub_uint32_t sig_len;   /* Length of signature data */
} GRUB_PACKED;

/* This represents an entire, parsed, appended signature */
struct grub_appended_signature
{
  grub_size_t signature_len;            /* Length of PKCS#7 data + metadata + magic */
  struct module_signature sig_metadata; /* Module signature metadata */
  struct pkcs7_signedData pkcs7;        /* Parsed PKCS#7 data */
};

/* This represents a trusted/distrusted list*/
struct grub_database
{
  struct x509_certificate *keys; /* Certificates */
  grub_size_t key_entries;       /* Number of certificates */
  grub_uint8_t **signatures;     /* Certificate/binary hashes */
  grub_size_t *signature_size;   /* Size of certificate/binary hashes */
  grub_size_t signature_entries; /* Number of certificate/binary hashes */
};

/* Trusted list */
struct grub_database db = {.keys = NULL, .key_entries = 0, .signatures = NULL,
                           .signature_size = NULL, .signature_entries = 0};

/* Distrusted list */
struct grub_database dbx = {.signatures = NULL, .signature_size = NULL,
                            .signature_entries = 0};

/*
 * Force gcry_rsa to be a module dependency.
 *
 * If we use grub_crypto_pk_rsa, then then the gcry_rsa module won't be built
 * in if you add 'appendedsig' to grub-install --modules. You would need to
 * add 'gcry_rsa' too. That's confusing and seems suboptimal, especially when
 * we only support RSA.
 *
 * Dynamic loading also causes some concerns. We can't load gcry_rsa from the
 * the filesystem after we install the verifier - we won't be able to verify
 * it without having it already present. We also shouldn't load it before we
 * install the verifier, because that would mean it wouldn't be verified - an
 * attacker could insert any code they wanted into the module.
 *
 * So instead, reference the internal symbol from gcry_rsa. That creates a
 * direct dependency on gcry_rsa, so it will be built in when this module
 * is built in. Being built in (assuming the core image is itself signed!)
 * also resolves our concerns about loading from the filesystem.
 */
extern gcry_pk_spec_t _gcry_pubkey_spec_rsa;
extern gcry_md_spec_t _gcry_digest_spec_sha224;
extern gcry_md_spec_t _gcry_digest_spec_sha384;

/* Free trusted list memory */
static void free_trusted_list (void);
/* Free distrusted list memory */
static void free_distrusted_list (void);

static enum
{
  check_sigs_no = 0,
  check_sigs_enforce = 1,
  check_sigs_forced = 2
} check_sigs = check_sigs_no;

/*
 * GUID can be used to determine the hashing function and
 * generate the hash using determined hashing function.
 */
static grub_err_t
get_hash (const grub_uuid_t *guid, const grub_uint8_t *data, const grub_size_t data_size,
          grub_uint8_t *hash, grub_size_t *hash_size)
{
  gcry_md_spec_t *hash_func = NULL;

  if (guid == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "GUID is null");

  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_UUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_UUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha256;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_UUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_UUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha384;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_UUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_UUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha512;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "Unsupported GUID for hash");

  grub_memset (hash, 0, GRUB_MAX_HASH_SIZE);
  grub_crypto_hash (hash_func, hash, data, data_size);
  *hash_size =  hash_func->mdlen;

  return GRUB_ERR_NONE;
}

/* Add the certificate/binary hash into the trusted/distrusted list */
static grub_err_t
add_hash (const grub_uint8_t **data, const grub_size_t data_size,
          grub_uint8_t ***signature_list, grub_size_t **signature_size_list,
          grub_size_t *signature_list_entries)
{
  grub_uint8_t **signatures = *signature_list;
  grub_size_t *signature_size = *signature_size_list;
  grub_size_t signature_entries = *signature_list_entries;

  if (*data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate/binary hash data/size is null");

  signatures = grub_realloc (signatures, sizeof (grub_uint8_t *) * (signature_entries + 1));
  signature_size = grub_realloc (signature_size,
                                 sizeof (grub_size_t) * (signature_entries + 1));

  if (signatures == NULL || signature_size == NULL)
    {
      /*
       * allocated memory will be freed by
       * free_trusted_list/free_distrusted_list
       */
      if (signatures != NULL)
        {
          *signature_list = signatures;
          *signature_list_entries = signature_entries + 1;
        }

      if (signature_size != NULL)
        *signature_size_list = signature_size;

      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
    }

  signatures[signature_entries] = (grub_uint8_t *) *data;
  signature_size[signature_entries] = data_size;
  signature_entries++;
  *data = NULL;

  *signature_list = signatures;
  *signature_size_list = signature_size;
  *signature_list_entries = signature_entries;

  return GRUB_ERR_NONE;
}

static int
is_x509 (const grub_uuid_t *guid)
{
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_GUID, GRUB_UUID_SIZE) == 0)
    return GRUB_ERR_NONE;

  return GRUB_ERR_UNKNOWN_COMMAND;
}

static int
is_cert_match (const struct x509_certificate *distrusted_cert,
               const struct x509_certificate *db_cert)
{

  if (grub_memcmp (distrusted_cert->subject, db_cert->subject, db_cert->subject_len) == 0
      && grub_memcmp (distrusted_cert->serial, db_cert->serial, db_cert->serial_len) == 0
      && grub_memcmp (distrusted_cert->mpis[0], db_cert->mpis[0], sizeof (db_cert->mpis[0])) == 0
      && grub_memcmp (distrusted_cert->mpis[1], db_cert->mpis[1], sizeof (db_cert->mpis[1])) == 0)
    return GRUB_ERR_NONE;

  return GRUB_ERR_UNKNOWN_COMMAND;
}

/*
 * Verify the certificate against the certificate from platform keystore buffer's
 * distrusted list.
 */
static grub_err_t
is_distrusted_cert (const struct x509_certificate *db_cert)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t i = 0;
  struct x509_certificate *distrusted_cert = NULL;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL)
        continue;

      if (is_x509 (&grub_pks_keystore.dbx[i].guid) == GRUB_ERR_NONE)
        {
          distrusted_cert = grub_zalloc (sizeof (struct x509_certificate));
          if (distrusted_cert == NULL)
            return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

          rc = parse_x509_certificate (grub_pks_keystore.dbx[i].data,
                                       grub_pks_keystore.dbx[i].data_size, distrusted_cert);
          if (rc != GRUB_ERR_NONE)
            {
              grub_free (distrusted_cert);
              continue;
            }

          if (is_cert_match (distrusted_cert, db_cert) == GRUB_ERR_NONE)
            {
              grub_printf ("Warning: a trusted certificate CN='%s' is ignored "
                           "because it is on the distrusted list (dbx).\n", db_cert->subject);
              grub_free (grub_pks_keystore.dbx[i].data);
              grub_memset (&grub_pks_keystore.dbx[i], 0, sizeof (grub_pks_sd_t));
              certificate_release (distrusted_cert);
              grub_free (distrusted_cert);
              return GRUB_ERR_ACCESS_DENIED;
            }

          certificate_release (distrusted_cert);
          grub_free (distrusted_cert);
        }
    }

  return GRUB_ERR_NONE;
}

/* Add the certificate into the trusted/distrusted list */
static grub_err_t
add_certificate (const grub_uint8_t *data, const grub_size_t data_size,
                 struct grub_database *database, const grub_size_t is_db)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t key_entries = database->key_entries;
  struct x509_certificate *cert = NULL;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data/size is null");

  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = parse_x509_certificate (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "skipping %s certificate (%d)\n",
                    (is_db ? "trusted":"distrusted"), rc);
      grub_free (cert);
      return rc;
    }

  if (is_db)
    {
      rc = is_distrusted_cert (cert);
      if (rc != GRUB_ERR_NONE)
        {
          certificate_release (cert);
          grub_free (cert);
          return rc;
        }
    }

  grub_dprintf ("appendedsig", "add a %s certificate CN='%s'\n",
                (is_db ? "trusted":"distrusted"), cert->subject);

  key_entries++;
  cert->next = database->keys;
  database->keys = cert;
  database->key_entries = key_entries;

  return rc;
}

static const char *
grub_env_read_sec (struct grub_env_var *var __attribute__ ((unused)),
                   const char *val __attribute__ ((unused)))
{
  if (check_sigs == check_sigs_forced)
    return "forced";
  else if (check_sigs == check_sigs_enforce)
    return "enforce";
  else
    return "no";
}

static char *
grub_env_write_sec (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  /* Do not allow the value to be changed if set to forced */
  if (check_sigs == check_sigs_forced)
    return grub_strdup ("forced");

  if ((*val == '2') || (*val == 'f'))
    check_sigs = check_sigs_forced;
  else if ((*val == '1') || (*val == 'e'))
    check_sigs = check_sigs_enforce;
  else if ((*val == '0') || (*val == 'n'))
    check_sigs = check_sigs_no;

  return grub_strdup (grub_env_read_sec (NULL, NULL));
}

static grub_err_t
file_read_all (grub_file_t file, grub_uint8_t **buf, grub_size_t *len)
{
  grub_off_t full_file_size;
  grub_size_t file_size, total_read_size = 0;
  grub_ssize_t read_size;

  full_file_size = grub_file_size (file);
  if (full_file_size == GRUB_FILE_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("Cannot read a file of unknown size into a buffer"));

  if (full_file_size > GRUB_SIZE_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       N_("File is too large to read: %" PRIuGRUB_UINT64_T " bytes"),
                       full_file_size);

  file_size = (grub_size_t) full_file_size;

  *buf = grub_malloc (file_size);
  if (!*buf)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       N_("Could not allocate file data buffer size %" PRIuGRUB_SIZE),
                       file_size);

  while (total_read_size < file_size)
    {
      read_size = grub_file_read (file, *buf + total_read_size, file_size - total_read_size);

      if (read_size < 0)
        {
          grub_free (*buf);
          return grub_errno;
        }
      else if (read_size == 0)
        {
          grub_free (*buf);
          return grub_error (GRUB_ERR_IO,
                             N_("Could not read full file size "
                                "(%" PRIuGRUB_SIZE "), only %" PRIuGRUB_SIZE " bytes read"),
                             file_size, total_read_size);
        }

      total_read_size += read_size;
    }
  *len = file_size;
  return GRUB_ERR_NONE;
}

static grub_err_t
read_cert_from_file (grub_file_t f, struct x509_certificate *certificate)
{
  grub_err_t err;
  grub_uint8_t *buf;
  grub_size_t file_size;

  err = file_read_all (f, &buf, &file_size);
  if (err != GRUB_ERR_NONE)
    return err;

  err = parse_x509_certificate (buf, file_size, certificate);
  grub_free (buf);

  return err;
}

static grub_err_t
extract_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize,
                            struct grub_appended_signature *sig)
{
  grub_size_t pkcs7_size;
  grub_size_t remaining_len;
  const grub_uint8_t *appsigdata = buf + bufsize - grub_strlen (magic);

  if (bufsize < grub_strlen (magic))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("File too short for signature magic"));

  if (grub_memcmp (appsigdata, (grub_uint8_t *) magic, grub_strlen (magic)))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("Missing or invalid signature magic"));

  remaining_len = bufsize - grub_strlen (magic);

  if (remaining_len < sizeof (struct module_signature))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("File too short for signature metadata"));

  appsigdata -= sizeof (struct module_signature);

  /* extract the metadata */
  grub_memcpy (&(sig->sig_metadata), appsigdata, sizeof (struct module_signature));

  remaining_len -= sizeof (struct module_signature);

  if (sig->sig_metadata.id_type != 2)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("Wrong signature type"));

  pkcs7_size = grub_be_to_cpu32 (sig->sig_metadata.sig_len);

  if (pkcs7_size > remaining_len)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("File too short for PKCS#7 message"));

  grub_dprintf ("appendedsig", "sig len %" PRIuGRUB_SIZE "\n", pkcs7_size);

  sig->signature_len = grub_strlen (magic) + sizeof (struct module_signature) + pkcs7_size;

  /* rewind pointer and parse pkcs7 data */
  appsigdata -= pkcs7_size;

  return parse_pkcs7_signedData (appsigdata, pkcs7_size, &sig->pkcs7);
}

static grub_err_t
get_binary_hash (const grub_size_t binary_hash_size, const grub_uint8_t *data,
                 const grub_size_t data_size, grub_uint8_t *hash, grub_size_t *hash_size)
{
  grub_uuid_t guid = { 0 };

  /* support SHA256, SHA384 and SHA512 for binary hash */
  if (binary_hash_size == 32)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_UUID_SIZE);
  else if (binary_hash_size == 48)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_UUID_SIZE);
  else if (binary_hash_size == 64)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_UUID_SIZE);
  else
    {
      grub_dprintf ("appendedsig", "unsupported hash type (%" PRIuGRUB_SIZE ") and skipping binary hash\n",
                    binary_hash_size);
      return GRUB_ERR_UNKNOWN_COMMAND;
    }

  return get_hash (&guid, data, data_size, hash, hash_size);
}

/*
 * Verify binary hash against the list of binary hashes that are distrusted
 * and trusted.
 * The following errors can occur:
 *  - GRUB_ERR_BAD_SIGNATURE: indicates that the hash is distrusted.
 *  - GRUB_ERR_NONE: the hash is trusted, since it was found in the trusted hashes list
 *  - GRUB_ERR_EOF: the hash could not be found in the hashes list
 */
static grub_err_t
verify_binary_hash (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t i = 0, hash_size = 0;
  grub_uint8_t hash[GRUB_MAX_HASH_SIZE] = { 0 };

  for (i = 0; i < dbx.signature_entries; i++)
    {
      rc = get_binary_hash (dbx.signature_size[i], data, data_size, hash, &hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (hash_size == dbx.signature_size[i] &&
          grub_memcmp (dbx.signatures[i], hash, hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "the binary hash (%02x%02x%02x%02x) was listed as distrusted\n",
                        hash[0], hash[1], hash[2], hash[3]);
          return GRUB_ERR_BAD_SIGNATURE;
        }
    }

  for (i = 0; i < db.signature_entries; i++)
    {
      rc = get_binary_hash (db.signature_size[i], data, data_size, hash, &hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (hash_size == db.signature_size[i] &&
          grub_memcmp (db.signatures[i], hash, hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "verified with a trusted binary hash (%02x%02x%02x%02x)\n",
                        hash[0], hash[1], hash[2], hash[3]);
          return GRUB_ERR_NONE;
        }
    }

  return GRUB_ERR_EOF;
}


/*
 * Verify the kernel's integrity, the trusted key will be used from
 * the trusted key list. If it fails, verify it against the list of binary hashes
 * that are distrusted and trusted.
 */
static grub_err_t
grub_verify_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize)
{
  grub_err_t err = GRUB_ERR_NONE;
  grub_size_t datasize;
  void *context;
  unsigned char *hash;
  gcry_mpi_t hashmpi;
  gcry_err_code_t rc;
  struct x509_certificate *cert;
  struct grub_appended_signature sig;
  struct pkcs7_signerInfo *si;
  int i;

  if (!db.key_entries && !db.signature_entries)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("No trusted keys to verify against"));

  err = extract_appended_signature (buf, bufsize, &sig);
  if (err != GRUB_ERR_NONE)
    return err;

  datasize = bufsize - sig.signature_len;
  err = verify_binary_hash (buf, datasize);
  if (err != GRUB_ERR_EOF && err != GRUB_ERR_NONE)
    {
      err = grub_error (err, N_("failed to verify binary-hash/signature with any trusted binary-hash/key\n"));
      pkcs7_signedData_release (&sig.pkcs7);
      return err;
    }
  else if (err == GRUB_ERR_EOF)
    {
      /* Binary hash was not found in trusted and distrusted list: check signature now */
      for (i = 0; i < sig.pkcs7.signerInfo_count; i++)
        {
          /*
           * This could be optimised in a couple of ways:
           * - we could only compute hashes once per hash type
           * - we could track signer information and only verify where IDs match
           * For now we do the naive O(db.keys * pkcs7 signers) approach.
           */
          si = &sig.pkcs7.signerInfos[i];
          context = grub_zalloc (si->hash->contextsize);
          if (context == NULL)
            return grub_errno;

          si->hash->init (context);
          si->hash->write (context, buf, datasize);
          si->hash->final (context);
          hash = si->hash->read (context);

          grub_dprintf ("appendedsig",
                        "data size %" PRIxGRUB_SIZE ", signer %d hash %02x%02x%02x%02x...\n",
                        datasize, i, hash[0], hash[1], hash[2], hash[3]);

          err = GRUB_ERR_BAD_SIGNATURE;
          for (cert = db.keys; cert; cert = cert->next)
            {
              rc = grub_crypto_rsa_pad (&hashmpi, hash, si->hash, cert->mpis[0]);
              if (rc != 0)
                {
                  err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                                    N_("Error padding hash for RSA verification: %d"), rc);
                  grub_free (context);
                  pkcs7_signedData_release (&sig.pkcs7);
                  return err;
                }

              rc = _gcry_pubkey_spec_rsa.verify (0, hashmpi, &si->sig_mpi, cert->mpis, NULL, NULL);
              gcry_mpi_release (hashmpi);
              if (rc == 0)
                {
                  grub_dprintf ("appendedsig", "verify signer %d with key '%s' succeeded\n",
                                i, cert->subject);
                  err = GRUB_ERR_NONE;
                  break;
                }

              grub_dprintf ("appendedsig", "verify signer %d with key '%s' failed with %d\n",
                            i, cert->subject, rc);
            }
          grub_free (context);
          if (err == GRUB_ERR_NONE)
            break;
      }
    }

  pkcs7_signedData_release (&sig.pkcs7);

  if (err != GRUB_ERR_NONE)
    err = grub_error (err, N_("failed to verify signature with any trusted key\n"));
  else
    grub_dprintf ("appendedsig", "successfully verified the signature with a trusted key\n");

  return err;
}

static grub_err_t
grub_cmd_verify_signature (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t f;
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint8_t *data;
  grub_size_t file_size;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("one argument expected"));

  grub_dprintf ("appendedsig", "verifying %s\n", args[0]);

  f = grub_file_open (args[0], GRUB_FILE_TYPE_VERIFY_SIGNATURE);
  if (!f)
    {
      err = grub_errno;
      goto cleanup;
    }

  err = file_read_all (f, &data, &file_size);
  if (err != GRUB_ERR_NONE)
    goto cleanup;

  err = grub_verify_appended_signature (data, file_size);

  grub_free (data);

cleanup:
  if (f)
    grub_file_close (f);
  return err;
}

static grub_err_t
grub_cmd_distrust (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  unsigned long cert_num, i;
  struct x509_certificate *cert, *prev;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("One argument expected"));

  grub_errno = GRUB_ERR_NONE;
  cert_num = grub_strtoul (args[0], NULL, 10);
  if (grub_errno != GRUB_ERR_NONE)
    return grub_errno;

  if (cert_num < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("Certificate number too small - numbers start at 1"));

  if (cert_num == 1)
    {
      cert = db.keys;
      db.keys = cert->next;

      certificate_release (cert);
      grub_free (cert);
      return GRUB_ERR_NONE;
    }
  i = 2;
  prev = db.keys;
  cert = db.keys->next;
  while (cert)
    {
      if (i == cert_num)
        {
          prev->next = cert->next;
          certificate_release (cert);
          grub_free (cert);
          return GRUB_ERR_NONE;
        }
      i++;
      prev = cert;
      cert = cert->next;
    }

  return grub_error (GRUB_ERR_BAD_ARGUMENT,
                     N_("No certificate number %lu found - only %lu certificates in the store"),
                     cert_num, i - 1);
}

static grub_err_t
grub_cmd_trust (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t certf;
  struct x509_certificate *cert = NULL;
  grub_err_t err;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("one argument expected"));

  certf = grub_file_open (args[0], GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (!certf)
    return grub_errno;

  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (!cert)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("Could not allocate memory for certificate"));

  err = read_cert_from_file (certf, cert);
  grub_file_close (certf);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (cert);
      return err;
    }
  grub_dprintf ("appendedsig", "Loaded certificate with CN: %s\n", cert->subject);

  cert->next = db.keys;
  db.keys = cert;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_list (grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)),
               char **args __attribute__ ((unused)))
{
  struct x509_certificate *cert;
  int cert_num = 1;
  grub_size_t i;

  for (cert = db.keys; cert; cert = cert->next)
    {
      grub_printf (N_("Certificate %d:\n"), cert_num);

      grub_printf (N_("\tSerial: "));
      for (i = 0; i < cert->serial_len - 1; i++)
        {
          grub_printf ("%02x:", cert->serial[i]);
        }
      grub_printf ("%02x\n", cert->serial[cert->serial_len - 1]);

      grub_printf ("\tCN: %s\n\n", cert->subject);
      cert_num++;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
appendedsig_init (grub_file_t io __attribute__ ((unused)), enum grub_file_type type,
                  void **context __attribute__ ((unused)), enum grub_verify_flags *flags)
{
  if (check_sigs == check_sigs_no)
    {
      *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
      return GRUB_ERR_NONE;
    }

  switch (type & GRUB_FILE_TYPE_MASK)
    {
      case GRUB_FILE_TYPE_CERTIFICATE_TRUST:
        /*
         * This is a certificate to add to trusted keychain.
         *
         * This needs to be verified or blocked. Ideally we'd write an x509
         * verifier, but we lack the hubris required to take this on. Instead,
         * require that it have an appended signature.
         */

        /* Fall through */

      case GRUB_FILE_TYPE_LINUX_KERNEL:
      case GRUB_FILE_TYPE_GRUB_MODULE:
        /*
         * Appended signatures are only defined for ELF binaries.
         * Out of an abundance of caution, we only verify Linux kernels and
         * GRUB modules at this point.
         */
        *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
        return GRUB_ERR_NONE;

      case GRUB_FILE_TYPE_ACPI_TABLE:
      case GRUB_FILE_TYPE_DEVICE_TREE_IMAGE:
        /*
         * It is possible to use appended signature verification without
         * lockdown - like the PGP verifier. When combined with an embedded
         * config file in a signed grub binary, this could still be a meaningful
         * secure-boot chain - so long as it isn't subverted by something like a
         * rouge ACPI table or DT image. Defer them explicitly.
         */
        *flags = GRUB_VERIFY_FLAGS_DEFER_AUTH;
        return GRUB_ERR_NONE;

      default:
        *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
        return GRUB_ERR_NONE;
    }
}

static grub_err_t
appendedsig_write (void *ctxt __attribute__ ((unused)), void *buf, grub_size_t size)
{
  return grub_verify_appended_signature (buf, size);
}

struct grub_file_verifier grub_appendedsig_verifier = {
  .name = "appendedsig",
  .init = appendedsig_init,
  .write = appendedsig_write,
};

static grub_ssize_t
pseudo_read (struct grub_file *file, char *buf, grub_size_t len)
{
  grub_memcpy (buf, (grub_uint8_t *) file->data + file->offset, len);
  return len;
}

/* Filesystem descriptor.  */
static struct grub_fs pseudo_fs = { .name = "pseudo", .fs_read = pseudo_read };

static grub_command_t cmd_verify, cmd_list, cmd_distrust, cmd_trust;

/*
 * Verify the trusted certificate against the certificate hashes from platform keystore buffer's
 * distrusted list.
 */
static grub_err_t
is_distrusted_cert_hash (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t i = 0, cert_hash_size = 0;
  grub_uint8_t cert_hash[GRUB_MAX_HASH_SIZE] = { 0 };

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "trusted certificate data/size is null");

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL ||
          grub_pks_keystore.dbx[i].data_size == 0)
        continue;

      rc = get_hash (&grub_pks_keystore.dbx[i].guid, data, data_size,
                     cert_hash, &cert_hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (cert_hash_size == grub_pks_keystore.dbx[i].data_size &&
          grub_memcmp (grub_pks_keystore.dbx[i].data, cert_hash, cert_hash_size) == 0)
        {
          grub_printf ("Warning: a trusted certificate (%02x%02x%02x%02x) is ignored "
                       "because this certificate hash is on the distrusted list (dbx).\n",
                       cert_hash[0], cert_hash[1], cert_hash[2], cert_hash[3]);
          grub_free (grub_pks_keystore.dbx[i].data);
          grub_memset (&grub_pks_keystore.dbx[i], 0, sizeof (grub_pks_keystore.dbx[i]));
          return GRUB_ERR_BAD_SIGNATURE;
        }
    }

  return GRUB_ERR_NONE;
}

/*
 * Verify the trusted binary hash against the platform keystore buffer's
 * distrusted list.
 */
static grub_err_t
is_distrusted_binary_hash (const grub_uint8_t *binary_hash,
                           const grub_size_t binary_hash_size)
{
  grub_size_t i = 0;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL ||
          grub_pks_keystore.dbx[i].data_size == 0)
        continue;

      if (binary_hash_size == grub_pks_keystore.dbx[i].data_size &&
          grub_memcmp (grub_pks_keystore.dbx[i].data, binary_hash, binary_hash_size) == 0)
        {
          grub_printf ("Warning: a trusted binary hash (%02x%02x%02x%02x) is ignored"
                       " because it is on the distrusted list (dbx).\n",
                       binary_hash[0], binary_hash[1], binary_hash[2], binary_hash[3]);
          grub_free (grub_pks_keystore.dbx[i].data);
          grub_memset (&grub_pks_keystore.dbx[i], 0, sizeof(grub_pks_keystore.dbx[i]));
          return GRUB_ERR_BAD_SIGNATURE;
        }
    }

  return GRUB_ERR_NONE;
}

/*
 * Extract the binary hashes from the platform keystore buffer,
 * and add it to the trusted list if it does not exist in the distrusted list.
 */
static grub_err_t
add_trusted_binary_hash (const grub_uint8_t **data, const grub_size_t data_size)
{
  grub_err_t rc = GRUB_ERR_NONE;

  if (*data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "trusted binary hash data/size is null");

  rc = is_distrusted_binary_hash (*data, data_size);
  if (rc != GRUB_ERR_NONE)
    return rc;

  rc = add_hash (data, data_size, &db.signatures, &db.signature_size,
                 &db.signature_entries);
  return rc;
}

static int
is_hash (const grub_uuid_t *guid)
{
  /* GUID type of the binary hash */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_UUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_UUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_UUID_SIZE) == 0)
    return GRUB_ERR_NONE;

  /* GUID type of the certificate hash */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_UUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_UUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_UUID_SIZE) == 0)
    return GRUB_ERR_NONE;

  return GRUB_ERR_UNKNOWN_COMMAND;
}

/*
 * Extract the x509 certificates/binary hashes from the platform keystore buffer,
 * parse it, and add it to the trusted list.
 */
static grub_err_t
create_trusted_list (void)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t i = 0;

  for (i = 0; i < grub_pks_keystore.db_entries; i++)
    {
      if (is_hash (&grub_pks_keystore.db[i].guid) == GRUB_ERR_NONE)
        {
          rc = add_trusted_binary_hash ((const grub_uint8_t **)
                                        &grub_pks_keystore.db[i].data,
                                        grub_pks_keystore.db[i].data_size);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_x509 (&grub_pks_keystore.db[i].guid) == GRUB_ERR_NONE)
        {
          rc = is_distrusted_cert_hash (grub_pks_keystore.db[i].data,
                                        grub_pks_keystore.db[i].data_size);
          if (rc != GRUB_ERR_NONE)
            continue;

          rc = add_certificate (grub_pks_keystore.db[i].data,
                                grub_pks_keystore.db[i].data_size, &db, 1);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
          else if (rc != GRUB_ERR_NONE)
            continue;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipping trusted data (%" PRIuGRUB_SIZE ")\n", i + 1);
    }

  return GRUB_ERR_NONE;
}

/*
 * Extract the certificates, certificate/binary hashes out of the platform keystore buffer,
 * and add it to the distrusted list.
 */
static grub_err_t
create_distrusted_list (void)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t i = 0;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data != NULL ||
          grub_pks_keystore.dbx[i].data_size > 0)
        {
          if (is_x509 (&grub_pks_keystore.dbx[i].guid) == GRUB_ERR_NONE)
            {
              rc = add_certificate (grub_pks_keystore.dbx[i].data,
                                    grub_pks_keystore.dbx[i].data_size, &dbx, 0);
              if (rc == GRUB_ERR_OUT_OF_MEMORY)
                return rc;
            }
          else if (is_hash (&grub_pks_keystore.dbx[i].guid) == GRUB_ERR_NONE)
            {
              rc = add_hash ((const grub_uint8_t **) &grub_pks_keystore.dbx[i].data,
                             grub_pks_keystore.dbx[i].data_size,
                             &dbx.signatures, &dbx.signature_size,
                             &dbx.signature_entries);
              if (rc != GRUB_ERR_NONE)
                return rc;
            }
          else
            grub_dprintf ("appendedsig", "unsupported signature data type and "
                          "skipping distrusted data (%" PRIuGRUB_SIZE ")\n", i + 1);
        }
    }

  return rc;
}

/*
 * Extract the x509 certificates from the ELF note header,
 * parse it, and add it to the trusted list.
 */
static grub_err_t
build_static_trusted_list (const struct grub_module_header *header, const grub_bool_t is_pks)
{
  grub_err_t err = GRUB_ERR_NONE;
  struct grub_file pseudo_file;
  grub_uint8_t *cert_data = NULL;
  grub_ssize_t cert_data_size = 0;

  grub_memset (&pseudo_file, 0, sizeof (pseudo_file));
  pseudo_file.fs = &pseudo_fs;
  pseudo_file.size = header->size - sizeof (struct grub_module_header);
  pseudo_file.data = (char *) header + sizeof (struct grub_module_header);

  grub_dprintf ("appendedsig", "found an x509 key, size=%" PRIuGRUB_UINT64_T "\n",
                pseudo_file.size);

  err = grub_read_file (&pseudo_file, &cert_data, &cert_data_size);
  if (err != GRUB_ERR_NONE)
    return err;

  if (is_pks)
    {
      err = is_distrusted_cert_hash (cert_data, cert_data_size);
      if (err != GRUB_ERR_NONE)
        return err;
    }

  err = add_certificate (cert_data, cert_data_size, &db, 1);
  grub_free (cert_data);

  return err;
}

/* releasing memory */
static void
free_trusted_list (void)
{
  struct x509_certificate *cert;
  grub_size_t i = 0;

  while (db.keys != NULL)
    {
      cert = db.keys;
      db.keys = db.keys->next;
      certificate_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < db.signature_entries; i++)
    grub_free (db.signatures[i]);

  grub_free (db.signatures);
  grub_free (db.signature_size);
  grub_memset (&db, 0, sizeof (db));
}

/* releasing memory */
static void
free_distrusted_list (void)
{
  struct x509_certificate *cert;
  grub_size_t i = 0;

  while (dbx.keys != NULL)
    {
      cert = dbx.keys;
      dbx.keys = dbx.keys->next;
      certificate_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < dbx.signature_entries; i++)
    grub_free (dbx.signatures[i]);

  grub_free (dbx.signatures);
  grub_free (dbx.signature_size);
  grub_memset (&dbx, 0, sizeof (dbx));
}

static grub_err_t
load_static_keys (const struct grub_module_header *header, const grub_bool_t is_pks)
{
  int rc = GRUB_ERR_NONE;
  FOR_MODULES (header)
    {
      /* Not an ELF module, skip.  */
      if (header->type != OBJ_TYPE_X509_PUBKEY)
        continue;
      rc = build_static_trusted_list (header, is_pks);
      if (rc != GRUB_ERR_NONE)
        return rc;
    }
  return rc;
}

GRUB_MOD_INIT (appendedsig)
{
  int rc;
  struct grub_module_header *header;

  /* If in lockdown, immediately enter forced mode */
  if (grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    check_sigs = check_sigs_forced;

  grub_register_variable_hook ("check_appended_signatures", grub_env_read_sec, grub_env_write_sec);
  grub_env_export ("check_appended_signatures");

  rc = asn1_init ();
  if (rc)
    grub_fatal ("Error initing ASN.1 data structures: %d: %s\n", rc, asn1_strerror (rc));

  if (!grub_pks_use_keystore && check_sigs == check_sigs_forced)
    {
      rc = load_static_keys (header, false);
      if (rc != GRUB_ERR_NONE)
        {
          free_trusted_list ();
          grub_error (rc, "static trusted list creation failed");
        }
      else
        grub_dprintf ("appendedsig", "the trusted list now has %" PRIuGRUB_SIZE " static keys\n",
                      db.key_entries);
    }
  else if (grub_pks_use_keystore && check_sigs == check_sigs_forced)
    {
      if (grub_pks_keystore.use_static_keys)
        {
          grub_printf ("Warning: db variable is not available at PKS and using a static keys "
                       "as a default key in trusted list\n");
          rc = load_static_keys (header, grub_pks_keystore.use_static_keys);
        }
      else
        rc = create_trusted_list ();

      if (rc != GRUB_ERR_NONE)
        {
          free_trusted_list ();
          grub_error (rc, "trusted list creation failed");
        }
      else
        {
          rc = create_distrusted_list ();
          if (rc != GRUB_ERR_NONE)
            {
              free_trusted_list ();
              free_distrusted_list ();
              grub_error (rc, "distrusted list creation failed");
            }
          else
            grub_dprintf ("appendedsig", "the trusted list now has %" PRIuGRUB_SIZE " keys.\n"
                          "the distrusted list now has %" PRIuGRUB_SIZE " keys.\n",
                          db.signature_entries + db.key_entries, dbx.signature_entries);
        }

      grub_pks_free_keystore ();
    }

  cmd_trust = grub_register_command ("trust_certificate", grub_cmd_trust, N_("X509_CERTIFICATE"),
                                     N_("Add X509_CERTIFICATE to trusted certificates."));
  cmd_list = grub_register_command ("list_certificates", grub_cmd_list, 0,
                                    N_("Show the list of trusted x509 certificates."));
  cmd_verify = grub_register_command ("verify_appended", grub_cmd_verify_signature, N_("FILE"),
                                      N_("Verify FILE against the trusted x509 certificates."));
  cmd_distrust = grub_register_command ("distrust_certificate", grub_cmd_distrust,
                                        N_("CERT_NUMBER"),
                                        N_("Remove CERT_NUMBER (as listed by list_certificates)"
                                           " from trusted certificates."));

  grub_verifier_register (&grub_appendedsig_verifier);
  grub_dl_set_persistent (mod);
}

GRUB_MOD_FINI (appendedsig)
{
  /*
   * grub_dl_set_persistent should prevent this from actually running, but
   * it does still run under emu.
   */

  grub_verifier_unregister (&grub_appendedsig_verifier);
  grub_unregister_command (cmd_verify);
  grub_unregister_command (cmd_list);
  grub_unregister_command (cmd_trust);
  grub_unregister_command (cmd_distrust);
}
