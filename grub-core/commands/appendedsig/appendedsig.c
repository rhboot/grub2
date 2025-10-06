/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2021, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2021, 2022, 2025 IBM Corporation
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
#include <grub/i18n.h>
#include <grub/gcrypt/gcrypt.h>
#include <grub/kernel.h>
#include <grub/extcmd.h>
#include <grub/verify.h>
#include <libtasn1.h>
#include <grub/env.h>
#include <grub/lockdown.h>
#include <grub/powerpc/ieee1275/platform_keystore.h>
#include <grub/efi/pks.h>

#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Public key type. */
#define PKEY_ID_PKCS7      2

/* Appended signature magic string and size. */
#define SIG_MAGIC          "~Module signature appended~\n"
#define SIG_MAGIC_SIZE     ((sizeof(SIG_MAGIC) - 1))

/* SHA256, SHA384 and SHA512 hash sizes. */
#define SHA256_HASH_SIZE   32
#define SHA384_HASH_SIZE   48
#define SHA512_HASH_SIZE   64

/*
 * This structure is extracted from scripts/sign-file.c in the linux kernel
 * source. It was licensed as LGPLv2.1+, which is GPLv3+ compatible.
 */
struct module_signature
{
  grub_uint8_t algo;       /* Public-key crypto algorithm [0]. */
  grub_uint8_t hash;       /* Digest algorithm [0]. */
  grub_uint8_t id_type;    /* Key identifier type [PKEY_ID_PKCS7]. */
  grub_uint8_t signer_len; /* Length of signer's name [0]. */
  grub_uint8_t key_id_len; /* Length of key identifier [0]. */
  grub_uint8_t __pad[3];
  grub_uint32_t sig_len;   /* Length of signature data. */
} GRUB_PACKED;

#define SIG_METADATA_SIZE  (sizeof (struct module_signature))
#define APPENDED_SIG_SIZE(pkcs7_data_size) \
                           (pkcs7_data_size + SIG_MAGIC_SIZE + SIG_METADATA_SIZE)

/* This represents an entire, parsed, appended signature. */
struct appended_signature
{
  struct module_signature sig_metadata; /* Module signature metadata. */
  grub_pkcs7_data_t pkcs7;              /* Parsed PKCS#7 data. */
  grub_size_t signature_len;            /* Length of PKCS#7 data + metadata + magic. */
};
typedef struct appended_signature sb_appendedsig_t;

/* This represents a trusted certificates. */
struct sb_database
{
  grub_x509_cert_t *certs;    /* Certificates. */
  grub_uint32_t cert_entries; /* Number of certificates. */
  grub_uint8_t **hashes;      /* Certificate/binary hashes. */
  grub_size_t *hash_sizes;    /* Sizes of certificate/binary hashes. */
  grub_uint32_t hash_entries; /* Number of certificate/binary hashes. */
  bool is_db;                 /* Flag to indicate the db/dbx list. */
};
typedef struct sb_database sb_database_t;

/* The db list is used to validate appended signatures. */
static sb_database_t db = {.certs = NULL, .cert_entries = 0, .hashes = NULL,
                           .hash_sizes = NULL, .hash_entries = 0, .is_db = true};
/*
 * The dbx list is used to ensure that the distrusted certificates or GRUB
 * modules/kernel binaries are rejected during appended signatures/hashes
 * validation.
 */
static sb_database_t dbx = {.certs = NULL, .cert_entries = 0, .hashes = NULL,
                            .hash_sizes = NULL, .hash_entries = 0, .is_db = false};

/*
 * Signature verification flag (check_sigs).
 * check_sigs: false
 *  - No signature verification. This is the default.
 * check_sigs: true
 *  - Enforce signature verification, and if signature verification fails, post
 *    the errors and stop the boot.
 */
static bool check_sigs = false;

/*
 * append_key_mgmt: Key Management Modes
 * False: Static key management (use built-in Keys). This is default.
 * True: Dynamic key management (use Platform KeySotre).
 */
static bool append_key_mgmt = false;

/* Platform KeyStore db and dbx. */
static grub_pks_t *pks_keystore;

/* Appended signature size. */
static grub_size_t append_sig_len = 0;

static grub_ssize_t
pseudo_read (struct grub_file *file, char *buf, grub_size_t len)
{
  grub_memcpy (buf, (grub_uint8_t *) file->data + file->offset, len);
  return len;
}

/* Filesystem descriptor. */
static struct grub_fs pseudo_fs = {
  .name = "pseudo",
  .fs_read = pseudo_read
};

/*
 * We cannot use hexdump() to display hash data because it is typically displayed
 * in hexadecimal format, along with an ASCII representation of the same data.
 *
 * Example: sha256 hash data
 * 00000000  52 b5 90 49 64 de 22 d7  4e 5f 4f b4 1b 51 9c 34  |R..Id.".N_O..Q.4|
 * 00000010  b1 96 21 7c 91 78 a5 0d  20 8c e9 5c 22 54 53 f7  |..!|.x.. ..\"TS.|
 *
 * An appended signature only required to display the hexadecimal of the hash data
 * by separating each byte with ":". So, we introduced a new method hexdump_colon
 * to display it.
 *
 * Example: Sha256 hash data
 *  52:b5:90:49:64:de:22:d7:4e:5f:4f:b4:1b:51:9c:34:
 *  b1:96:21:7c:91:78:a5:0d:20:8c:e9:5c:22:54:53:f7
 */
static void
hexdump_colon (const grub_uint8_t *data, const grub_size_t length)
{
  grub_size_t i, count = 0;

  for (i = 0; i < length - 1; i++)
    {
      grub_printf ("%02x:", data[i]);
      count++;
      if (count == 16)
        {
          grub_printf ("\n         ");
          count = 0;
        }
    }

  grub_printf ("%02x\n", data[i]);
}

static void
print_certificate (const grub_x509_cert_t *cert, const grub_uint32_t cert_num)
{
  grub_uint32_t i;

  grub_printf ("\nCertificate: %u\n", cert_num);
  grub_printf ("    Data:\n");
  grub_printf ("        Version: %u (0x%u)\n", cert->version + 1, cert->version);
  grub_printf ("        Serial Number:\n             ");

  for (i = 0; i < cert->serial_len - 1; i++)
    grub_printf ("%02x:", cert->serial[i]);

  grub_printf ("%02x\n", cert->serial[cert->serial_len - 1]);
  grub_printf ("        Issuer: %s\n", cert->issuer);
  grub_printf ("        Subject: %s\n", cert->subject);
  grub_printf ("        Subject Public Key Info:\n");
  grub_printf ("            Public Key Algorithm: rsaEncryption\n");
  grub_printf ("                RSA Public-Key: (%d bit)\n", cert->modulus_size);
  grub_printf ("    Fingerprint: sha256\n         ");
  hexdump_colon (&cert->fingerprint[GRUB_FINGERPRINT_SHA256][0],
                 grub_strlen ((char *) cert->fingerprint[GRUB_FINGERPRINT_SHA256]));
}

/*
 * GUID can be used to determine the hashing function and generate the hash using
 * determined hashing function.
 */
static grub_err_t
get_hash (const grub_packed_guid_t *guid, const grub_uint8_t *data, const grub_size_t data_size,
          grub_uint8_t *hash, grub_size_t *hash_size)
{
  gcry_md_spec_t *hash_func = NULL;

  if (guid == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "GUID is not available");

  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha256;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha384;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha512;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "unsupported GUID hash");

  grub_crypto_hash (hash_func, hash, data, data_size);
  *hash_size = hash_func->mdlen;

  return GRUB_ERR_NONE;
}

static grub_err_t
generate_cert_hash (const grub_size_t cert_hash_size, const grub_uint8_t *data,
                    const grub_size_t data_size, grub_uint8_t *hash, grub_size_t *hash_size)
{
  grub_packed_guid_t guid = { 0 };

  /* support SHA256, SHA384 and SHA512 for certificate hash */
  if (cert_hash_size == SHA256_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_PACKED_GUID_SIZE);
  else if (cert_hash_size == SHA384_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_PACKED_GUID_SIZE);
  else if (cert_hash_size == SHA512_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_PACKED_GUID_SIZE);
  else
    {
      grub_dprintf ("appendedsig", "unsupported hash type (%" PRIuGRUB_SIZE ") and "
                    "skipped\n", cert_hash_size);
      return GRUB_ERR_UNKNOWN_COMMAND;
    }

  return get_hash (&guid, data, data_size, hash, hash_size);
}

/* Check the hash presence in the db/dbx list. */
static bool
check_hash_presence (grub_uint8_t *const hash, const grub_size_t hash_size,
                     const sb_database_t *sb_database)
{
  grub_uint32_t i;

  for (i = 0; i < sb_database->hash_entries; i++)
    {
      if (sb_database->hashes[i] == NULL)
        continue;

      if (hash_size == sb_database->hash_sizes[i] &&
          grub_memcmp (sb_database->hashes[i], hash, hash_size) == 0)
        return true;
    }

  return false;
}

/* Add the certificate/binary hash into the db/dbx list. */
static grub_err_t
add_hash (grub_uint8_t *const data, const grub_size_t data_size, sb_database_t *sb_database)
{
  grub_uint8_t **hashes;
  grub_size_t *hash_sizes;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate/binary-hash data or size is not available");

  if (sb_database->is_db == true)
    {
      if (check_hash_presence (data, data_size, &dbx) == true)
        {
          grub_dprintf ("appendedsig",
                        "cannot add a hash (%02x%02x%02x%02x), as it is present in the dbx list\n",
                        data[0], data[1], data[2], data[3]);
          return GRUB_ERR_ACCESS_DENIED;
        }
    }

  if (check_hash_presence (data, data_size, sb_database) == true)
    {
      grub_dprintf ("appendedsig",
                    "cannot add a hash (%02x%02x%02x%02x), as it is present in the %s list\n",
                    data[0], data[1], data[2], data[3], ((sb_database->is_db == true) ? "db" : "dbx"));
      return GRUB_ERR_EXISTS;
    }

  hashes = grub_realloc (sb_database->hashes, sizeof (grub_uint8_t *) * (sb_database->hash_entries + 1));
  if (hashes == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  hash_sizes = grub_realloc (sb_database->hash_sizes, sizeof (grub_size_t) * (sb_database->hash_entries + 1));
  if (hash_sizes == NULL)
    {
      /* Allocated memory will be freed by free_db_list()/free_dbx_list(). */
      hashes[sb_database->hash_entries] = NULL;
      sb_database->hashes = hashes;
      sb_database->hash_entries++;

      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
    }

  hashes[sb_database->hash_entries] = grub_malloc (data_size);
  if (hashes[sb_database->hash_entries] == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  grub_dprintf ("appendedsig",
                "added the hash %02x%02x%02x%02x... with size of %" PRIuGRUB_SIZE " to the %s list\n",
                data[0], data[1], data[2], data[3], data_size,
                ((sb_database->is_db == true) ? "db" : "dbx"));

  grub_memcpy (hashes[sb_database->hash_entries], data, data_size);
  hash_sizes[sb_database->hash_entries] = data_size;
  sb_database->hash_sizes = hash_sizes;
  sb_database->hashes = hashes;
  sb_database->hash_entries++;

  return GRUB_ERR_NONE;
}

static bool
is_hash (const grub_packed_guid_t *guid)
{
  /* GUID type of the binary hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  /* GUID type of the certificate hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  return false;
}

static bool
is_x509 (const grub_packed_guid_t *guid)
{
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  return false;
}

static bool
is_cert_match (const grub_x509_cert_t *cert1, const grub_x509_cert_t *cert2)
{
  if (grub_memcmp (cert1->subject, cert2->subject, cert2->subject_len) == 0
      && grub_memcmp (cert1->issuer, cert2->issuer, cert2->issuer_len) == 0
      && grub_memcmp (cert1->serial, cert2->serial, cert2->serial_len) == 0
      && grub_memcmp (cert1->mpis[GRUB_RSA_PK_MODULUS], cert2->mpis[GRUB_RSA_PK_MODULUS],
                      sizeof (cert2->mpis[GRUB_RSA_PK_MODULUS])) == 0
      && grub_memcmp (cert1->mpis[GRUB_RSA_PK_EXPONENT], cert2->mpis[GRUB_RSA_PK_EXPONENT],
                      sizeof (cert2->mpis[GRUB_RSA_PK_EXPONENT])) == 0
      && grub_memcmp (cert1->fingerprint[GRUB_FINGERPRINT_SHA256],
                      cert2->fingerprint[GRUB_FINGERPRINT_SHA256],
                      grub_strlen ((char *) cert2->fingerprint[GRUB_FINGERPRINT_SHA256])) == 0)
    return true;

  return false;
}

/* Check the certificate hash presence in the dbx list. */
static bool
is_cert_hash_present_in_dbx (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc;
  grub_uint32_t i;
  grub_size_t cert_hash_size = 0;
  grub_uint8_t cert_hash[GRUB_MAX_HASH_LEN] = { 0 };

  for (i = 0; i < dbx.hash_entries; i++)
    {
      if (dbx.hashes[i] == NULL)
        continue;

      rc = generate_cert_hash (dbx.hash_sizes[i], data, data_size, cert_hash, &cert_hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (cert_hash_size == dbx.hash_sizes[i] &&
          grub_memcmp (dbx.hashes[i], cert_hash, cert_hash_size) == 0)
        return true;
    }

  return false;
}

/* Check the certificate presence in the db/dbx list. */
static bool
check_cert_presence (const grub_x509_cert_t *cert_in, const sb_database_t *sb_database)
{
  grub_x509_cert_t *cert;

  for (cert = sb_database->certs; cert != NULL; cert = cert->next)
    if (is_cert_match (cert, cert_in) == true)
      return true;

  return false;
}

/*
 * Add the certificate into the db list if it is not present in the dbx and db
 * list when is_db is true. Add the certificate into the dbx list when is_db is
 * false.
 */
static grub_err_t
add_certificate (const grub_uint8_t *data, const grub_size_t data_size,
                 sb_database_t *sb_database)
{
  grub_err_t rc;
  grub_x509_cert_t *cert;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data or size is not available");

  cert = grub_zalloc (sizeof (grub_x509_cert_t));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = grub_x509_cert_parse (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "cannot add a certificate CN='%s' to the %s list\n",
                    cert->subject, (sb_database->is_db == true) ? "db" : "dbx");
      grub_free (cert);
      return rc;
    }

  /*
   * Only checks the certificate against dbx if is_db is true when dynamic key
   * management is enabled.
   */
  if (append_key_mgmt == true)
    {
      if (sb_database->is_db == true)
        {
          if (is_cert_hash_present_in_dbx (data, data_size) == true ||
              check_cert_presence (cert, &dbx) == true)
            {
              grub_dprintf ("appendedsig",
                            "cannot add a certificate CN='%s', as it is present in the dbx list",
                            cert->subject);
              rc = GRUB_ERR_ACCESS_DENIED;
              goto fail;
            }
        }
    }

  if (check_cert_presence (cert, sb_database) == true)
    {
      grub_dprintf ("appendedsig",
                    "cannot add a certificate CN='%s', as it is present in the %s list",
                    cert->subject, ((sb_database->is_db == true) ? "db" : "dbx"));
      rc = GRUB_ERR_EXISTS;
      goto fail;
    }

  grub_dprintf ("appendedsig", "added a certificate CN='%s' to the %s list\n",
                cert->subject, ((sb_database->is_db == true) ? "db" : "dbx"));

  cert->next = sb_database->certs;
  sb_database->certs = cert;
  sb_database->cert_entries++;

  return rc;

 fail:
  grub_x509_cert_release (cert);
  grub_free (cert);

  return rc;
}

static void
_remove_cert_from_db (const grub_x509_cert_t *cert)
{
  grub_uint32_t i = 1;
  grub_x509_cert_t *curr_cert, *prev_cert;

  for (curr_cert = prev_cert = db.certs; curr_cert != NULL; curr_cert = curr_cert->next, i++)
    {
      if (is_cert_match (curr_cert, cert) == true)
        {
          if (i == 1) /* Match with first certificate in the db list. */
            db.certs = curr_cert->next;
          else
            prev_cert->next = curr_cert->next;

          grub_dprintf ("appendedsig",
                        "removed distrusted certificate with CN: %s from the db list\n",
                        curr_cert->subject);
          curr_cert->next = NULL;
          grub_x509_cert_release (curr_cert);
          grub_free (curr_cert);
          break;
        }
      else
        prev_cert = curr_cert;
    }
}

static grub_err_t
remove_cert_from_db (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc;
  grub_x509_cert_t *cert;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data or size is not available");

  cert = grub_zalloc (sizeof (grub_x509_cert_t));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = grub_x509_cert_parse (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "cannot remove an invalid certificate from the db list\n");
      grub_free (cert);
      return rc;
    }

  /* Remove certificate from the db list. */
  _remove_cert_from_db (cert);

  return rc;
}

static grub_err_t
file_read_whole (grub_file_t file, grub_uint8_t **buf, grub_size_t *len)
{
  grub_off_t full_file_size;
  grub_size_t file_size, total_read_size = 0;
  grub_ssize_t read_size;

  full_file_size = grub_file_size (file);
  if (full_file_size == GRUB_FILE_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "cannot read a file of unknown size into a buffer");

  if (full_file_size > GRUB_SIZE_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "file is too large to read: %" PRIuGRUB_OFFSET " bytes",
                       full_file_size);

  file_size = (grub_size_t) full_file_size;
  *buf = grub_malloc (file_size);
  if (*buf == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate file data buffer size %" PRIuGRUB_SIZE,
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
                             "could not read full file size "
                             "(%" PRIuGRUB_SIZE "), only %" PRIuGRUB_SIZE " bytes read",
                             file_size, total_read_size);
        }

      total_read_size += read_size;
    }

  *len = file_size;

  return GRUB_ERR_NONE;
}

static grub_err_t
extract_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize,
                            sb_appendedsig_t *sig)
{
  grub_size_t appendedsig_pkcs7_size;
  grub_size_t signed_data_size = bufsize;
  const grub_uint8_t *signed_data = buf;

  if (signed_data_size < SIG_MAGIC_SIZE)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature magic");

  /* Fast-forwarding pointer and get signature magic string. */
  signed_data += signed_data_size - SIG_MAGIC_SIZE;
  if (grub_strncmp ((const char *) signed_data, SIG_MAGIC, SIG_MAGIC_SIZE))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "missing or invalid signature magic");

  signed_data_size -= SIG_MAGIC_SIZE;
  if (signed_data_size < SIG_METADATA_SIZE)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature metadata");

  /* Rewind pointer and extract signature metadata. */
  signed_data -= SIG_METADATA_SIZE;
  grub_memcpy (&(sig->sig_metadata), signed_data, SIG_METADATA_SIZE);

  if (sig->sig_metadata.id_type != PKEY_ID_PKCS7)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "wrong signature type");

  appendedsig_pkcs7_size = grub_be_to_cpu32 (sig->sig_metadata.sig_len);

  signed_data_size -= SIG_METADATA_SIZE;
  if (appendedsig_pkcs7_size > signed_data_size)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for PKCS#7 message");

  grub_dprintf ("appendedsig", "sig len %" PRIuGRUB_SIZE "\n", appendedsig_pkcs7_size);

  /* Appended signature size. */
  sig->signature_len = APPENDED_SIG_SIZE (appendedsig_pkcs7_size);
  /* Rewind pointer and parse appended pkcs7 data. */
  signed_data -= appendedsig_pkcs7_size;

  return grub_pkcs7_data_parse (signed_data, appendedsig_pkcs7_size, &sig->pkcs7);
}

static grub_err_t
get_binary_hash (const grub_size_t binary_hash_size, const grub_uint8_t *data,
                 const grub_size_t data_size, grub_uint8_t *hash, grub_size_t *hash_size)
{
  grub_packed_guid_t guid = { 0 };

  /* support SHA256, SHA384 and SHA512 for binary hash */
  if (binary_hash_size == SHA256_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE);
  else if (binary_hash_size == SHA384_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE);
  else if (binary_hash_size == SHA512_HASH_SIZE)
    grub_memcpy (&guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE);
  else
    {
      grub_dprintf ("appendedsig", "unsupported hash type (%" PRIuGRUB_SIZE ") and "
                    "skipped\n", binary_hash_size);
      return GRUB_ERR_UNKNOWN_COMMAND;
    }

  return get_hash (&guid, data, data_size, hash, hash_size);
}

/*
 * Verify binary hash against the db and dbx list.
 * The following errors can occur:
 *  - GRUB_ERR_BAD_SIGNATURE: indicates that the hash is in dbx list.
 *  - GRUB_ERR_EOF: the hash could not be found in the db and dbx list.
 *  - GRUB_ERR_NONE: the hash is found in db list.
 */
static grub_err_t
verify_binary_hash (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_uint32_t i;
  grub_size_t hash_size = 0;
  grub_uint8_t hash[GRUB_MAX_HASH_LEN] = { 0 };

  for (i = 0; i < dbx.hash_entries; i++)
    {
      if (dbx.hashes[i] == NULL)
        continue;

      rc = get_binary_hash (dbx.hash_sizes[i], data, data_size, hash, &hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (hash_size == dbx.hash_sizes[i] &&
          grub_memcmp (dbx.hashes[i], hash, hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "the hash (%02x%02x%02x%02x) is present in the dbx list\n",
                        hash[0], hash[1], hash[2], hash[3]);
          return GRUB_ERR_BAD_SIGNATURE;
        }
    }

  for (i = 0; i < db.hash_entries; i++)
    {
      if (db.hashes[i] == NULL)
        continue;

      rc = get_binary_hash (db.hash_sizes[i], data, data_size, hash, &hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (hash_size == db.hash_sizes[i] &&
          grub_memcmp (db.hashes[i], hash, hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "verified with a trusted hash (%02x%02x%02x%02x)\n",
                        hash[0], hash[1], hash[2], hash[3]);
          return GRUB_ERR_NONE;
        }
    }

  return GRUB_ERR_EOF;
}

/*
 * Given a hash value 'hval', of hash specification 'hash', prepare the
 * S-expressions (sexp) and perform the signature verification.
 */
static grub_err_t
verify_signature (const gcry_mpi_t *pkmpi, const gcry_mpi_t hmpi,
                  const gcry_md_spec_t *hash, const grub_uint8_t *hval)
{
  gcry_sexp_t hsexp, pubkey, sig;
  grub_size_t errof;

  if (_gcry_sexp_build (&hsexp, &errof, "(data (flags %s) (hash %s %b))", "pkcs1",
                        hash->name, hash->mdlen, hval) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  if (_gcry_sexp_build (&pubkey, &errof, "(public-key (dsa (n %M) (e %M)))",
                        pkmpi[0], pkmpi[1]) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  if (_gcry_sexp_build (&sig, &errof, "(sig-val (rsa (s %M)))", hmpi) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  _gcry_sexp_dump (sig);
  _gcry_sexp_dump (hsexp);
  _gcry_sexp_dump (pubkey);

  if (grub_crypto_pk_rsa->verify (sig, hsexp, pubkey) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_verify_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize)
{
  grub_err_t err;
  grub_size_t datasize;
  void *context;
  grub_uint8_t *hash;
  grub_x509_cert_t *pk;
  sb_appendedsig_t sig;
  grub_pkcs7_signer_t *si;
  grub_int32_t i;

  if (!db.cert_entries && !db.hash_entries)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "no trusted keys to verify against");

  err = extract_appended_signature (buf, bufsize, &sig);
  if (err != GRUB_ERR_NONE)
    return err;

  append_sig_len = sig.signature_len;
  datasize = bufsize - sig.signature_len;

  /*
   * If signature verification is enabled with dynamic key management mode,
   * Verify binary hash against the db and dbx list.
   */
  if (append_key_mgmt == true)
    {
      err = verify_binary_hash (buf, datasize);
      if (err == GRUB_ERR_BAD_SIGNATURE)
        {
          grub_pkcs7_data_release (&sig.pkcs7);
          return grub_error (err,
                             "failed to verify the binary hash against a trusted binary hash");
        }
    }

  /* Verify signature using trusted keys from db list. */
  for (i = 0; i < sig.pkcs7.signer_count; i++)
    {
      si = &sig.pkcs7.signers[i];
      context = grub_zalloc (si->hash->contextsize);
      if (context == NULL)
        return grub_errno;

      si->hash->init (context, 0);
      si->hash->write (context, buf, datasize);
      si->hash->final (context);
      hash = si->hash->read (context);

      grub_dprintf ("appendedsig", "data size %" PRIuGRUB_SIZE ", signer %d hash %02x%02x%02x%02x...\n",
                    datasize, i, hash[0], hash[1], hash[2], hash[3]);

      for (pk = db.certs; pk != NULL; pk = pk->next)
        {
          err = verify_signature (pk->mpis, si->sig_mpi, si->hash, hash);
          if (err == GRUB_ERR_NONE)
            {
              grub_dprintf ("appendedsig", "verify signer %d with key '%s' succeeded\n",
                            i, pk->subject);
              break;
            }

          grub_dprintf ("appendedsig", "verify signer %d with key '%s' failed\n",
                        i, pk->subject);
        }

      grub_free (context);
      if (err == GRUB_ERR_NONE)
        break;
    }

  grub_pkcs7_data_release (&sig.pkcs7);

  if (err != GRUB_ERR_NONE)
    return grub_error (err, "failed to verify signature against a trusted key");

  return err;
}

static grub_err_t
grub_cmd_verify_signature (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t signed_file;
  grub_err_t err;
  grub_uint8_t *signed_data = NULL;
  grub_size_t signed_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a signed file is expected\nExample:\n\tappend_verify <SIGNED FILE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing signed file");

  grub_dprintf ("appendedsig", "verifying %s\n", args[0]);

  signed_file = grub_file_open (args[0], GRUB_FILE_TYPE_VERIFY_SIGNATURE);
  if (signed_file == NULL)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND, "could not open %s file", args[0]);

  err = file_read_whole (signed_file, &signed_data, &signed_data_size);
  if (err == GRUB_ERR_NONE)
    {
      err = grub_verify_appended_signature (signed_data, signed_data_size);
      grub_free (signed_data);
    }

  grub_file_close (signed_file);

  return err;
}

/*
 * Checks the trusted certificate against dbx list if dynamic key management is
 * enabled. And add it to the db list if it is not already present.
 *
 * Note: When signature verification is enabled, this command only accepts the
 * trusted certificate that is signed with an appended signature.
 * The signature is verified by the appendedsig module. If verification succeeds,
 * the certificate is added to the db list. Otherwise, an error is posted and
 * the certificate is not added.
 * When signature verification is disabled, it accepts the trusted certificate
 * without an appended signature and add it to the db list.
 *
 * Also, note that the adding of the trusted certificate using this command does
 * not persist across reboots.
 */
static grub_err_t
grub_cmd_db_cert (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_err_t err;
  grub_file_t cert_file;
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a trusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_add_db_cert <X509_CERTIFICATE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing trusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = file_read_whole (cert_file, &cert_data, &cert_data_size);
  grub_file_close (cert_file);
  if (err != GRUB_ERR_NONE)
    return err;

  /*
   * If signature verification is enabled (check_sigs is set to true), obtain
   * the actual certificate size by subtracting the appended signature size from
   * the certificate size because the certificate has an appended signature, and
   * this actual certificate size is used to get the X.509 certificate.
   */
  if (check_sigs == true)
    cert_data_size -= append_sig_len;

  err = add_certificate (cert_data, cert_data_size, &db);
  grub_free (cert_data);

  return err;
}

/*
 * Remove the distrusted certificate from the db list if it is already present.
 * And add it to the dbx list if not present when dynamic key management is
 * enabled.
 *
 * Note: When signature verification is enabled, this command only accepts the
 * distrusted certificate that is signed with an appended signature.
 * The signature is verified by the appended sig module. If verification
 * succeeds, the certificate is removed from the db list. Otherwise, an error
 * is posted and the certificate is not removed.
 * When signature verification is disabled, it accepts the distrusted certificate
 * without an appended signature and removes it from the db list.
 *
 * Also, note that the removal of the distrusted certificate using this command
 * does not persist across reboots.
 */
static grub_err_t
grub_cmd_dbx_cert (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_err_t err;
  grub_file_t cert_file;
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a distrusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_add_dbx_cert <X509_CERTIFICATE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing distrusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = file_read_whole (cert_file, &cert_data, &cert_data_size);
  grub_file_close (cert_file);
  if (err != GRUB_ERR_NONE)
    return err;

  /*
   * If signature verification is enabled (check_sigs is set to true), obtain
   * the actual certificate size by subtracting the appended signature size from
   * the certificate size because the certificate has an appended signature, and
   * this actual certificate size is used to get the X.509 certificate.
   */
  if (check_sigs == true)
    cert_data_size -= append_sig_len;

  /* Remove distrusted certificate from the db list if present. */
  err = remove_cert_from_db (cert_data, cert_data_size);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (cert_data);
      return err;
    }

  /* Only add the certificate to the dbx list if dynamic key management is enabled. */
  if (append_key_mgmt == true)
    err = add_certificate (cert_data, cert_data_size, &dbx);

  grub_free (cert_data);

  return err;
}

static grub_err_t
grub_cmd_list_db (grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)),
                  char **args __attribute__ ((unused)))
{
  struct x509_certificate *cert;
  grub_uint32_t i, cert_num = 1;

  for (cert = db.certs; cert != NULL; cert = cert->next, cert_num++)
    print_certificate (cert, cert_num);

  if (append_key_mgmt == false)
    return GRUB_ERR_NONE;

  for (i = 0; i < db.hash_entries; i++)
    {
      if (db.hashes[i] != NULL)
        {
          grub_printf ("\nBinary hash: %u\n", i + 1);
          grub_printf ("    Hash: sha%" PRIuGRUB_SIZE "\n         ", db.hash_sizes[i] * 8);
          hexdump_colon (db.hashes[i], db.hash_sizes[i]);
        }
    }

  return GRUB_ERR_NONE;
}

/* Add the X.509 certificates/binary hash to the db list from PKS. */
static grub_err_t
load_pks2db (void)
{
  grub_err_t rc;
  grub_uint32_t i;

  for (i = 0; i < pks_keystore->db_entries; i++)
    {
      if (is_hash (&pks_keystore->db[i].guid) == true)
        {
          rc = add_hash (pks_keystore->db[i].data,
                         pks_keystore->db[i].data_size, &db);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_x509 (&pks_keystore->db[i].guid) == true)
        {
          rc = add_certificate (pks_keystore->db[i].data,
                                pks_keystore->db[i].data_size, &db);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipped (%u)\n", i + 1);
    }

  return GRUB_ERR_NONE;
}

/* Add the certificates and certificate/binary hash to the dbx list from PKS. */
static grub_err_t
load_pks2dbx (void)
{
  grub_err_t rc;
  grub_uint32_t i;

  for (i = 0; i < pks_keystore->dbx_entries; i++)
    {
      if (is_x509 (&pks_keystore->dbx[i].guid) == true)
        {
          rc = add_certificate (pks_keystore->dbx[i].data,
                                pks_keystore->dbx[i].data_size, &dbx);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_hash (&pks_keystore->dbx[i].guid) == true)
        {
          rc = add_hash (pks_keystore->dbx[i].data,
                         pks_keystore->dbx[i].data_size, &dbx);
          if (rc != GRUB_ERR_NONE)
            return rc;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipped (%u)\n", i + 1);
    }

  return GRUB_ERR_NONE;
}

/*
 * Extract the X.509 certificates from the ELF Note header, parse it, and add
 * it to the db list.
 */
static void
load_elf2db (void)
{
  grub_err_t err;
  struct grub_module_header *header;
  struct grub_file pseudo_file;
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  FOR_MODULES (header)
    {
      /* Not an X.509 certificate, skip. */
      if (header->type != OBJ_TYPE_X509_PUBKEY)
        continue;

      grub_memset (&pseudo_file, 0, sizeof (pseudo_file));
      pseudo_file.fs = &pseudo_fs;
      pseudo_file.size = header->size - sizeof (struct grub_module_header);
      pseudo_file.data = (char *) header + sizeof (struct grub_module_header);

      grub_dprintf ("appendedsig", "found an X.509 certificate, size=%" PRIuGRUB_UINT64_T "\n",
                    pseudo_file.size);

      err = file_read_whole (&pseudo_file, &cert_data, &cert_data_size);
      if (err == GRUB_ERR_OUT_OF_MEMORY)
        return;
      else if (err != GRUB_ERR_NONE)
        continue;

      err = add_certificate (cert_data, cert_data_size, &db);
      grub_free (cert_data);
      if (err == GRUB_ERR_OUT_OF_MEMORY)
        return;
    }
}

/*
 * Extract trusted and distrusted keys from PKS and store them in the db and
 * dbx list.
 */
static void
create_dbs_from_pks (void)
{
  grub_err_t err;

  err = load_pks2dbx ();
  if (err != GRUB_ERR_NONE)
    grub_printf ("warning: dbx list might not be fully populated\n");

  /*
   * If db does not exist in the PKS storage, then read the static keys as a db
   * default keys from the GRUB ELF Note and add them into the db list.
   */
  if (pks_keystore->db_exists == false)
    load_elf2db ();
  else
    {
      err = load_pks2db ();
      if (err != GRUB_ERR_NONE)
        grub_printf ("warning: db list might not be fully populated\n");
    }

  grub_pks_free_data ();
  grub_dprintf ("appendedsig", "the db list now has %u keys\n"
                "the dbx list now has %u keys\n",
                db.hash_entries + db.cert_entries,
                dbx.hash_entries + dbx.cert_entries);
}

/* Free db list memory */
static void
free_db_list (void)
{
  grub_x509_cert_t *cert;
  grub_uint32_t i;

  while (db.certs != NULL)
    {
      cert = db.certs;
      db.certs = db.certs->next;
      grub_x509_cert_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < db.hash_entries; i++)
    grub_free (db.hashes[i]);

  grub_free (db.hashes);
  grub_free (db.hash_sizes);
  grub_memset (&db, 0, sizeof (sb_database_t));
}

/* Free dbx list memory */
static void
free_dbx_list (void)
{
  grub_x509_cert_t *cert;
  grub_uint32_t i;

  while (dbx.certs != NULL)
    {
      cert = dbx.certs;
      dbx.certs = dbx.certs->next;
      grub_x509_cert_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < dbx.hash_entries; i++)
    grub_free (dbx.hashes[i]);

  grub_free (dbx.hashes);
  grub_free (dbx.hash_sizes);
  grub_memset (&dbx, 0, sizeof (sb_database_t));
}

static const char *
grub_env_read_sec (struct grub_env_var *var __attribute__ ((unused)),
                   const char *val __attribute__ ((unused)))
{
  if (check_sigs == true)
    return "yes";

  return "no";
}

static char *
grub_env_write_sec (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  char *ret;

  /*
   * Do not allow the value to be changed if signature verification is enabled
   * (check_sigs is set to true) and GRUB is locked down.
   */
  if (check_sigs == true && grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    {
      ret = grub_strdup ("yes");
      if (ret == NULL)
        grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string enforce");

      return ret;
    }

  if (grub_strcmp (val, "yes") == 0)
    check_sigs = true;
  else if (grub_strcmp (val, "no") == 0)
    check_sigs = false;

  ret = grub_strdup (grub_env_read_sec (NULL, NULL));
  if (ret == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string %s",
                grub_env_read_sec (NULL, NULL));

  return ret;
}

static const char *
grub_env_read_key_mgmt (struct grub_env_var *var __attribute__ ((unused)),
                        const char *val __attribute__ ((unused)))
{
  if (append_key_mgmt == true)
    return "dynamic";

  return "static";
}

static char *
grub_env_write_key_mgmt (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  char *ret;

  /*
   * Do not allow the value to be changed if signature verification is enabled
   * (check_sigs is set to true) and GRUB is locked down.
   */
  if (check_sigs == true && grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    {
      ret = grub_strdup (grub_env_read_key_mgmt (NULL, NULL));
      if (ret == NULL)
        grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

      return ret;
    }

  if (grub_strcmp (val, "dynamic") == 0)
    append_key_mgmt = true;
  else if (grub_strcmp (val, "static") == 0)
    append_key_mgmt = false;

  ret = grub_strdup (grub_env_read_key_mgmt (NULL, NULL));
  if (ret == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  return ret;
}

static grub_err_t
appendedsig_init (grub_file_t io __attribute__ ((unused)), enum grub_file_type type,
                  void **context __attribute__ ((unused)), enum grub_verify_flags *flags)
{
  if (check_sigs == false)
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
      case GRUB_FILE_TYPE_LINUX_KERNEL:
      case GRUB_FILE_TYPE_GRUB_MODULE:
        /*
         * Appended signatures are only defined for ELF binaries. Out of an
         * abundance of caution, we only verify Linux kernels and GRUB modules
         * at this point.
         */
        *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
        return GRUB_ERR_NONE;

      case GRUB_FILE_TYPE_ACPI_TABLE:
      case GRUB_FILE_TYPE_DEVICE_TREE_IMAGE:
        /*
         * It is possible to use appended signature verification without
         * lockdown - like the PGP verifier. When combined with an embedded
         * config file in a signed GRUB binary, this could still be a meaningful
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

static grub_command_t cmd_verify, cmd_list_db, cmd_dbx_cert, cmd_db_cert;

GRUB_MOD_INIT (appendedsig)
{
  grub_int32_t rc;

  /*
   * If secure boot is enabled with enforce mode and GRUB is locked down, enable
   * signature verification.
   */
  if (grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    check_sigs = true;

  /* If PKS keystore is available, use dynamic key management. */
  pks_keystore = grub_pks_get_keystore ();
  if (pks_keystore != NULL)
    append_key_mgmt = true;

  /*
   * This is appended signature verification environment variable. It is
   * automatically set to either "no" or "yes" based on the ’ibm,secure-boot’
   * device tree property.
   *
   * "no": No signature verification. This is the default.
   *
   * "yes": Enforce signature verification. When GRUB is locked down, user cannot
   *        change the value by setting the check_appended_signatures variable
   *        back to ‘no’
   */
  grub_register_variable_hook ("check_appended_signatures", grub_env_read_sec, grub_env_write_sec);
  grub_env_export ("check_appended_signatures");

  /*
   * This is appended signature key management environment variable. It is
   * automatically set to either "static" or "dynamic" based on the
   * Platform KeyStore.
   *
   * "static": Enforce static key management signature verification. This is
   *           the default. When the GRUB is locked down, user cannot change
   *           the value by setting the appendedsig_key_mgmt variable back to
   *           "dynamic".
   *
   * "dynamic": Enforce dynamic key management signature verification. When the
   *            GRUB is locked down, user cannot change the value by setting the
   *            appendedsig_key_mgmt variable back to "static".
   */
  grub_register_variable_hook ("appendedsig_key_mgmt", grub_env_read_key_mgmt, grub_env_write_key_mgmt);
  grub_env_export ("appendedsig_key_mgmt");

  rc = grub_asn1_init ();
  if (rc != ASN1_SUCCESS)
    grub_fatal ("error initing ASN.1 data structures: %d: %s\n", rc, asn1_strerror (rc));

  /*
   * If signature verification is enabled with the dynamic key management,
   * extract trusted and distrusted keys from PKS and store them in the db
   * and dbx list.
   */
  if (append_key_mgmt == true)
    create_dbs_from_pks ();
  /*
   * If signature verification is enabled with the static key management,
   * extract trusted keys from ELF Note and store them in the db list.
   */
  else
    {
      load_elf2db ();
      grub_dprintf ("appendedsig", "the db list now has %u static keys\n",
                    db.cert_entries);
    }

  cmd_verify = grub_register_command ("append_verify", grub_cmd_verify_signature, N_("<SIGNED_FILE>"),
                                      N_("Verify SIGNED_FILE against the trusted X.509 certificates in the db list"));
  cmd_list_db = grub_register_command ("append_list_db", grub_cmd_list_db, 0,
                                       N_("Show the list of trusted X.509 certificates from the db list"));
  cmd_db_cert = grub_register_command ("append_add_db_cert", grub_cmd_db_cert, N_("<X509_CERTIFICATE>"),
                                       N_("Add trusted X509_CERTIFICATE to the db list"));
  cmd_dbx_cert = grub_register_command ("append_add_dbx_cert", grub_cmd_dbx_cert, N_("<X509_CERTIFICATE>"),
                                        N_("Add distrusted X509_CERTIFICATE to the dbx list"));

  grub_verifier_register (&grub_appendedsig_verifier);
  grub_dl_set_persistent (mod);
}

GRUB_MOD_FINI (appendedsig)
{
  /*
   * grub_dl_set_persistent should prevent this from actually running, but it
   * does still run under emu.
   */

  free_db_list ();
  free_dbx_list ();
  grub_register_variable_hook ("check_appended_signatures", NULL, NULL);
  grub_env_unset ("check_appended_signatures");
  grub_register_variable_hook ("appendedsig_key_mgmt", NULL, NULL);
  grub_env_unset ("appendedsig_key_mgmt");
  grub_verifier_unregister (&grub_appendedsig_verifier);
  grub_unregister_command (cmd_verify);
  grub_unregister_command (cmd_list_db);
  grub_unregister_command (cmd_db_cert);
  grub_unregister_command (cmd_dbx_cert);
}
