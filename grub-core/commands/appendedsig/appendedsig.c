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

#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Public key type. */
#define PKEY_ID_PKCS7      2

/* Appended signature magic string and size. */
#define SIG_MAGIC          "~Module signature appended~\n"
#define SIG_MAGIC_SIZE     ((sizeof(SIG_MAGIC) - 1))

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
};
typedef struct sb_database sb_database_t;

/* The db list is used to validate appended signatures. */
static sb_database_t db = {.certs = NULL, .cert_entries = 0};

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

/* Check the certificate presence in the db list. */
static bool
check_cert_presence (const grub_x509_cert_t *cert_in, const sb_database_t *sb_database)
{
  grub_x509_cert_t *cert;

  for (cert = sb_database->certs; cert != NULL; cert = cert->next)
    if (is_cert_match (cert, cert_in) == true)
      return true;

  return false;
}

/* Add the certificate into the db list */
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
      grub_dprintf ("appendedsig", "cannot add a certificate CN='%s' to the db list\n",
                    cert->subject);
      grub_free (cert);
      return rc;
    }

  if (check_cert_presence (cert, sb_database) == true)
    {
      grub_dprintf ("appendedsig",
                    "cannot add a certificate CN='%s', as it is present in the db list",
                    cert->subject);
      grub_x509_cert_release (cert);
      grub_free (cert);

      return GRUB_ERR_EXISTS;
    }

  grub_dprintf ("appendedsig", "added a certificate CN='%s' to the db list\n",
                cert->subject);

  cert->next = sb_database->certs;
  sb_database->certs = cert;
  sb_database->cert_entries++;

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

  if (!db.cert_entries)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "no trusted keys to verify against");

  err = extract_appended_signature (buf, bufsize, &sig);
  if (err != GRUB_ERR_NONE)
    return err;

  datasize = bufsize - sig.signature_len;

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

/* Free db list memory */
static void
free_db_list (void)
{
  grub_x509_cert_t *cert;

  while (db.certs != NULL)
    {
      cert = db.certs;
      db.certs = db.certs->next;
      grub_x509_cert_release (cert);
      grub_free (cert);
    }

  grub_memset (&db, 0, sizeof (sb_database_t));
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

  /* Extract trusted keys from ELF Note and store them in the db. */
  load_elf2db ();
  grub_dprintf ("appendedsig", "the db list now has %u static keys\n",
                db.cert_entries);

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
  grub_register_variable_hook ("check_appended_signatures", NULL, NULL);
  grub_env_unset ("check_appended_signatures");
  grub_register_variable_hook ("appendedsig_key_mgmt", NULL, NULL);
  grub_env_unset ("appendedsig_key_mgmt");
  grub_verifier_unregister (&grub_appendedsig_verifier);
}
