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

#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

const char magic[] = "~Module signature appended~\n";

/*
 * This structure is extracted from scripts/sign-file.c in the linux kernel
 * source. It was licensed as LGPLv2.1+, which is GPLv3+ compatible.
 */
struct module_signature
{
  grub_uint8_t algo;		/* Public-key crypto algorithm [0] */
  grub_uint8_t hash;		/* Digest algorithm [0] */
  grub_uint8_t id_type;		/* Key identifier type [PKEY_ID_PKCS7] */
  grub_uint8_t signer_len;	/* Length of signer's name [0] */
  grub_uint8_t key_id_len;	/* Length of key identifier [0] */
  grub_uint8_t __pad[3];
  grub_uint32_t sig_len;	/* Length of signature data */
} GRUB_PACKED;


/* This represents an entire, parsed, appended signature */
struct grub_appended_signature
{
  grub_size_t signature_len;		/* Length of PKCS#7 data +
                                         * metadata + magic */

  struct module_signature sig_metadata;	/* Module signature metadata */
  struct pkcs7_signedData pkcs7;	/* Parsed PKCS#7 data */
};

/* Trusted certificates for verifying appended signatures */
struct x509_certificate *grub_trusted_key;

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

static int check_sigs = 0;

static char *
grub_env_write_sec (struct grub_env_var *var __attribute__((unused)),
		    const char *val)
{
  if (check_sigs == 2)
    return grub_strdup ("forced");
  check_sigs = (*val == '1') || (*val == 'e');
  return grub_strdup (check_sigs ? "enforce" : "no");
}

static const char *
grub_env_read_sec (struct grub_env_var *var __attribute__ ((unused)),
                         const char *val __attribute__ ((unused)))
{
  if (check_sigs == 2)
    return "forced";
  else if (check_sigs == 1)
    return "enforce";
  else
    return "no";
}

static grub_err_t
read_cert_from_file (grub_file_t f, struct x509_certificate *certificate)
{
  grub_err_t err;
  grub_uint8_t *buf = NULL;
  grub_ssize_t read_size;
  grub_off_t total_read_size = 0;
  grub_off_t file_size = grub_file_size (f);


  if (file_size == GRUB_FILE_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("Cannot parse a certificate file of unknown size"));

  buf = grub_zalloc (file_size);
  if (!buf)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("Could not allocate buffer for certificate file contents"));

  while (total_read_size < file_size)
    {
      read_size =
	grub_file_read (f, &buf[total_read_size],
			file_size - total_read_size);
      if (read_size < 0)
	{
	  err = grub_error (GRUB_ERR_READ_ERROR,
			    N_("Error reading certificate file"));
	  goto cleanup_buf;
	}
      total_read_size += read_size;
    }

  err = certificate_import (buf, total_read_size, certificate);
  if (err != GRUB_ERR_NONE)
    goto cleanup_buf;

  return GRUB_ERR_NONE;

cleanup_buf:
  grub_free (buf);
  return err;
}

static grub_err_t
extract_appended_signature (grub_uint8_t * buf, grub_size_t bufsize,
			    struct grub_appended_signature *sig)
{
  grub_err_t err;
  grub_size_t pkcs7_size;
  grub_size_t remaining_len;
  grub_uint8_t *appsigdata = buf + bufsize - grub_strlen (magic);

  if (bufsize < grub_strlen (magic))
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
		       N_("File too short for signature magic"));

  if (grub_memcmp (appsigdata, (grub_uint8_t *) magic, grub_strlen (magic)))
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
		       N_("Missing or invalid signature magic"));

  remaining_len = bufsize - grub_strlen (magic);

  if (remaining_len < sizeof (struct module_signature))
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
		       N_("File too short for signature metadata"));

  appsigdata -= sizeof (struct module_signature);

  /* extract the metadata */
  grub_memcpy (&(sig->sig_metadata), appsigdata,
	       sizeof (struct module_signature));

  remaining_len -= sizeof (struct module_signature);

  if (sig->sig_metadata.id_type != 2)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, N_("Wrong signature type"));

#ifdef GRUB_TARGET_WORDS_BIGENDIAN
  pkcs7_size = sig->sig_metadata.sig_len;
#else
  pkcs7_size = __builtin_bswap32 (sig->sig_metadata.sig_len);
#endif

  if (pkcs7_size > remaining_len)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
		       N_("File too short for PKCS#7 message"));

  grub_dprintf ("appendedsig", "sig len %" PRIuGRUB_SIZE "\n", pkcs7_size);

  sig->signature_len =
    grub_strlen (magic) + sizeof (struct module_signature) + pkcs7_size;

  /* rewind pointer and parse pkcs7 data */
  appsigdata -= pkcs7_size;

  err = parse_pkcs7_signedData (appsigdata, pkcs7_size, &sig->pkcs7);
  if (err != GRUB_ERR_NONE)
    return err;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_verify_appended_signature (grub_uint8_t * buf, grub_size_t bufsize)
{
  grub_err_t err = GRUB_ERR_NONE;
  grub_size_t datasize;
  void *context;
  unsigned char *hash;
  gcry_mpi_t hashmpi;
  gcry_err_code_t rc;
  struct x509_certificate *pk;
  struct grub_appended_signature sig;

  if (!grub_trusted_key)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
		       N_("No trusted keys to verify against"));

  err = extract_appended_signature (buf, bufsize, &sig);
  if (err != GRUB_ERR_NONE)
    return err;

  datasize = bufsize - sig.signature_len;

  context = grub_zalloc (sig.pkcs7.hash->contextsize);
  if (!context)
    return grub_errno;

  sig.pkcs7.hash->init (context);
  sig.pkcs7.hash->write (context, buf, datasize);
  sig.pkcs7.hash->final (context);
  hash = sig.pkcs7.hash->read (context);
  grub_dprintf ("appendedsig",
		"data size %" PRIxGRUB_SIZE ", hash %02x%02x%02x%02x...\n",
		datasize, hash[0], hash[1], hash[2], hash[3]);

  err = GRUB_ERR_BAD_SIGNATURE;
  for (pk = grub_trusted_key; pk; pk = pk->next)
    {
      rc = grub_crypto_rsa_pad (&hashmpi, hash, sig.pkcs7.hash, pk->mpis[0]);
      if (rc)
	{
	  err = grub_error (GRUB_ERR_BAD_SIGNATURE,
			    N_("Error padding hash for RSA verification: %d"),
			    rc);
	  goto cleanup;
	}

      rc = _gcry_pubkey_spec_rsa.verify (0, hashmpi, &sig.pkcs7.sig_mpi,
					 pk->mpis, NULL, NULL);
      gcry_mpi_release (hashmpi);

      if (rc == 0)
	{
	  grub_dprintf ("appendedsig", "verify with key '%s' succeeded\n",
			pk->subject);
	  err = GRUB_ERR_NONE;
	  break;
	}

      grub_dprintf ("appendedsig", "verify with key '%s' failed with %d\n",
		    pk->subject, rc);
    }

  /* If we didn't verify, provide a neat message */
  if (err != GRUB_ERR_NONE)
      err = grub_error (GRUB_ERR_BAD_SIGNATURE,
			N_("Failed to verify signature against a trusted key"));

cleanup:
  grub_free (context);
  pkcs7_signedData_release (&sig.pkcs7);

  return err;
}

static grub_err_t
grub_cmd_verify_signature (grub_command_t cmd __attribute__((unused)),
			   int argc, char **args)
{
  grub_file_t f;
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint8_t *data;
  grub_ssize_t read_size;
  grub_off_t file_size, total_read_size = 0;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("one argument expected"));

  grub_dprintf ("appendedsig", "verifying %s\n", args[0]);

  f = grub_file_open (args[0], GRUB_FILE_TYPE_VERIFY_SIGNATURE);
  if (!f)
    {
      err = grub_errno;
      goto cleanup;
    }

  file_size = grub_file_size (f);
  if (file_size == GRUB_FILE_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("Cannot verify the signature of a file of unknown size"));

  data = grub_malloc (file_size);
  if (!data)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("Could not allocate data buffer size "
		       PRIuGRUB_UINT64_T " for verification"), file_size);

  while (total_read_size < file_size)
    {
      read_size =
	grub_file_read (f, &data[total_read_size],
			file_size - total_read_size);
      if (read_size < 0)
	{
	  err = grub_error (GRUB_ERR_READ_ERROR,
			    N_("Error reading file to verify"));
	  goto cleanup_data;
	}
      total_read_size += read_size;
    }

  err = grub_verify_appended_signature (data, file_size);

cleanup_data:
  grub_free (data);
cleanup:
  if (f)
    grub_file_close (f);
  return err;
}

static grub_err_t
grub_cmd_distrust (grub_command_t cmd __attribute__((unused)),
		   int argc, char **args)
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
      cert = grub_trusted_key;
      grub_trusted_key = cert->next;

      certificate_release (cert);
      grub_free (cert);
      return GRUB_ERR_NONE;
    }
  i = 2;
  prev = grub_trusted_key;
  cert = grub_trusted_key->next;
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
		     N_("No certificate number %d found - only %d certificates in the store"),
		     cert_num, i - 1);
}

static grub_err_t
grub_cmd_trust (grub_command_t cmd __attribute__((unused)),
		int argc, char **args)
{
  grub_file_t certf;
  struct x509_certificate *cert = NULL;
  grub_err_t err;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("one argument expected"));

  certf = grub_file_open (args[0],
			  GRUB_FILE_TYPE_CERTIFICATE_TRUST
			  | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (!certf)
    return grub_errno;


  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (!cert)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("Could not allocate memory for certificate"));

  err = read_cert_from_file (certf, cert);
  grub_file_close (certf);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (cert);
      return err;
    }
  grub_dprintf ("appendedsig", "Loaded certificate with CN: %s\n",
		cert->subject);

  cert->next = grub_trusted_key;
  grub_trusted_key = cert;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_list (grub_command_t cmd __attribute__((unused)),
	       int argc __attribute__((unused)),
	       char **args __attribute__((unused)))
{
  struct x509_certificate *cert;
  int cert_num = 1;
  grub_size_t i;

  for (cert = grub_trusted_key; cert; cert = cert->next)
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
appendedsig_init (grub_file_t io, enum grub_file_type type,
		  void **context __attribute__((unused)),
		  enum grub_verify_flags *flags)
{
  const char *dangerous_mod;

  if (!check_sigs)
    {
      *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
      return GRUB_ERR_NONE;
    }

  switch (type & GRUB_FILE_TYPE_MASK)
    {
    case GRUB_FILE_TYPE_GRUB_MODULE:
      if (grub_is_dangerous_module (io))
	return grub_error (GRUB_ERR_ACCESS_DENIED,
			   N_("module cannot be loaded in appended signature mode: %s"),
			   io->name);

      *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
      return GRUB_ERR_NONE;

    case GRUB_FILE_TYPE_ACPI_TABLE:
    case GRUB_FILE_TYPE_DEVICE_TREE_IMAGE:
      *flags = GRUB_VERIFY_FLAGS_DEFER_AUTH;
      return GRUB_ERR_NONE;

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
    case GRUB_FILE_TYPE_MULTIBOOT_KERNEL:
    case GRUB_FILE_TYPE_BSD_KERNEL:
    case GRUB_FILE_TYPE_XNU_KERNEL:
    case GRUB_FILE_TYPE_PLAN9_KERNEL:

      dangerous_mod = grub_dangerous_module_loaded ();
      if (dangerous_mod)
	return grub_error (GRUB_ERR_ACCESS_DENIED,
			   N_("cannot proceed due to dangerous module in memory: %s"),
			   dangerous_mod);

      *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
      return GRUB_ERR_NONE;

    default:
      /*
       * powerpc only supports the linux loader. If you support more,
       * (especially chain loaded binaries) make sure they're checked!
       */
      *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
      return GRUB_ERR_NONE;
    }
}

static grub_err_t
appendedsig_write (void *ctxt __attribute__((unused)),
		   void *buf, grub_size_t size)
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
static struct grub_fs pseudo_fs = {
  .name = "pseudo",
  .fs_read = pseudo_read
};

static grub_command_t cmd_verify, cmd_list, cmd_distrust, cmd_trust;

GRUB_MOD_INIT (appendedsig)
{
  int rc;
  struct grub_module_header *header;
  const char *val;

  val = grub_env_get ("check_appended_signatures");
  grub_dprintf ("appendedsig", "check_appended_signatures='%s'\n", val);

  if (val)
  {
    if (val[0] == '2' || val[0] == 'f')
      check_sigs = 2;
    else if (val[0] == '1' || val[0] == 'e')
      check_sigs = 1;
    else
      check_sigs = 0;
  }

  grub_trusted_key = NULL;

  grub_register_variable_hook ("check_appended_signatures",
  			       grub_env_read_sec,
			       grub_env_write_sec);
  grub_env_export ("check_appended_signatures");

  rc = asn1_init ();
  if (rc)
    grub_fatal ("Error initing ASN.1 data structures: %d: %s\n", rc,
		asn1_strerror (rc));

  FOR_MODULES (header)
  {
    struct grub_file pseudo_file;
    struct x509_certificate *pk = NULL;
    grub_err_t err;

    /* Not an ELF module, skip.  */
    if (header->type != OBJ_TYPE_X509_PUBKEY)
      continue;

    grub_memset (&pseudo_file, 0, sizeof (pseudo_file));
    pseudo_file.fs = &pseudo_fs;
    pseudo_file.size = header->size - sizeof (struct grub_module_header);
    pseudo_file.data = (char *) header + sizeof (struct grub_module_header);

    grub_dprintf ("appendedsig",
		  "Found an x509 key, size=%" PRIuGRUB_UINT64_T "\n",
		  pseudo_file.size);

    pk = grub_zalloc (sizeof (struct x509_certificate));
    if (!pk)
      {
	grub_fatal ("Out of memory loading initial certificates");
      }

    err = read_cert_from_file (&pseudo_file, pk);
    if (err != GRUB_ERR_NONE)
      grub_fatal ("Error loading initial key: %s", grub_errmsg);

    grub_dprintf ("appendedsig", "loaded certificate CN='%s'\n", pk->subject);

    pk->next = grub_trusted_key;
    grub_trusted_key = pk;
  }

  /*
   * When controlled by ibm,secure-boot, we don't want the presence of
   * a certificate to enforce secure boot.
   * if (!val || val[0] == '\0')
   * {
   *    grub_env_set ("check_appended_signatures",
   *		      grub_trusted_key ? "enforce" : "no");
   * }
   */

  cmd_trust =
    grub_register_command ("trust_certificate", grub_cmd_trust,
			   N_("X509_CERTIFICATE"),
			   N_("Add X509_CERTIFICATE to trusted certificates."));
  cmd_list =
    grub_register_command ("list_certificates", grub_cmd_list, 0,
			   N_("Show the list of trusted x509 certificates."));
  cmd_verify =
    grub_register_command ("verify_appended", grub_cmd_verify_signature,
			   N_("FILE"),
			   N_("Verify FILE against the trusted x509 certificates."));
  cmd_distrust =
    grub_register_command ("distrust_certificate", grub_cmd_distrust,
			   N_("CERT_NUMBER"),
			   N_("Remove CERT_NUMBER (as listed by list_certificates) from trusted certificates."));

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
