/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Microsoft Corporation
 *  Copyright (C) 2024 Free Software Foundation, Inc.
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

#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/file.h>
#include <grub/list.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/key_protector.h>

#include <tss2_buffer.h>
#include <tss2_types.h>
#include <tss2_mu.h>

#include "tpm2_args.h"
#include "tpm2.h"
#include "tpm2key.h"

GRUB_MOD_LICENSE ("GPLv3+");

typedef enum tpm2_protector_mode
{
  TPM2_PROTECTOR_MODE_UNSET,
  TPM2_PROTECTOR_MODE_SRK,
  TPM2_PROTECTOR_MODE_NV
} tpm2_protector_mode_t;

typedef enum tpm2_protector_options
{
  OPTION_MODE,
  OPTION_PCRS,
  OPTION_BANK,
  OPTION_TPM2KEY,
  OPTION_KEYFILE,
  OPTION_SRK,
  OPTION_ASYMMETRIC,
  OPTION_NVINDEX
} tpm2_protector_options_t;

typedef struct tpm2_protector_context
{
  tpm2_protector_mode_t mode;
  grub_uint8_t pcrs[TPM_MAX_PCRS];
  grub_uint8_t pcr_count;
  grub_srk_type_t srk_type;
  TPM_ALG_ID_t bank;
  const char *tpm2key;
  const char *keyfile;
  TPM_HANDLE_t srk;
  TPM_HANDLE_t nv;
} tpm2_protector_context_t;

static const struct grub_arg_option tpm2_protector_init_cmd_options[] =
  {
    /* Options for all modes */
    {
      .longarg  = "mode",
      .shortarg = 'm',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Unseal key using SRK ('srk') (default) or retrieve it from an NV "
	   "Index ('nv')."),
    },
    {
      .longarg  = "pcrs",
      .shortarg = 'p',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Comma-separated list of PCRs used to authorize key release "
	   "e.g., '7,11'. (default: 7)"),
    },
    {
      .longarg  = "bank",
      .shortarg = 'b',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Bank of PCRs used to authorize key release: "
	   "SHA1, SHA256, SHA384 or SHA512. (default: SHA256)"),
    },
    /* SRK-mode options */
    {
      .longarg  = "tpm2key",
      .shortarg = 'T',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("In SRK mode, path to the key file in the TPM 2.0 Key File format "
	   "to unseal using the TPM (e.g., (hd0,gpt1)/boot/grub2/sealed.tpm)."),
    },
    {
      .longarg  = "keyfile",
      .shortarg = 'k',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("In SRK mode, path to the key file in the raw format to unseal "
	   "using the TPM (e.g., (hd0,gpt1)/boot/grub2/sealed.key). "
	   "(Mainly for backward compatibility. Please use '--tpm2key'.)"),
    },
    {
      .longarg  = "srk",
      .shortarg = 's',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("In SRK mode, the SRK handle if the SRK is persistent."),
    },
    {
      .longarg  = "asymmetric",
      .shortarg = 'a',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("In SRK mode, the type of SRK: RSA (RSA2048) and ECC (ECC_NIST_P256)"
	   "(default: ECC)"),
    },
    /* NV Index-mode options */
    {
      .longarg  = "nvindex",
      .shortarg = 'n',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Required in NV Index mode, the NV handle to read which must "
	   "readily exist on the TPM and which contains the key."),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

static grub_extcmd_t tpm2_protector_init_cmd;
static grub_extcmd_t tpm2_protector_clear_cmd;
static tpm2_protector_context_t tpm2_protector_ctx = {0};

static grub_err_t
tpm2_protector_srk_read_file (const char *filepath, void **buffer, grub_size_t *buffer_size)
{
  grub_file_t file;
  grub_off_t file_size;
  void *read_buffer;
  grub_off_t read_n;
  grub_err_t err;

  /*
   * Using GRUB_FILE_TYPE_SIGNATURE ensures we do not hash the keyfile into PCR9
   * otherwise we'll never be able to predict the value of PCR9 at unseal time
   */
  file = grub_file_open (filepath, GRUB_FILE_TYPE_SIGNATURE);
  if (file == NULL)
    {
      /* Push errno from grub_file_open() into the error message stack */
      grub_error_push();
      err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("could not open file: %s"), filepath);
      goto error;
    }

  file_size = grub_file_size (file);
  if (file_size == 0)
    {
      err = grub_error (GRUB_ERR_OUT_OF_RANGE, N_("could not read file size: %s"), filepath);
      goto error;
    }

  read_buffer = grub_malloc (file_size);
  if (read_buffer == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("could not allocate buffer for %s"), filepath);
      goto error;
    }

  read_n = grub_file_read (file, read_buffer, file_size);
  if (read_n != file_size)
    {
      grub_free (read_buffer);
      err = grub_error (GRUB_ERR_FILE_READ_ERROR, N_("could not retrieve file contents: %s"), filepath);
      goto error;
    }

  *buffer = read_buffer;
  *buffer_size = file_size;

  err = GRUB_ERR_NONE;

 error:
  if (file != NULL)
    grub_file_close (file);

  return err;
}

static grub_err_t
tpm2_protector_srk_unmarshal_keyfile (void *sealed_key,
				      grub_size_t sealed_key_size,
				      tpm2_sealed_key_t *sk)
{
  struct grub_tpm2_buffer buf;

  grub_tpm2_buffer_init (&buf);
  if (sealed_key_size > buf.cap)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("sealed key larger than %llu bytes"), (unsigned long long)buf.cap);

  grub_memcpy (buf.data, sealed_key, sealed_key_size);
  buf.size = sealed_key_size;

  grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (&buf, &sk->public);
  grub_Tss2_MU_TPM2B_PRIVATE_Unmarshal (&buf, &sk->private);

  if (buf.error != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("malformed TPM wire key file"));

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2_protector_srk_unmarshal_tpm2key (void *sealed_key,
				      grub_size_t sealed_key_size,
				      tpm2key_policy_t *policy_seq,
				      tpm2key_authpolicy_t *authpol_seq,
				      grub_uint8_t *rsaparent,
				      grub_uint32_t *parent,
				      tpm2_sealed_key_t *sk)
{
  asn1_node tpm2key = NULL;
  grub_uint8_t rsaparent_tmp;
  grub_uint32_t parent_tmp;
  void *sealed_pub = NULL;
  grub_size_t sealed_pub_size;
  void *sealed_priv = NULL;
  grub_size_t sealed_priv_size;
  struct grub_tpm2_buffer buf;
  grub_err_t err;

  /*
   * Start to parse the tpm2key file
   * TPMKey ::= SEQUENCE {
   *     type        OBJECT IDENTIFIER,
   *     emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
   *     policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
   *     secret      [2] EXPLICIT OCTET STRING OPTIONAL,
   *     authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
   *     description [4] EXPLICIT UTF8String OPTIONAL,
   *     rsaParent   [5] EXPLICIT BOOLEAN OPTIONAL,
   *     parent      INTEGER,
   *     pubkey      OCTET STRING,
   *     privkey     OCTET STRING
   * }
   */
  err = grub_tpm2key_start_parsing (&tpm2key, sealed_key, sealed_key_size);
  if (err != GRUB_ERR_NONE)
    return err;

  /*
   * Retrieve the policy sequence from 'policy'
   * policy_seq will be NULL when 'policy' is not available
   */
  err = grub_tpm2key_get_policy_seq (tpm2key, policy_seq);
  if (err != GRUB_ERR_NONE)
    goto error;

  /*
   * Retrieve the authpolicy sequence from 'authPolicy'
   * authpol_seq will be NULL when 'authPolicy' is not available
   */
  err = grub_tpm2key_get_authpolicy_seq (tpm2key, authpol_seq);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Retrieve rsaParent */
  err = grub_tpm2key_get_rsaparent (tpm2key, &rsaparent_tmp);
  if (err != GRUB_ERR_NONE)
    goto error;

  *rsaparent = rsaparent_tmp;

  /* Retrieve the parent handle */
  err = grub_tpm2key_get_parent (tpm2key, &parent_tmp);
  if (err != GRUB_ERR_NONE)
    goto error;

  /*  The parent handle should be either PERMANENT or PERSISTENT. */
  if (!TPM_HT_IS_PERMANENT (parent_tmp) && !TPM_HT_IS_PERSISTENT (parent_tmp))
    {
      err = GRUB_ERR_OUT_OF_RANGE;
      goto error;
    }

  *parent = parent_tmp;

  /* Retrieve the public part of the sealed key */
  err = grub_tpm2key_get_pubkey (tpm2key, &sealed_pub, &sealed_pub_size);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Retrieve the private part of the sealed key */
  err = grub_tpm2key_get_privkey (tpm2key, &sealed_priv, &sealed_priv_size);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Unmarshal the sealed key */
  grub_tpm2_buffer_init (&buf);
  if (sealed_pub_size + sealed_priv_size > buf.cap)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("sealed key larger than %llu bytes"), (unsigned long long)buf.cap);
      goto error;
    }

  grub_tpm2_buffer_pack (&buf, sealed_pub, sealed_pub_size);
  grub_tpm2_buffer_pack (&buf, sealed_priv, sealed_priv_size);

  buf.offset = 0;

  grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (&buf, &sk->public);
  grub_Tss2_MU_TPM2B_PRIVATE_Unmarshal (&buf, &sk->private);

  if (buf.error != 0)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("malformed TPM 2.0 key file"));
      goto error;
    }

  err = GRUB_ERR_NONE;

 error:
  /* End the parsing */
  grub_tpm2key_end_parsing (tpm2key);
  grub_free (sealed_pub);
  grub_free (sealed_priv);

  return err;
}

/* Check if the SRK exists in the specified handle */
static grub_err_t
tpm2_protector_srk_check (const TPM_HANDLE_t srk_handle)
{
  TPM_RC_t rc;
  TPM2B_PUBLIC_t public;

  /* Find SRK */
  rc = grub_tpm2_readpublic (srk_handle, NULL, &public);
  if (rc == TPM_RC_SUCCESS)
    return GRUB_ERR_NONE;

  return grub_error (GRUB_ERR_BAD_ARGUMENT, "failed to retrieve SRK from 0x%x (TPM2_ReadPublic: 0x%x)", srk_handle, rc);
}

/* Get the SRK with the template */
static grub_err_t
tpm2_protector_srk_get (const grub_srk_type_t srk_type,
			const TPM_HANDLE_t parent,
			TPM_HANDLE_t *srk_handle)
{
  TPM_RC_t rc;
  TPMT_PUBLIC_PARMS_t parms = {0};
  TPMS_AUTH_COMMAND_t authCommand = {0};
  TPM2B_SENSITIVE_CREATE_t inSensitive = {0};
  TPM2B_PUBLIC_t inPublic = {0};
  TPM2B_DATA_t outsideInfo = {0};
  TPML_PCR_SELECTION_t creationPcr = {0};
  TPM2B_PUBLIC_t outPublic = {0};
  TPM2B_CREATION_DATA_t creationData = {0};
  TPM2B_DIGEST_t creationHash = {0};
  TPMT_TK_CREATION_t creationTicket = {0};
  TPM2B_NAME_t srkName = {0};
  TPM_HANDLE_t tmp_handle = 0;

  inPublic.publicArea.type = srk_type.type;
  inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
  inPublic.publicArea.objectAttributes.restricted = 1;
  inPublic.publicArea.objectAttributes.userWithAuth = 1;
  inPublic.publicArea.objectAttributes.decrypt = 1;
  inPublic.publicArea.objectAttributes.fixedTPM = 1;
  inPublic.publicArea.objectAttributes.fixedParent = 1;
  inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
  inPublic.publicArea.objectAttributes.noDA = 1;

  if (srk_type.type == TPM_ALG_RSA)
    {
      inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.rsaDetail.keyBits = srk_type.detail.rsa_bits;
      inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    }
  else if (srk_type.type == TPM_ALG_ECC)
    {
      inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.eccDetail.curveID = srk_type.detail.ecc_curve;
      inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    }
  else
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "unknown SRK algorithm");

  /* Test the parameters before SRK generation */
  parms.type = srk_type.type;
  grub_memcpy (&parms.parameters, &inPublic.publicArea.parameters,
	       sizeof (TPMU_PUBLIC_PARMS_t));

  rc = grub_tpm2_testparms (&parms, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "unsupported SRK template (TPM2_TestParms: 0x%x)", rc);

  /* Create SRK */
  authCommand.sessionHandle = TPM_RS_PW;
  rc = grub_tpm2_createprimary (parent, &authCommand, &inSensitive, &inPublic,
				&outsideInfo, &creationPcr, &tmp_handle, &outPublic,
				&creationData, &creationHash, &creationTicket,
				&srkName, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, "could not create SRK (TPM2_CreatePrimary: 0x%x)", rc);

  *srk_handle = tmp_handle;

  return GRUB_ERR_NONE;
}

/*
 * Load the SRK from the persistent handle or create one with a given type of
 * template, and then associate the sealed key with the SRK
 * Return values:
 * - GRUB_ERR_NONE: Everything is fine.
 * - GRUB_ERR_BAD_ARGUMENT: The SRK doesn't match. Try another one.
 * - Other: Something went wrong.
 */
static grub_err_t
tpm2_protector_srk_load (const grub_srk_type_t srk_type,
			 const tpm2_sealed_key_t *sealed_key,
			 const TPM_HANDLE_t parent,
			 TPM_HANDLE_t *sealed_handle,
			 TPM_HANDLE_t *srk_handle)
{
  TPMS_AUTH_COMMAND_t authCmd = {0};
  TPM2B_NAME_t name = {0};
  TPM_RC_t rc;
  grub_err_t err;

  if (srk_handle == NULL)
    return GRUB_ERR_BUG;

  if (*srk_handle != 0)
    {
      err = tpm2_protector_srk_check (*srk_handle);
      if (err != GRUB_ERR_NONE)
	return err;
    }
  else
    {
      err = tpm2_protector_srk_get (srk_type, parent, srk_handle);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  /* Load the sealed key and associate it with the SRK */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = grub_tpm2_load (*srk_handle, &authCmd, &sealed_key->private, &sealed_key->public,
		       sealed_handle, &name, NULL);
  /*
   * If TPM2_Load returns (TPM_RC_INTEGRITY | TPM_RC_P | TPM_RC_1), then it
   * implies the wrong SRK is used.
   */
  if (rc == (TPM_RC_INTEGRITY | TPM_RC_P | TPM_RC_1))
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, "SRK not matched");
      goto error;
    }
  else if (rc != TPM_RC_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE, "failed to load sealed key (TPM2_Load: 0x%x)", rc);
      goto error;
    }

  return GRUB_ERR_NONE;

 error:
  if (!TPM_HT_IS_PERSISTENT (*srk_handle))
    grub_tpm2_flushcontext (*srk_handle);

  return err;
}

static const char *
srk_type_to_name (grub_srk_type_t srk_type)
{
  if (srk_type.type == TPM_ALG_ECC && srk_type.detail.ecc_curve == TPM_ECC_NIST_P256)
    return "ECC_NIST_P256";
  else if (srk_type.type == TPM_ALG_RSA && srk_type.detail.rsa_bits == 2048)
    return "RSA2048";

  return "Unknown";
}

static grub_err_t
tpm2_protector_load_key (const tpm2_protector_context_t *ctx,
			 const tpm2_sealed_key_t *sealed_key,
			 const TPM_HANDLE_t parent_handle,
			 TPM_HANDLE_t *sealed_handle,
			 TPM_HANDLE_t *srk_handle)
{
  grub_err_t err;
  int i;
  grub_srk_type_t fallback_srks[] = {
    {
      .type = TPM_ALG_ECC,
      .detail.ecc_curve = TPM_ECC_NIST_P256,
    },
    {
      .type = TPM_ALG_RSA,
      .detail.rsa_bits = 2048,
    },
    {
      .type = TPM_ALG_ERROR,
    }
  };

  /* Try the given persistent SRK if exists */
  if (*srk_handle != 0)
    {
      err = tpm2_protector_srk_load (ctx->srk_type, sealed_key,
				     parent_handle, sealed_handle,
				     srk_handle);
      if (err != GRUB_ERR_BAD_ARGUMENT)
	return err;

      grub_print_error ();
      grub_printf ("Trying the specified SRK algorithm: %s\n", srk_type_to_name (ctx->srk_type));
      grub_errno = GRUB_ERR_NONE;
      *srk_handle = 0;
    }

  /* Try the specified algorithm for the SRK template */
  if (*srk_handle == 0)
    {
      err = tpm2_protector_srk_load (ctx->srk_type, sealed_key,
				     parent_handle, sealed_handle,
				     srk_handle);
      if (err != GRUB_ERR_BAD_ARGUMENT)
	return err;

      grub_print_error ();
      grub_errno = GRUB_ERR_NONE;
      *srk_handle = 0;
    }

  /* Try all the fallback SRK templates */
  for (i = 0; fallback_srks[i].type != TPM_ALG_ERROR; i++)
    {
      /* Skip the specified algorithm */
      if (fallback_srks[i].type == ctx->srk_type.type &&
	  (fallback_srks[i].detail.rsa_bits == ctx->srk_type.detail.rsa_bits ||
	   fallback_srks[i].detail.ecc_curve == ctx->srk_type.detail.ecc_curve))
	continue;

      grub_printf ("Trying fallback %s template\n", srk_type_to_name (fallback_srks[i]));

      *srk_handle = 0;

      err = tpm2_protector_srk_load (fallback_srks[i], sealed_key,
				     parent_handle, sealed_handle,
				     srk_handle);
      if (err != GRUB_ERR_BAD_ARGUMENT)
	return err;

      grub_print_error ();
      grub_errno = GRUB_ERR_NONE;
  }

  return err;
}

static grub_err_t
tpm2_protector_policypcr (TPMI_SH_AUTH_SESSION_t session, struct grub_tpm2_buffer *cmd_buf)
{
  TPM2B_DIGEST_t pcr_digest;
  TPML_PCR_SELECTION_t pcr_sel;
  TPM_RC_t rc;

  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (cmd_buf, &pcr_digest);
  grub_Tss2_MU_TPML_PCR_SELECTION_Unmarshal (cmd_buf, &pcr_sel);
  if (cmd_buf->error != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "failed to unmarshal commandPolicy for TPM2_PolicyPCR");

  rc = grub_tpm2_policypcr (session, NULL, &pcr_digest, &pcr_sel, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, "failed to submit PCR policy (TPM2_PolicyPCR: 0x%x)", rc);

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2_protector_policyauthorize (TPMI_SH_AUTH_SESSION_t session, struct grub_tpm2_buffer *cmd_buf)
{
  TPM2B_PUBLIC_t pubkey;
  TPM2B_DIGEST_t policy_ref;
  TPMT_SIGNATURE_t signature;
  TPM2B_DIGEST_t pcr_policy;
  TPM2B_DIGEST_t pcr_policy_hash;
  TPMI_ALG_HASH_t sig_hash;
  TPMT_TK_VERIFIED_t verification_ticket;
  TPM_HANDLE_t pubkey_handle = 0;
  TPM2B_NAME_t pubname;
  TPM_RC_t rc;
  grub_err_t err;

  grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (cmd_buf, &pubkey);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (cmd_buf, &policy_ref);
  grub_Tss2_MU_TPMT_SIGNATURE_Unmarshal (cmd_buf, &signature);
  if (cmd_buf->error != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "failed to unmarshal the buffer for TPM2_PolicyAuthorize");

  /* Retrieve Policy Digest */
  rc = grub_tpm2_policygetdigest (session, NULL, &pcr_policy, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, "failed to get policy digest (TPM2_PolicyGetDigest: 0x%x).", rc);

  /* Calculate the digest of the polcy for VerifySignature */
  sig_hash = TPMT_SIGNATURE_get_hash_alg (&signature);
  if (sig_hash == TPM_ALG_NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "failed to get the hash algorithm of the signature");

  rc = grub_tpm2_hash (NULL, (TPM2B_MAX_BUFFER_t *) &pcr_policy, sig_hash,
		       TPM_RH_NULL, &pcr_policy_hash, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, "failed to create PCR policy hash (TPM2_Hash: 0x%x)", rc);

  /* Load the public key */
  rc = grub_tpm2_loadexternal (NULL, NULL, &pubkey, TPM_RH_OWNER, &pubkey_handle, &pubname, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, "failed to load public key (TPM2_LoadExternal: 0x%x)", rc);

  /* Verify the signature against the public key and the policy digest */
  rc = grub_tpm2_verifysignature (pubkey_handle, NULL, &pcr_policy_hash, &signature,
				  &verification_ticket, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE, "failed to verify signature (TPM2_VerifySignature: 0x%x)", rc);
      goto error;
    }

  /* Authorize the signed policy with the public key and the verification ticket */
  rc = grub_tpm2_policyauthorize (session, NULL, &pcr_policy, &policy_ref, &pubname,
				  &verification_ticket, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE, "failed to authorize PCR policy (TPM2_PolicyAuthorize: 0x%x)", rc);
      goto error;
    }

  err = GRUB_ERR_NONE;

 error:
  grub_tpm2_flushcontext (pubkey_handle);

  return err;
}

static grub_err_t
tpm2_protector_enforce_policy (tpm2key_policy_t policy, TPMI_SH_AUTH_SESSION_t session)
{
  struct grub_tpm2_buffer buf;
  grub_err_t err;

  grub_tpm2_buffer_init (&buf);
  if (policy->cmd_policy_len > buf.cap)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "CommandPolicy larger than TPM buffer");

  grub_memcpy (buf.data, policy->cmd_policy, policy->cmd_policy_len);
  buf.size = policy->cmd_policy_len;

  switch (policy->cmd_code)
    {
    case TPM_CC_PolicyPCR:
      err = tpm2_protector_policypcr (session, &buf);
      break;
    case TPM_CC_PolicyAuthorize:
      err = tpm2_protector_policyauthorize (session, &buf);
      break;
    default:
      return grub_error (GRUB_ERR_BAD_ARGUMENT, "unknown TPM Command: 0x%x", policy->cmd_code);
    }

  return err;
}

static grub_err_t
tpm2_protector_enforce_policy_seq (tpm2key_policy_t policy_seq, TPMI_SH_AUTH_SESSION_t session)
{
  tpm2key_policy_t policy;
  grub_err_t err;

  FOR_LIST_ELEMENTS (policy, policy_seq)
    {
      err = tpm2_protector_enforce_policy (policy, session);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2_protector_simple_policy_seq (const tpm2_protector_context_t *ctx,
				  tpm2key_policy_t *policy_seq)
{
  tpm2key_policy_t policy = NULL;
  struct grub_tpm2_buffer buf;
  TPML_PCR_SELECTION_t pcr_sel = {
    .count = 1,
    .pcrSelections = {
      {
	.hash = ctx->bank,
	.sizeOfSelect = 3,
	.pcrSelect = {0}
      },
    }
  };
  grub_uint8_t i;
  grub_err_t err;

  if (policy_seq == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  grub_tpm2_buffer_init (&buf);

  for (i = 0; i < ctx->pcr_count; i++)
    TPMS_PCR_SELECTION_SelectPCR (&pcr_sel.pcrSelections[0], ctx->pcrs[i]);

  grub_tpm2_buffer_pack_u16 (&buf, 0);
  grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (&buf, &pcr_sel);

  if (buf.error != 0)
    return GRUB_ERR_BAD_ARGUMENT;

  policy = grub_malloc (sizeof(struct tpm2key_policy));
  if (policy == NULL)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto error;
    }
  policy->cmd_code = TPM_CC_PolicyPCR;
  policy->cmd_policy = grub_malloc (buf.size);
  if (policy->cmd_policy == NULL)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto error;
    }
  grub_memcpy (policy->cmd_policy, buf.data, buf.size);
  policy->cmd_policy_len = buf.size;

  grub_list_push (GRUB_AS_LIST_P (policy_seq), GRUB_AS_LIST (policy));

  return GRUB_ERR_NONE;

 error:
  grub_free (policy);

  return err;
}

static grub_err_t
tpm2_protector_unseal (tpm2key_policy_t policy_seq, TPM_HANDLE_t sealed_handle,
		       grub_uint8_t **key, grub_size_t *key_size, bool *dump_pcr)
{
  TPMS_AUTH_COMMAND_t authCmd = {0};
  TPM2B_SENSITIVE_DATA_t data;
  TPM2B_NONCE_t nonceCaller = {0};
  TPMT_SYM_DEF_t symmetric = {0};
  TPMI_SH_AUTH_SESSION_t session;
  grub_uint8_t *key_out;
  TPM_RC_t rc;
  grub_err_t err;

  *dump_pcr = false;

  /* Start Auth Session */
  nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
  symmetric.algorithm = TPM_ALG_NULL;
  rc = grub_tpm2_startauthsession (TPM_RH_NULL, TPM_RH_NULL, NULL, &nonceCaller, NULL,
				   TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256,
				   &session, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE, "failed to start auth session (TPM2_StartAuthSession: 0x%x)", rc);

  /* Enforce the policy command sequence */
  err = tpm2_protector_enforce_policy_seq (policy_seq, session);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Unseal Sealed Key */
  authCmd.sessionHandle = session;
  rc = grub_tpm2_unseal (sealed_handle, &authCmd, &data, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      /*
       * Trigger PCR dump on policy fail
       * TPM_RC_S (0x800) | TPM_RC_1 (0x100) | RC_FMT (0x80) | TPM_RC_POLICY_FAIL (0x1D)
       */
      if (rc == 0x99D)
	*dump_pcr = true;

      err = grub_error (GRUB_ERR_BAD_DEVICE, "failed to unseal sealed key (TPM2_Unseal: 0x%x)", rc);
      goto error;
    }

  /* Epilogue */
  key_out = grub_malloc (data.size);
  if (key_out == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("no memory left to allocate unlock key buffer"));
      goto error;
    }

  grub_memcpy (key_out, data.buffer, data.size);

  *key = key_out;
  *key_size = data.size;

  err = GRUB_ERR_NONE;

 error:
  grub_tpm2_flushcontext (session);

  return err;
}

#define TPM_PCR_STR_SIZE (sizeof (TPMU_HA_t) * 2 + 1)

static grub_err_t
tpm2_protector_get_pcr_str (const TPM_ALG_ID_t algo, grub_uint32_t index, char *pcr_str, grub_uint16_t buf_size)
{
  TPML_PCR_SELECTION_t pcr_sel = {
    .count = 1,
    .pcrSelections = {
      {
	.hash = algo,
	.sizeOfSelect = 3,
	.pcrSelect = {0}
      },
    }
  };
  TPML_DIGEST_t digest = {0};
  grub_uint16_t i;
  TPM_RC_t rc;

  if (buf_size < TPM_PCR_STR_SIZE)
    {
      grub_snprintf (pcr_str, buf_size, "insufficient buffer");
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  TPMS_PCR_SELECTION_SelectPCR (&pcr_sel.pcrSelections[0], index);

  rc = grub_tpm2_pcr_read (NULL, &pcr_sel, NULL, NULL, &digest, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      grub_snprintf (pcr_str, buf_size, "TPM2_PCR_Read: 0x%x", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Check the returned digest number and size */
  if (digest.count != 1 || digest.digests[0].size > sizeof (TPMU_HA_t))
    {
      grub_snprintf (pcr_str, buf_size, "invalid digest");
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Print the digest to the buffer */
  for (i = 0; i < digest.digests[0].size; i++)
    grub_snprintf (pcr_str + 2 * i, buf_size - 2 * i, "%02x", digest.digests[0].buffer[i]);

  return GRUB_ERR_NONE;
}

static void
tpm2_protector_dump_pcr (const TPM_ALG_ID_t bank)
{
  const char *algo_name;
  char pcr_str[TPM_PCR_STR_SIZE];
  grub_uint8_t i;
  grub_err_t err;

  if (bank == TPM_ALG_SHA1)
    algo_name = "sha1";
  else if (bank == TPM_ALG_SHA256)
    algo_name = "sha256";
  else if (bank == TPM_ALG_SHA384)
    algo_name = "sha384";
  else if (bank == TPM_ALG_SHA512)
    algo_name = "sha512";
  else
    algo_name = "other";

  /* Try to fetch PCR 0 */
  err = tpm2_protector_get_pcr_str (bank, 0, pcr_str, sizeof (pcr_str));
  if (err != GRUB_ERR_NONE)
    {
      grub_printf ("Unsupported PCR bank [%s]: %s\n", algo_name, pcr_str);
      return;
    }

  grub_printf ("TPM PCR [%s]:\n", algo_name);

  grub_printf ("  %02d: %s\n", 0, pcr_str);
  for (i = 1; i < TPM_MAX_PCRS; i++)
    {
      tpm2_protector_get_pcr_str (bank, i, pcr_str, sizeof (pcr_str));
      grub_printf ("  %02d: %s\n", i, pcr_str);
    }
}

static grub_err_t
tpm2_protector_srk_recover (const tpm2_protector_context_t *ctx,
			    grub_uint8_t **key, grub_size_t *key_size)
{
  tpm2_sealed_key_t sealed_key = {0};
  void *file_bytes = NULL;
  grub_size_t file_size = 0;
  grub_uint8_t rsaparent = 0;
  TPM_HANDLE_t parent_handle = 0;
  TPM_HANDLE_t srk_handle = 0;
  TPM_HANDLE_t sealed_handle = 0;
  tpm2key_policy_t policy_seq = NULL;
  tpm2key_authpolicy_t authpol = NULL;
  tpm2key_authpolicy_t authpol_seq = NULL;
  bool dump_pcr = false;
  grub_err_t err;

  /*
   * Retrieve sealed key, parent handle, policy sequence, and authpolicy
   * sequence from the key file
  */
  if (ctx->tpm2key != NULL)
    {
      err = tpm2_protector_srk_read_file (ctx->tpm2key, &file_bytes,
					       &file_size);
      if (err != GRUB_ERR_NONE)
	return err;

      err = tpm2_protector_srk_unmarshal_tpm2key (file_bytes,
						  file_size,
						  &policy_seq,
						  &authpol_seq,
						  &rsaparent,
						  &parent_handle,
						  &sealed_key);
      if (err != GRUB_ERR_NONE)
	goto exit1;

      if (rsaparent == 1)
	{
	  tpm2_protector_context_t *ctx_w;

	  /* Overwrite the SRK type as noted in the key */
	  ctx_w = (tpm2_protector_context_t *)ctx;
	  ctx_w->srk_type.type = TPM_ALG_RSA;
	  ctx_w->srk_type.detail.rsa_bits = 2048;
	}
    }
  else
    {
      err = tpm2_protector_srk_read_file (ctx->keyfile, &file_bytes, &file_size);
      if (err != GRUB_ERR_NONE)
	return err;

      parent_handle = TPM_RH_OWNER;
      err = tpm2_protector_srk_unmarshal_keyfile (file_bytes, file_size, &sealed_key);
      if (err != GRUB_ERR_NONE)
	goto exit1;
    }

  /* Set the SRK handle if it is specified with '--srk' or inside the key file */
  if (ctx->srk != 0)
    srk_handle = ctx->srk;
  else if (TPM_HT_IS_PERSISTENT (parent_handle))
    srk_handle = parent_handle;

  /* Load the sealed key into TPM and associate it with the SRK */
  err = tpm2_protector_load_key (ctx, &sealed_key, parent_handle, &sealed_handle, &srk_handle);
  if (err != GRUB_ERR_NONE)
    goto exit1;

  /*
   * Set err to an error code to trigger the standalone policy sequence
   * if there is no authpolicy sequence
   */
  err = GRUB_ERR_READ_ERROR;

  /* Iterate the authpolicy sequence to find one that unseals the key */
  FOR_LIST_ELEMENTS (authpol, authpol_seq)
    {
      err = tpm2_protector_unseal (authpol->policy_seq, sealed_handle, key, key_size, &dump_pcr);
      if (err == GRUB_ERR_NONE)
        break;

      /*
       * Push the error message into the grub_error stack
       * Note: The grub_error stack may overflow if there are too many policy
       *       sequences. Anyway, we still can keep the error messages from
       *       the first few policy sequences which are usually most likely to
       *       unseal the key.
       */
      grub_error_push();
    }

  /* Give the standalone policy sequence a try */
  if (err != GRUB_ERR_NONE)
    {
      /*
       * Create a basic policy sequence based on the given PCR selection if the
       * key file doesn't provide one
       */
      if (policy_seq == NULL)
	{
	  err = tpm2_protector_simple_policy_seq (ctx, &policy_seq);
	  if (err != GRUB_ERR_NONE)
	    goto exit2;
	}

      err = tpm2_protector_unseal (policy_seq, sealed_handle, key, key_size, &dump_pcr);
    }

  /* Pop error messages on success */
  if (err == GRUB_ERR_NONE)
    while (grub_error_pop ());

  /* Dump PCRs if necessary */
  if (dump_pcr == true)
    {
      grub_printf ("PCR Mismatch! Check firmware and bootloader before typing passphrase!\n");
      tpm2_protector_dump_pcr (ctx->bank);
    }

 exit2:
  grub_tpm2_flushcontext (sealed_handle);

  if (!TPM_HT_IS_PERSISTENT (srk_handle))
    grub_tpm2_flushcontext (srk_handle);

 exit1:
  grub_tpm2key_free_policy_seq (policy_seq);
  grub_tpm2key_free_authpolicy_seq (authpol_seq);
  grub_free (file_bytes);
  return err;
}

static grub_err_t
tpm2_protector_nv_recover (const tpm2_protector_context_t *ctx,
			   grub_uint8_t **key, grub_size_t *key_size)
{
  TPM_HANDLE_t sealed_handle = ctx->nv;
  tpm2key_policy_t policy_seq = NULL;
  bool dump_pcr = false;
  grub_err_t err;

  /* Create a basic policy sequence based on the given PCR selection */
  err = tpm2_protector_simple_policy_seq (ctx, &policy_seq);
  if (err != GRUB_ERR_NONE)
    goto exit;

  err = tpm2_protector_unseal (policy_seq, sealed_handle, key, key_size, &dump_pcr);

  /* Dump PCRs if necessary */
  if (dump_pcr == true)
    {
      grub_printf ("PCR Mismatch! Check firmware and bootloader before typing passphrase!\n");
      tpm2_protector_dump_pcr (ctx->bank);
    }

 exit:
  grub_tpm2_flushcontext (sealed_handle);

  grub_tpm2key_free_policy_seq (policy_seq);

  return err;
}

static grub_err_t
tpm2_protector_recover (const tpm2_protector_context_t *ctx,
			grub_uint8_t **key, grub_size_t *key_size)
{
  switch (ctx->mode)
    {
    case TPM2_PROTECTOR_MODE_SRK:
      return tpm2_protector_srk_recover (ctx, key, key_size);
    case TPM2_PROTECTOR_MODE_NV:
      return tpm2_protector_nv_recover (ctx, key, key_size);
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }
}

static grub_err_t
tpm2_protector_recover_key (grub_uint8_t **key, grub_size_t *key_size)
{
  /* Expect a call to tpm2_protector_init before anybody tries to use us */
  if (tpm2_protector_ctx.mode == TPM2_PROTECTOR_MODE_UNSET)
    return grub_error (GRUB_ERR_INVALID_COMMAND, N_("cannot use TPM2 key protector without initializing it, call tpm2_protector_init first"));

  if (key == NULL || key_size == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  return tpm2_protector_recover (&tpm2_protector_ctx, key, key_size);
}

static grub_err_t
tpm2_protector_check_args (tpm2_protector_context_t *ctx)
{
  if (ctx->mode == TPM2_PROTECTOR_MODE_UNSET)
    ctx->mode = TPM2_PROTECTOR_MODE_SRK;

  /* Checks for SRK mode */
  if (ctx->mode == TPM2_PROTECTOR_MODE_SRK &&
      (ctx->keyfile == NULL && ctx->tpm2key == NULL))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("in SRK mode, a key file must be specified: --tpm2key/-T or --keyfile/-k"));

  if (ctx->mode == TPM2_PROTECTOR_MODE_SRK &&
      (ctx->keyfile != NULL && ctx->tpm2key != NULL))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("in SRK mode, please specify a key file with only --tpm2key/-T or --keyfile/-k"));

  if (ctx->mode == TPM2_PROTECTOR_MODE_SRK && ctx->nv != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("in SRK mode, an NV Index cannot be specified"));

  /* Checks for NV mode */
  if (ctx->mode == TPM2_PROTECTOR_MODE_NV && ctx->nv == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("in NV Index mode, an NV Index must be specified: --nvindex or -n"));

  if (ctx->mode == TPM2_PROTECTOR_MODE_NV &&
      (ctx->tpm2key != NULL || ctx->keyfile != NULL))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("in NV Index mode, a keyfile cannot be specified"));

  if (ctx->mode == TPM2_PROTECTOR_MODE_NV && ctx->srk != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("in NV Index mode, an SRK cannot be specified"));

  if (ctx->mode == TPM2_PROTECTOR_MODE_NV &&
      ctx->srk_type.type != TPM_ALG_ERROR)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("in NV Index mode, an asymmetric key type cannot be specified"));

  /* Defaults assignment */
  if (ctx->bank == TPM_ALG_ERROR)
    ctx->bank = TPM_ALG_SHA256;

  if (ctx->pcr_count == 0)
    {
      ctx->pcrs[0] = 7;
      ctx->pcr_count = 1;
    }

  if (ctx->mode == TPM2_PROTECTOR_MODE_SRK &&
      ctx->srk_type.type == TPM_ALG_ERROR)
    {
      ctx->srk_type.type = TPM_ALG_ECC;
      ctx->srk_type.detail.ecc_curve = TPM_ECC_NIST_P256;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2_protector_parse_file (const char *value, const char **file)
{
  if (grub_strlen (value) == 0)
    return GRUB_ERR_BAD_ARGUMENT;

  *file = grub_strdup (value);
  if (*file == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("no memory to duplicate file path"));

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2_protector_parse_mode (const char *value, tpm2_protector_mode_t *mode)
{
  if (grub_strcmp (value, "srk") == 0)
    *mode = TPM2_PROTECTOR_MODE_SRK;
  else if (grub_strcmp (value, "nv") == 0)
    *mode = TPM2_PROTECTOR_MODE_NV;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("value '%s' is not a valid TPM2 key protector mode"), value);

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2_protector_init_cmd_handler (grub_extcmd_context_t ctxt, int argc,
				 char **args __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;
  grub_err_t err;

  if (argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("the TPM2 key protector does not accept any non-option arguments (i.e., like -o and/or --option only)"));

  grub_free ((void *) tpm2_protector_ctx.keyfile);
  grub_memset (&tpm2_protector_ctx, 0, sizeof (tpm2_protector_ctx));

  if (state[OPTION_MODE].set)  /* mode */
    {
      err = tpm2_protector_parse_mode (state[OPTION_MODE].arg, &tpm2_protector_ctx.mode);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_PCRS].set)  /* pcrs */
    {
      err = grub_tpm2_protector_parse_pcrs (state[OPTION_PCRS].arg,
					    tpm2_protector_ctx.pcrs,
					    &tpm2_protector_ctx.pcr_count);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_BANK].set)  /* bank */
    {
      err = grub_tpm2_protector_parse_bank (state[OPTION_BANK].arg,
					    &tpm2_protector_ctx.bank);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_TPM2KEY].set)  /* tpm2key */
    {
      err = tpm2_protector_parse_file (state[OPTION_TPM2KEY].arg,
				       &tpm2_protector_ctx.tpm2key);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_KEYFILE].set)  /* keyfile */
    {
      err = tpm2_protector_parse_file (state[OPTION_KEYFILE].arg,
				       &tpm2_protector_ctx.keyfile);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_SRK].set)  /* srk */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[OPTION_SRK].arg,
						  &tpm2_protector_ctx.srk);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_ASYMMETRIC].set)  /* asymmetric */
    {
      err = grub_tpm2_protector_parse_asymmetric (state[OPTION_ASYMMETRIC].arg,
						  &tpm2_protector_ctx.srk_type);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_NVINDEX].set)  /* nvindex */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[OPTION_NVINDEX].arg,
						  &tpm2_protector_ctx.nv);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  err = tpm2_protector_check_args (&tpm2_protector_ctx);

  /* This command only initializes the protector, so nothing else to do. */

  return err;
}

static grub_err_t
tpm2_protector_clear_cmd_handler (grub_extcmd_context_t ctxt __attribute__ ((unused)),
				  int argc, char **args __attribute__ ((unused)))
{
  if (argc != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("tpm2_key_protector_clear accepts no arguments"));

  grub_free ((void *) tpm2_protector_ctx.keyfile);
  grub_memset (&tpm2_protector_ctx, 0, sizeof (tpm2_protector_ctx));

  return GRUB_ERR_NONE;
}

static struct grub_key_protector tpm2_key_protector =
  {
    .name = "tpm2",
    .recover_key = tpm2_protector_recover_key
  };

GRUB_MOD_INIT (tpm2_key_protector)
{
  tpm2_protector_init_cmd =
    grub_register_extcmd ("tpm2_key_protector_init",
			  tpm2_protector_init_cmd_handler, 0,
			  N_("[-m mode] "
			     "[-p pcr_list] "
			     "[-b pcr_bank] "
			     "[-T tpm2_key_file_path] "
			     "[-k sealed_key_file_path] "
			     "[-s srk_handle] "
			     "[-a asymmetric_key_type] "
			     "[-n nv_index]"),
			  N_("Initialize the TPM2 key protector."),
			  tpm2_protector_init_cmd_options);
  tpm2_protector_clear_cmd =
    grub_register_extcmd ("tpm2_key_protector_clear",
			  tpm2_protector_clear_cmd_handler, 0, NULL,
			  N_("Clear the TPM2 key protector if previously initialized."),
			  NULL);
  grub_key_protector_register (&tpm2_key_protector);
}

GRUB_MOD_FINI (tpm2_key_protector)
{
  grub_free ((void *) tpm2_protector_ctx.keyfile);

  grub_key_protector_unregister (&tpm2_key_protector);
  grub_unregister_extcmd (tpm2_protector_clear_cmd);
  grub_unregister_extcmd (tpm2_protector_init_cmd);
}
