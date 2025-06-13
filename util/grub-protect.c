/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Microsoft Corporation
 *  Copyright (C) 2023 SUSE LLC
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

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <libtasn1.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <grub/emu/hostdisk.h>
#include <grub/emu/misc.h>

#include <grub/util/misc.h>

#include <tss2_buffer.h>
#include <tss2_mu.h>
#include <tcg2.h>
#include <tpm2_args.h>
#include <tpm2.h>

#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#include <argp.h>
#pragma GCC diagnostic error "-Wmissing-prototypes"
#pragma GCC diagnostic error "-Wmissing-declarations"

#include "progname.h"

/* Unprintable option keys for argp */
typedef enum protect_opt
{
  /* General */
  PROTECT_OPT_ACTION      = 'a',
  PROTECT_OPT_PROTECTOR   = 'p',
  /* TPM2 */
  PROTECT_OPT_TPM2_DEVICE = 0x100,
  PROTECT_OPT_TPM2_PCRS,
  PROTECT_OPT_TPM2_ASYMMETRIC,
  PROTECT_OPT_TPM2_BANK,
  PROTECT_OPT_TPM2_SRK,
  PROTECT_OPT_TPM2_KEYFILE,
  PROTECT_OPT_TPM2_OUTFILE,
  PROTECT_OPT_TPM2_EVICT,
  PROTECT_OPT_TPM2_TPM2KEY,
  PROTECT_OPT_TPM2_NVINDEX,
} protect_opt_t;

/* Option flags to keep track of specified arguments */
typedef enum protect_arg
{
  /* General */
  PROTECT_ARG_ACTION          = 1 << 0,
  PROTECT_ARG_PROTECTOR       = 1 << 1,
  /* TPM2 */
  PROTECT_ARG_TPM2_DEVICE     = 1 << 2,
  PROTECT_ARG_TPM2_PCRS       = 1 << 3,
  PROTECT_ARG_TPM2_ASYMMETRIC = 1 << 4,
  PROTECT_ARG_TPM2_BANK       = 1 << 5,
  PROTECT_ARG_TPM2_SRK        = 1 << 6,
  PROTECT_ARG_TPM2_KEYFILE    = 1 << 7,
  PROTECT_ARG_TPM2_OUTFILE    = 1 << 8,
  PROTECT_ARG_TPM2_EVICT      = 1 << 9,
  PROTECT_ARG_TPM2_TPM2KEY    = 1 << 10,
  PROTECT_ARG_TPM2_NVINDEX    = 1 << 11
} protect_arg_t;

typedef enum protect_protector
{
  PROTECT_TYPE_ERROR,
  PROTECT_TYPE_TPM2
} protect_protector_t;

typedef enum protect_action
{
  PROTECT_ACTION_ERROR,
  PROTECT_ACTION_ADD,
  PROTECT_ACTION_REMOVE
} protect_action_t;

typedef struct protect_args
{
  protect_arg_t args;
  protect_action_t action;
  protect_protector_t protector;

  const char *tpm2_device;
  grub_uint8_t tpm2_pcrs[TPM_MAX_PCRS];
  grub_uint8_t tpm2_pcr_count;
  grub_srk_type_t srk_type;
  TPM_ALG_ID_t tpm2_bank;
  TPM_HANDLE_t tpm2_srk;
  const char *tpm2_keyfile;
  const char *tpm2_outfile;
  bool tpm2_evict;
  bool tpm2_tpm2key;
  TPM_HANDLE_t tpm2_nvindex;
} protect_args_t;

static struct argp_option protect_options[] =
  {
    /* Top-level options */
   {
      .name  = "action",
      .key   = 'a',
      .arg   = "add|remove",
      .flags = 0,
      .doc   =
	N_("Add or remove a key protector to or from a key."),
      .group = 0
    },
    {
      .name  = "protector",
      .key   = 'p',
      .arg   = "tpm2",
      .flags = 0,
      .doc   =
	N_("Set key protector to use (only tpm2 is currently supported)."),
      .group = 0
    },
    /* TPM2 key protector options */
    {
      .name = "tpm2-device",
      .key   = PROTECT_OPT_TPM2_DEVICE,
      .arg   = "FILE",
      .flags = 0,
      .doc   =
	N_("Set the path to the TPM2 device. (default: /dev/tpm0)"),
      .group = 0
    },
    {
      .name = "tpm2-pcrs",
      .key   = PROTECT_OPT_TPM2_PCRS,
      .arg   = "0[,1]...",
      .flags = 0,
      .doc   =
	N_("Set a comma-separated list of PCRs used to authorize key release "
	   "e.g., '7,11'. Please be aware that PCR 0~7 are used by the "
	   "firmware and the measurement result may change after a "
	   "firmware update (for baremetal systems) or a package "
	   "(OVMF/SLOF) update in the VM host. This may lead to "
	   "the failure of key unsealing. (default: 7)"),
      .group = 0
    },
    {
      .name = "tpm2-bank",
      .key  = PROTECT_OPT_TPM2_BANK,
      .arg   = "ALG",
      .flags = 0,
      .doc   =
	N_("Set the bank of PCRs used to authorize key release: "
	   "SHA1, SHA256, SHA384, or SHA512. (default: SHA256)"),
      .group = 0
    },
    {
      .name = "tpm2-keyfile",
      .key   = PROTECT_OPT_TPM2_KEYFILE,
      .arg   = "FILE",
      .flags = 0,
      .doc   =
	N_("Set the path to a file that contains the cleartext key to protect."),
      .group = 0
    },
    {
      .name = "tpm2-outfile",
      .key   = PROTECT_OPT_TPM2_OUTFILE,
      .arg   = "FILE",
      .flags = 0,
      .doc   =
	N_("Set the path to the file that will contain the key after sealing "
	   "(must be accessible to GRUB during boot)."),
      .group = 0
    },
    {
      .name = "tpm2-srk",
      .key   = PROTECT_OPT_TPM2_SRK,
      .arg   = "NUM",
      .flags = 0,
      .doc   =
	N_("Set the SRK handle if the SRK is to be made persistent."),
      .group = 0
    },
    {
      .name = "tpm2-asymmetric",
      .key   = PROTECT_OPT_TPM2_ASYMMETRIC,
      .arg   = "TYPE",
      .flags = 0,
      .doc   =
	N_("Set the type of SRK: RSA (RSA2048) and ECC (ECC_NIST_P256)."
	   "(default: ECC)"),
      .group = 0
    },
    {
      .name = "tpm2-evict",
      .key   = PROTECT_OPT_TPM2_EVICT,
      .arg   = NULL,
      .flags = 0,
      .doc   =
	N_("Evict a previously persisted SRK from the TPM, if any."),
      .group = 0
    },
    {
      .name = "tpm2key",
      .key   = PROTECT_OPT_TPM2_TPM2KEY,
      .arg   = NULL,
      .flags = 0,
      .doc   =
	N_("Use TPM 2.0 Key File format."),
      .group = 0
    },
    {
      .name = "tpm2-nvindex",
      .key   = PROTECT_OPT_TPM2_NVINDEX,
      .arg   = "NUM",
      .flags = 0,
      .doc   =
	N_("Store the sealed key in a persistent or NV index handle."),
      .group = 0
    },
    /* End of list */
    { 0, 0, 0, 0, 0, 0 }
  };

static int protector_tpm2_fd = -1;

static grub_err_t
protect_read_file (const char *filepath, void **buffer, size_t *buffer_size)
{
  grub_err_t err;
  FILE *f;
  long len;
  void *buf;

  f = fopen (filepath, "rb");
  if (f == NULL)
    {
      fprintf (stderr, N_("Could not open file: %s\n"), filepath);
      return GRUB_ERR_FILE_NOT_FOUND;
    }

  if (fseek (f, 0, SEEK_END))
    {
      fprintf (stderr, N_("Could not seek file: %s\n"), filepath);
      err = GRUB_ERR_FILE_READ_ERROR;
      goto exit1;
    }

  len = ftell (f);
  if (len <= 0)
    {
      fprintf (stderr, N_("Could not get file length: %s\n"), filepath);
      err = GRUB_ERR_FILE_READ_ERROR;
      goto exit1;
    }

  rewind (f);

  buf = grub_malloc (len);
  if (buf == NULL)
    {
      fprintf (stderr, N_("Could not allocate memory for file: %s\n"), filepath);
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto exit1;
    }

  if (fread (buf, len, 1, f) != 1)
    {
      fprintf (stderr, N_("Could not read file: %s\n"), filepath);
      err = GRUB_ERR_FILE_READ_ERROR;
      goto exit2;
    }

  *buffer = buf;
  *buffer_size = len;

  buf = NULL;
  err = GRUB_ERR_NONE;

 exit2:
  grub_free (buf);

 exit1:
  fclose (f);

  return err;
}

static grub_err_t
protect_write_file (const char *filepath, void *buffer, size_t buffer_size)
{
  grub_err_t err;
  FILE *f;

  f = fopen (filepath, "wb");
  if (f == NULL)
    return GRUB_ERR_FILE_NOT_FOUND;

  if (fwrite (buffer, buffer_size, 1, f) != 1)
  {
    err = GRUB_ERR_WRITE_ERROR;
    goto exit;
  }

  err = GRUB_ERR_NONE;

 exit:
  fclose (f);

  return err;
}

grub_err_t
grub_tcg2_get_max_output_size (grub_size_t *size)
{
  if (size == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  *size = GRUB_TPM2_BUFFER_CAPACITY;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tcg2_submit_command (grub_size_t input_size, grub_uint8_t *input,
			  grub_size_t output_size, grub_uint8_t *output)
{
  if (write (protector_tpm2_fd, input, input_size) != input_size)
    {
      fprintf (stderr, N_("Could not send TPM command.\n"));
      return GRUB_ERR_BAD_DEVICE;
    }

  if (read (protector_tpm2_fd, output, output_size) < sizeof (TPM_RESPONSE_HEADER_t))
    {
      fprintf (stderr, N_("Could not get TPM response.\n"));
      return GRUB_ERR_BAD_DEVICE;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_open_device (const char *dev_node)
{
  if (protector_tpm2_fd != -1)
    return GRUB_ERR_NONE;

  protector_tpm2_fd = open (dev_node, O_RDWR);
  if (protector_tpm2_fd == -1)
    {
      fprintf (stderr, N_("Could not open TPM device (%s).\n"), strerror (errno));
      return GRUB_ERR_FILE_NOT_FOUND;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_close_device (void)
{
  int err;

  if (protector_tpm2_fd == -1)
    return GRUB_ERR_NONE;

  err = close (protector_tpm2_fd);
  if (err != GRUB_ERR_NONE)
  {
    fprintf (stderr, N_("Could not close TPM device (%s).\n"), strerror (errno));
    return GRUB_ERR_IO;
  }

  protector_tpm2_fd = -1;
  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_get_policy_digest (protect_args_t *args, TPM2B_DIGEST_t *digest)
{
  TPM_RC_t rc;
  TPML_PCR_SELECTION_t pcr_sel = {
    .count = 1,
    .pcrSelections = {
      {
	.hash = args->tpm2_bank,
	.sizeOfSelect = 3,
	.pcrSelect = {0}
      },
    }
  };
  TPML_PCR_SELECTION_t pcr_sel_out = {0};
  TPML_DIGEST_t pcr_values = {0};
  TPM2B_DIGEST_t pcr_digest = {0};
  grub_size_t pcr_digest_len;
  TPM2B_MAX_BUFFER_t pcr_concat = {0};
  grub_size_t pcr_concat_len;
  grub_uint8_t *pcr_cursor;
  TPM2B_NONCE_t nonce = {0};
  TPM2B_ENCRYPTED_SECRET_t salt = {0};
  TPMT_SYM_DEF_t symmetric = {0};
  TPMI_SH_AUTH_SESSION_t session = 0;
  TPM2B_DIGEST_t policy_digest = {0};
  grub_uint8_t i;
  grub_err_t err;

  /* PCR Read */
  for (i = 0; i < args->tpm2_pcr_count; i++)
    TPMS_PCR_SELECTION_SelectPCR (&pcr_sel.pcrSelections[0], args->tpm2_pcrs[i]);

  rc = grub_tpm2_pcr_read (NULL, &pcr_sel, NULL, &pcr_sel_out, &pcr_values, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to read PCRs (TPM2_PCR_Read: 0x%x).\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  if ((pcr_sel_out.count != pcr_sel.count) ||
       (pcr_sel.pcrSelections[0].sizeOfSelect !=
	pcr_sel_out.pcrSelections[0].sizeOfSelect))
    {
      fprintf (stderr, N_("Could not read all the specified PCRs.\n"));
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Compute PCR Digest */
  switch (args->tpm2_bank)
    {
    case TPM_ALG_SHA1:
      pcr_digest_len = TPM_SHA1_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA256:
      pcr_digest_len = TPM_SHA256_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA384:
      pcr_digest_len = TPM_SHA384_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA512:
      pcr_digest_len = TPM_SHA512_DIGEST_SIZE;
      break;
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }

  pcr_concat_len = pcr_digest_len * args->tpm2_pcr_count;
  if (pcr_concat_len > TPM_MAX_DIGEST_BUFFER)
    {
      fprintf (stderr, N_("PCR concatenation buffer not big enough.\n"));
      return GRUB_ERR_OUT_OF_RANGE;
    }

  pcr_cursor = pcr_concat.buffer;
  for (i = 0; i < args->tpm2_pcr_count; i++)
    {
      if (pcr_values.digests[i].size != pcr_digest_len)
	{
	  fprintf (stderr,
		   N_("Bad PCR value size: expected %llu bytes but got %u bytes.\n"),
		   (long long unsigned int)pcr_digest_len, pcr_values.digests[i].size);
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      grub_memcpy (pcr_cursor, pcr_values.digests[i].buffer, pcr_digest_len);
      pcr_cursor += pcr_digest_len;
    }
  pcr_concat.size = pcr_concat_len;

  rc = grub_tpm2_hash (NULL, &pcr_concat, TPM_ALG_SHA256, TPM_RH_NULL, &pcr_digest, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to generate PCR digest (TPM2_Hash: 0x%x)\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Start Trial Session */
  nonce.size = TPM_SHA256_DIGEST_SIZE;
  symmetric.algorithm = TPM_ALG_NULL;

  rc = grub_tpm2_startauthsession (TPM_RH_NULL, TPM_RH_NULL, 0, &nonce, &salt,
				   TPM_SE_TRIAL, &symmetric, TPM_ALG_SHA256,
				   &session, NULL, 0);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to start trial policy session (TPM2_StartAuthSession: 0x%x).\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* PCR Policy */
  rc = grub_tpm2_policypcr (session, NULL, &pcr_digest, &pcr_sel, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to submit PCR policy (TPM2_PolicyPCR: 0x%x).\n", rc);
      err = GRUB_ERR_BAD_DEVICE;
      goto error;
    }

  /* Retrieve Policy Digest */
  rc = grub_tpm2_policygetdigest (session, NULL, &policy_digest, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to get policy digest (TPM2_PolicyGetDigest: 0x%x).\n", rc);
      err = GRUB_ERR_BAD_DEVICE;
      goto error;
    }

  /* Epilogue */
  *digest = policy_digest;
  err = GRUB_ERR_NONE;

 error:
  grub_tpm2_flushcontext (session);

  return err;
}

static grub_err_t
protect_tpm2_get_srk (protect_args_t *args, TPM_HANDLE_t *srk)
{
  TPM_RC_t rc;
  TPM2B_PUBLIC_t public;
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
  TPM_HANDLE_t srkHandle;

  if (args->tpm2_srk != 0)
    {
      /* Find SRK */
      rc = grub_tpm2_readpublic (args->tpm2_srk, NULL, &public);
      if (rc == TPM_RC_SUCCESS)
	{
	  printf ("Read SRK from 0x%x\n", args->tpm2_srk);
	  *srk = args->tpm2_srk;
	  return GRUB_ERR_NONE;
	}

      /* The handle exists but its public area could not be read. */
      if ((rc & ~TPM_RC_N_MASK) != TPM_RC_HANDLE)
	{
	  fprintf (stderr, "Failed to retrieve SRK from 0x%x (TPM2_ReadPublic: 0x%x).\n", args->tpm2_srk, rc);
	  return GRUB_ERR_BAD_DEVICE;
	}
    }

  /* Create SRK */
  authCommand.sessionHandle = TPM_RS_PW;
  inPublic.publicArea.type = args->srk_type.type;
  inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
  inPublic.publicArea.objectAttributes.restricted = 1;
  inPublic.publicArea.objectAttributes.userWithAuth = 1;
  inPublic.publicArea.objectAttributes.decrypt = 1;
  inPublic.publicArea.objectAttributes.fixedTPM = 1;
  inPublic.publicArea.objectAttributes.fixedParent = 1;
  inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
  inPublic.publicArea.objectAttributes.noDA = 1;

  switch (args->srk_type.type)
    {
    case TPM_ALG_RSA:
      inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.rsaDetail.keyBits = args->srk_type.detail.rsa_bits;
      inPublic.publicArea.parameters.rsaDetail.exponent = 0;
      break;

    case TPM_ALG_ECC:
      inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.eccDetail.curveID = args->srk_type.detail.ecc_curve;
      inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
      break;

    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }

  rc = grub_tpm2_createprimary (TPM_RH_OWNER, &authCommand, &inSensitive, &inPublic,
			        &outsideInfo, &creationPcr, &srkHandle, &outPublic,
			        &creationData, &creationHash, &creationTicket,
			        &srkName, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to create SRK (TPM2_CreatePrimary: 0x%x).\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Persist SRK */
  if (args->tpm2_srk != 0)
    {
      rc = grub_tpm2_evictcontrol (TPM_RH_OWNER, srkHandle, &authCommand, args->tpm2_srk, NULL);
      if (rc == TPM_RC_SUCCESS)
	{
	  grub_tpm2_flushcontext (srkHandle);
	  srkHandle = args->tpm2_srk;
	}
      else
	fprintf (stderr,
		 "Warning: Failed to persist SRK (0x%x) (TPM2_EvictControl: 0x%x).\n"
		 "Continuing anyway...\n", args->tpm2_srk, rc);
    }

  /* Epilogue */
  *srk = srkHandle;

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_seal (TPM2B_DIGEST_t *policyDigest, TPM_HANDLE_t srk,
		   grub_uint8_t *clearText, grub_size_t clearTextLength,
		   tpm2_sealed_key_t *sealed_key)
{
  TPM_RC_t rc;
  TPMS_AUTH_COMMAND_t authCommand = {0};
  TPM2B_SENSITIVE_CREATE_t inSensitive = {0};
  TPM2B_PUBLIC_t inPublic  = {0};
  TPM2B_DATA_t outsideInfo = {0};
  TPML_PCR_SELECTION_t pcr_sel = {0};
  TPM2B_PRIVATE_t outPrivate = {0};
  TPM2B_PUBLIC_t outPublic = {0};

  /* Seal Data */
  authCommand.sessionHandle = TPM_RS_PW;

  inSensitive.sensitive.data.size = clearTextLength;
  memcpy(inSensitive.sensitive.data.buffer, clearText, clearTextLength);

  inPublic.publicArea.type = TPM_ALG_KEYEDHASH;
  inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
  inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
  inPublic.publicArea.authPolicy = *policyDigest;

  rc = grub_tpm2_create (srk, &authCommand, &inSensitive, &inPublic, &outsideInfo,
			 &pcr_sel, &outPrivate, &outPublic, NULL, NULL, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to seal key (TPM2_Create: 0x%x).\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Epilogue */
  sealed_key->public = outPublic;
  sealed_key->private = outPrivate;

  return GRUB_ERR_NONE;
}

extern asn1_static_node tpm2key_asn1_tab[];

/* id-sealedkey OID defined in TPM 2.0 Key Files Spec */
#define TPM2KEY_SEALED_KEY_OID "2.23.133.10.1.5"

static grub_err_t
protect_tpm2_export_tpm2key (const protect_args_t *args, tpm2_sealed_key_t *sealed_key,
			     void **der_buf, int *der_buf_size)
{
  const char *sealed_key_oid = TPM2KEY_SEALED_KEY_OID;
  asn1_node asn1_def = NULL;
  asn1_node tpm2key = NULL;
  grub_uint32_t parent;
  grub_uint32_t cmd_code;
  struct grub_tpm2_buffer pol_buf;
  TPML_PCR_SELECTION_t pcr_sel = {
    .count = 1,
    .pcrSelections = {
      {
	.hash = args->tpm2_bank,
	.sizeOfSelect = 3,
	.pcrSelect = {0}
      },
    }
  };
  struct grub_tpm2_buffer pub_buf;
  struct grub_tpm2_buffer priv_buf;
  int i;
  int ret;
  grub_err_t err;

  if (der_buf == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  for (i = 0; i < args->tpm2_pcr_count; i++)
    TPMS_PCR_SELECTION_SelectPCR (&pcr_sel.pcrSelections[0], args->tpm2_pcrs[i]);

  /*
   * Prepare the parameters for TPM_CC_PolicyPCR:
   * empty pcrDigest and the user selected PCRs
   */
  grub_tpm2_buffer_init (&pol_buf);
  grub_tpm2_buffer_pack_u16 (&pol_buf, 0);
  grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (&pol_buf, &pcr_sel);

  grub_tpm2_buffer_init (&pub_buf);
  grub_Tss2_MU_TPM2B_PUBLIC_Marshal (&pub_buf, &sealed_key->public);
  grub_tpm2_buffer_init (&priv_buf);
  grub_Tss2_MU_TPM2B_Marshal (&priv_buf, sealed_key->private.size,
			      sealed_key->private.buffer);
  if (pub_buf.error != 0 || priv_buf.error != 0)
    return GRUB_ERR_BAD_ARGUMENT;

  ret = asn1_array2tree (tpm2key_asn1_tab, &asn1_def, NULL);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_BAD_ARGUMENT;

  ret = asn1_create_element (asn1_def, "TPM2KEY.TPMKey" , &tpm2key);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_BAD_ARGUMENT;

  /* Set 'type' to "sealed key" */
  ret = asn1_write_value (tpm2key, "type", sealed_key_oid, 1);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'type': 0x%u\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Set 'emptyAuth' to TRUE */
  ret = asn1_write_value (tpm2key, "emptyAuth", "TRUE", 1);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'emptyAuth': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Set 'policy' */
  ret = asn1_write_value (tpm2key, "policy", "NEW", 1);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'policy': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }
  cmd_code = grub_cpu_to_be32 (TPM_CC_PolicyPCR);
  ret = asn1_write_value (tpm2key, "policy.?LAST.CommandCode", &cmd_code,
			  sizeof (cmd_code));
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'policy CommandCode': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }
  ret = asn1_write_value (tpm2key, "policy.?LAST.CommandPolicy", &pol_buf.data,
			  pol_buf.size);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'policy CommandPolicy': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Remove 'secret' */
  ret = asn1_write_value (tpm2key, "secret", NULL, 0);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to remove 'secret': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Remove 'authPolicy' */
  ret = asn1_write_value (tpm2key, "authPolicy", NULL, 0);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to remove 'authPolicy': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Remove 'description' */
  ret = asn1_write_value (tpm2key, "description", NULL, 0);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to remove 'description': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /*
   *  Use the SRK handle as the parent handle if specified
   *  Otherwise, Use TPM_RH_OWNER as the default parent handle
  */
  if (args->tpm2_srk != 0)
    parent = grub_cpu_to_be32 (args->tpm2_srk);
  else
    parent = grub_cpu_to_be32 (TPM_RH_OWNER);
  ret = asn1_write_value (tpm2key, "parent", &parent, sizeof (parent));
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'parent': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /*
   * Set 'rsaParent' to TRUE if the RSA SRK is specified and the SRK
   * handle is not persistent. Otherwise, remove 'rsaParent'.
   */
  if (args->tpm2_srk == 0 && args->srk_type.type == TPM_ALG_RSA)
    ret = asn1_write_value (tpm2key, "rsaParent", "TRUE", 1);
  else
    ret = asn1_write_value (tpm2key, "rsaParent", NULL, 0);

  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'rsaParent': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Set the pubkey */
  ret = asn1_write_value (tpm2key, "pubkey", pub_buf.data, pub_buf.size);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'pubkey': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Set the privkey */
  ret = asn1_write_value (tpm2key, "privkey", priv_buf.data, priv_buf.size);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "Failed to set 'privkey': 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* Create the DER binary */
  *der_buf_size = 0;
  ret = asn1_der_coding (tpm2key, "", NULL, der_buf_size, NULL);
  if (ret != ASN1_MEM_ERROR)
    {
      fprintf (stderr, "Failed to get DER size: 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  *der_buf = grub_malloc (*der_buf_size);
  if (*der_buf == NULL)
    {
      fprintf (stderr, "Failed to allocate memory for DER encoding\n");
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto error;
    }

  ret = asn1_der_coding (tpm2key, "", *der_buf, der_buf_size, NULL);
  if (ret != ASN1_SUCCESS)
    {
      fprintf (stderr, "DER coding error: 0x%x\n", ret);
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

 error:
  if (tpm2key)
    asn1_delete_structure (&tpm2key);

  return err;
}

static grub_err_t
protect_tpm2_export_raw (tpm2_sealed_key_t *sealed_key, void **out_buf, int *out_buf_size)
{
  struct grub_tpm2_buffer buf;

  grub_tpm2_buffer_init (&buf);
  grub_Tss2_MU_TPM2B_PUBLIC_Marshal (&buf, &sealed_key->public);
  grub_Tss2_MU_TPM2B_Marshal (&buf, sealed_key->private.size,
			      sealed_key->private.buffer);
  if (buf.error != 0)
    return GRUB_ERR_BAD_ARGUMENT;

  *out_buf_size = buf.size;
  *out_buf = grub_malloc (buf.size);

  if (*out_buf == NULL)
    {
      fprintf (stderr, N_("Could not allocate memory for the raw format key.\n"));
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  grub_memcpy (*out_buf, buf.data, buf.size);

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_export_persistent (protect_args_t *args,
				TPM_HANDLE_t srk_handle,
				tpm2_sealed_key_t *sealed_key)
{
  TPMS_AUTH_COMMAND_t authCmd = {0};
  TPM2B_NAME_t name = {0};
  TPM_HANDLE_t sealed_handle;
  TPM_RC_t rc;
  grub_err_t err = GRUB_ERR_NONE;

  /* Load the sealed key and associate it with the SRK */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = grub_tpm2_load (srk_handle, &authCmd, &sealed_key->private, &sealed_key->public,
		       &sealed_handle, &name, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to load sealed key (TPM2_Load: %x).\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Make the sealed key object persistent */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = grub_tpm2_evictcontrol (TPM_RH_OWNER, sealed_handle, &authCmd, args->tpm2_nvindex, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to make sealed key persistent with handle 0x%x (TPM2_EvictControl: 0x%x).\n", args->tpm2_nvindex, rc);
      err = GRUB_ERR_BAD_DEVICE;
      goto exit;
    }

 exit:
  grub_tpm2_flushcontext (sealed_handle);

  return err;
}

static grub_err_t
protect_tpm2_export_nvindex (protect_args_t *args, void *data, int data_size)
{
  TPMS_AUTH_COMMAND_t authCmd = {0};
  TPM2B_NV_PUBLIC_t pub_info = {0};
  TPM2B_MAX_NV_BUFFER_t nv_data = {0};
  TPM_RC_t rc;

  if (data_size > TPM_MAX_NV_BUFFER_SIZE || data_size < 0)
    {
      fprintf (stderr, N_("Invalid tpm2key size for TPM NV buffer\n"));
      return GRUB_ERR_OUT_OF_RANGE;
    }

  pub_info.nvPublic.nvIndex = args->tpm2_nvindex;
  pub_info.nvPublic.nameAlg = TPM_ALG_SHA256;
  pub_info.nvPublic.attributes = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;
  pub_info.nvPublic.dataSize = (grub_uint16_t) data_size;

  authCmd.sessionHandle = TPM_RS_PW;
  rc = grub_tpm2_nv_definespace (TPM_RH_OWNER, &authCmd, NULL, &pub_info);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to define NV space for 0x%x (TPM2_NV_DefineSpace: 0x%x)\n", args->tpm2_nvindex, rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  authCmd.sessionHandle = TPM_RS_PW;
  grub_memcpy (nv_data.buffer, data, data_size);
  nv_data.size = (grub_uint16_t) data_size;

  rc = grub_tpm2_nv_write (TPM_RH_OWNER, args->tpm2_nvindex, &authCmd, &nv_data, 0);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to write data into 0x%x (TPM2_NV_Write: 0x%x)\n", args->tpm2_nvindex, rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_add (protect_args_t *args)
{
  grub_err_t err;
  grub_uint8_t *key = NULL;
  grub_size_t key_size;
  TPM_HANDLE_t srk;
  TPM2B_DIGEST_t policy_digest;
  void *out_buf = NULL;
  int out_buf_size;
  tpm2_sealed_key_t sealed_key;

  err = protect_tpm2_open_device (args->tpm2_device);
  if (err != GRUB_ERR_NONE)
    return err;

  err = protect_read_file (args->tpm2_keyfile, (void **)&key, &key_size);
  if (err != GRUB_ERR_NONE)
    goto exit1;

  if (key_size > TPM_MAX_SYM_DATA)
    {
      fprintf (stderr, N_("Input key size larger than %u bytes.\n"), TPM_MAX_SYM_DATA);
      err = GRUB_ERR_OUT_OF_RANGE;
      goto exit2;
    }

  err = protect_tpm2_get_srk (args, &srk);
  if (err != GRUB_ERR_NONE)
    goto exit2;

  err = protect_tpm2_get_policy_digest (args, &policy_digest);
  if (err != GRUB_ERR_NONE)
    goto exit3;

  err = protect_tpm2_seal (&policy_digest, srk, key, key_size, &sealed_key);
  if (err != GRUB_ERR_NONE)
    goto exit3;

  if (args->tpm2_tpm2key == true)
    {
      err = protect_tpm2_export_tpm2key (args, &sealed_key, &out_buf, &out_buf_size);
      if (err != GRUB_ERR_NONE)
	{
	  fprintf (stderr, N_("Could not export to TPM 2.0 Key File format\n"));
	  goto exit3;
	}
    }
  else
    {
      err = protect_tpm2_export_raw (&sealed_key, &out_buf, &out_buf_size);
      if (err != GRUB_ERR_NONE)
	{
	  fprintf (stderr, N_("Could not export to the raw format\n"));
	  goto exit3;
	}
    }

  if (args->tpm2_outfile != NULL)
    {
      err = protect_write_file (args->tpm2_outfile, out_buf, out_buf_size);
      if (err != GRUB_ERR_NONE)
	{
	  fprintf (stderr, N_("Could not write key file (%s).\n"), strerror (errno));
	  goto exit3;
	}
    }

  if (TPM_HT_IS_NVINDEX (args->tpm2_nvindex) == true)
    {
      err = protect_tpm2_export_nvindex (args, out_buf, out_buf_size);
      if (err != GRUB_ERR_NONE)
	goto exit3;
    }
  else if (TPM_HT_IS_PERSISTENT (args->tpm2_nvindex) == true)
    {
      err = protect_tpm2_export_persistent (args, srk, &sealed_key);
      if (err != GRUB_ERR_NONE)
	goto exit3;
    }

 exit3:
  grub_tpm2_flushcontext (srk);
  grub_free (out_buf);

 exit2:
  grub_free (key);

 exit1:
  protect_tpm2_close_device ();

  return err;
}

static grub_err_t
protect_tpm2_evict (TPM_HANDLE_t handle)
{
  TPM_RC_t rc;
  TPM2B_PUBLIC_t public;
  TPMS_AUTH_COMMAND_t authCmd = {0};

  /* Find the persistent handle */
  rc = grub_tpm2_readpublic (handle, NULL, &public);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Handle 0x%x not found.\n", handle);
      return GRUB_ERR_BAD_ARGUMENT;
    }

  /* Evict the persistent handle */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = grub_tpm2_evictcontrol (TPM_RH_OWNER, handle, &authCmd, handle, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to evict handle 0x%x (TPM2_EvictControl: 0x%x).\n", handle, rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_nv_undefine (TPM_HANDLE_t handle)
{
  TPM_RC_t rc;
  TPM2B_NV_PUBLIC_t nv_public;
  TPMS_AUTH_COMMAND_t authCmd = {0};
  TPM2B_NAME_t nv_name;

  /* Find the nvindex handle */
  rc = grub_tpm2_nv_readpublic (handle, NULL, &nv_public, &nv_name);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Handle 0x%x not found.\n", handle);
      return GRUB_ERR_BAD_ARGUMENT;
    }

  /* Undefine the nvindex handle */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = grub_tpm2_nv_undefinespace (TPM_RH_OWNER, handle, &authCmd);
  if (rc != TPM_RC_SUCCESS)
    {
      fprintf (stderr, "Failed to undefine handle 0x%x (TPM2_NV_UndefineSpace: 0x%x).\n", handle, rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_tpm2_remove (protect_args_t *args)
{
  grub_err_t err;

  if (args->tpm2_evict == false)
    {
      printf ("--tpm2-evict not specified, nothing to do.\n");
      return GRUB_ERR_NONE;
    }

  err = protect_tpm2_open_device (args->tpm2_device);
  if (err != GRUB_ERR_NONE)
    return err;

  if (args->tpm2_srk != 0)
    {
      err = protect_tpm2_evict (args->tpm2_srk);
      if (err != GRUB_ERR_NONE)
	goto exit;
    }

  if (args->tpm2_nvindex != 0)
    {
      if (TPM_HT_IS_PERSISTENT (args->tpm2_nvindex) == true)
	{
	  err = protect_tpm2_evict (args->tpm2_nvindex);
	  if (err != GRUB_ERR_NONE)
	    goto exit;
	}
      else if (TPM_HT_IS_NVINDEX (args->tpm2_nvindex) == true)
	{
	  err = protect_tpm2_nv_undefine (args->tpm2_nvindex);
	  if (err != GRUB_ERR_NONE)
	    goto exit;
	}
      else
	{
	  fprintf (stderr, "Unsupported handle 0x%x\n", args->tpm2_nvindex);
	  err = GRUB_ERR_BAD_ARGUMENT;
	  goto exit;
	}
    }

  err = GRUB_ERR_NONE;

 exit:
  protect_tpm2_close_device ();

  return err;
}

static grub_err_t
protect_tpm2_run (protect_args_t *args)
{
  switch (args->action)
    {
    case PROTECT_ACTION_ADD:
      return protect_tpm2_add (args);

    case PROTECT_ACTION_REMOVE:
      return protect_tpm2_remove (args);

    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }
}

static grub_err_t
protect_tpm2_args_verify (protect_args_t *args)
{
  if (args->tpm2_device == NULL)
    args->tpm2_device = "/dev/tpm0";

  switch (args->action)
    {
    case PROTECT_ACTION_ADD:
      if (args->args & PROTECT_ARG_TPM2_EVICT)
	{
	  fprintf (stderr, N_("--tpm2-evict is invalid when --action is 'add'.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->tpm2_keyfile == NULL)
	{
	  fprintf (stderr, N_("--tpm2-keyfile must be specified.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->tpm2_outfile == NULL && args->tpm2_nvindex == 0)
	{
	  fprintf (stderr, N_("--tpm2-outfile or --tpm2-nvindex must be specified.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->tpm2_nvindex != 0)
	{
	  if (args->tpm2_tpm2key == true && TPM_HT_IS_PERSISTENT (args->tpm2_nvindex) == true)
	    {
	      fprintf (stderr, N_("Persistent handle does not support TPM 2.0 Key File format.\n"));
	      return GRUB_ERR_BAD_ARGUMENT;
	    }

	  if (TPM_HT_IS_PERSISTENT (args->tpm2_nvindex) == false && TPM_HT_IS_NVINDEX (args->tpm2_nvindex) == false)
	    {
	      fprintf (stderr, N_("--tpm2-nvindex must be a persistent or NV index handle.\n"));
	      return GRUB_ERR_BAD_ARGUMENT;
	    }

	  if (args->tpm2_nvindex == args->tpm2_srk)
	    {
	      fprintf (stderr, N_("--tpm2-nvindex and --tpm2-srk must be different.\n"));
	      return GRUB_ERR_BAD_ARGUMENT;
	    }
	}

      if (args->tpm2_srk != 0 && TPM_HT_IS_PERSISTENT(args->tpm2_srk) == false)
	{
	  fprintf (stderr, N_("--tpm2-srk must be a persistent handle, e.g. 0x81000000.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->tpm2_pcr_count == 0)
	{
	  args->tpm2_pcrs[0] = 7;
	  args->tpm2_pcr_count = 1;
	}

      if (args->srk_type.type == TPM_ALG_ERROR)
	{
	  args->srk_type.type = TPM_ALG_ECC;
	  args->srk_type.detail.ecc_curve = TPM_ECC_NIST_P256;
	}

      if (args->tpm2_bank == TPM_ALG_ERROR)
	args->tpm2_bank = TPM_ALG_SHA256;

      break;

    case PROTECT_ACTION_REMOVE:
      if (args->args & PROTECT_ARG_TPM2_ASYMMETRIC)
	{
	  fprintf (stderr, N_("--tpm2-asymmetric is invalid when --action is 'remove'.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->args & PROTECT_ARG_TPM2_BANK)
	{
	  fprintf (stderr, N_("--tpm2-bank is invalid when --action is 'remove'.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->args & PROTECT_ARG_TPM2_KEYFILE)
	{
	  fprintf (stderr, N_("--tpm2-keyfile is invalid when --action is 'remove'.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->args & PROTECT_ARG_TPM2_OUTFILE)
	{
	  fprintf (stderr, N_("--tpm2-outfile is invalid when --action is 'remove'.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->args & PROTECT_ARG_TPM2_PCRS)
	{
	  fprintf (stderr, N_("--tpm2-pcrs is invalid when --action is 'remove'.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      if (args->tpm2_srk == 0 && args->tpm2_nvindex == 0)
	{
	  fprintf (stderr, N_("missing --tpm2-srk or --tpm2-nvindex for --action 'remove'.\n"));
	  return GRUB_ERR_BAD_ARGUMENT;
	}

      break;

    default:
      fprintf (stderr, N_("The TPM2 key protector only supports the following actions: add, remove.\n"));
      return GRUB_ERR_BAD_ARGUMENT;
    }

  return GRUB_ERR_NONE;
}

static error_t
protect_argp_parser (int key, char *arg, struct argp_state *state)
{
  grub_err_t err;
  protect_args_t *args = state->input;

  switch (key)
    {
    case PROTECT_OPT_ACTION:
      if (args->args & PROTECT_ARG_ACTION)
	{
	  fprintf (stderr, N_("--action|-a can only be specified once.\n"));
	  return EINVAL;
	}

      if (grub_strcmp (arg, "add") == 0)
	args->action = PROTECT_ACTION_ADD;
      else if (grub_strcmp (arg, "remove") == 0)
	args->action = PROTECT_ACTION_REMOVE;
      else
	{
	  fprintf (stderr, N_("'%s' is not a valid action.\n"), arg);
	  return EINVAL;
	}

      args->args |= PROTECT_ARG_ACTION;
      break;

    case PROTECT_OPT_PROTECTOR:
      if (args->args & PROTECT_ARG_PROTECTOR)
	{
	  fprintf (stderr, N_("--protector|-p can only be specified once.\n"));
	  return EINVAL;
	}

      if (grub_strcmp (arg, "tpm2") == 0)
	args->protector = PROTECT_TYPE_TPM2;
      else
	{
	  fprintf (stderr, N_("'%s' is not a valid protector.\n"), arg);
	  return EINVAL;
	}

      args->args |= PROTECT_ARG_PROTECTOR;
      break;

    case PROTECT_OPT_TPM2_DEVICE:
      if (args->args & PROTECT_ARG_TPM2_DEVICE)
	{
	  fprintf (stderr, N_("--tpm2-device can only be specified once.\n"));
	  return EINVAL;
	}

      args->tpm2_device = xstrdup (arg);
      args->args |= PROTECT_ARG_TPM2_DEVICE;
      break;

    case PROTECT_OPT_TPM2_PCRS:
      if (args->args & PROTECT_ARG_TPM2_PCRS)
	{
	  fprintf (stderr, N_("--tpm2-pcrs can only be specified once.\n"));
	  return EINVAL;
	}

      err = grub_tpm2_protector_parse_pcrs (arg, args->tpm2_pcrs,
					    &args->tpm2_pcr_count);
      if (err != GRUB_ERR_NONE)
	{
	  if (grub_errno != GRUB_ERR_NONE)
	    grub_print_error ();
	  return EINVAL;
	}

      args->args |= PROTECT_ARG_TPM2_PCRS;
      break;

    case PROTECT_OPT_TPM2_SRK:
      if (args->args & PROTECT_ARG_TPM2_SRK)
	{
	  fprintf (stderr, N_("--tpm2-srk can only be specified once.\n"));
	  return EINVAL;
	}

      err = grub_tpm2_protector_parse_tpm_handle (arg, &args->tpm2_srk);
      if (err != GRUB_ERR_NONE)
	{
	  if (grub_errno != GRUB_ERR_NONE)
	    grub_print_error ();
	  return EINVAL;
	}

      args->args |= PROTECT_ARG_TPM2_SRK;
      break;

    case PROTECT_OPT_TPM2_ASYMMETRIC:
      if (args->args & PROTECT_ARG_TPM2_ASYMMETRIC)
	{
	  fprintf (stderr, N_("--tpm2-asymmetric can only be specified once.\n"));
	  return EINVAL;
	}

      err = grub_tpm2_protector_parse_asymmetric (arg, &args->srk_type);
      if (err != GRUB_ERR_NONE)
	{
	  if (grub_errno != GRUB_ERR_NONE)
	    grub_print_error ();
	  return EINVAL;
	}

      args->args |= PROTECT_ARG_TPM2_ASYMMETRIC;
      break;

    case PROTECT_OPT_TPM2_BANK:
      if (args->args & PROTECT_ARG_TPM2_BANK)
	{
	  fprintf (stderr, N_("--tpm2-bank can only be specified once.\n"));
	  return EINVAL;
	}

      err = grub_tpm2_protector_parse_bank (arg, &args->tpm2_bank);
      if (err != GRUB_ERR_NONE)
	{
	  if (grub_errno != GRUB_ERR_NONE)
	    grub_print_error ();
	  return EINVAL;
	}

      args->args |= PROTECT_ARG_TPM2_BANK;
      break;

    case PROTECT_OPT_TPM2_KEYFILE:
      if (args->args & PROTECT_ARG_TPM2_KEYFILE)
	{
	  fprintf (stderr, N_("--tpm2-keyfile can only be specified once.\n"));
	  return EINVAL;
	}

      args->tpm2_keyfile = xstrdup(arg);
      args->args |= PROTECT_ARG_TPM2_KEYFILE;
      break;

    case PROTECT_OPT_TPM2_OUTFILE:
      if (args->args & PROTECT_ARG_TPM2_OUTFILE)
	{
	  fprintf (stderr, N_("--tpm2-outfile can only be specified once.\n"));
	  return EINVAL;
	}

      args->tpm2_outfile = xstrdup(arg);
      args->args |= PROTECT_ARG_TPM2_OUTFILE;
      break;

    case PROTECT_OPT_TPM2_EVICT:
      if (args->args & PROTECT_ARG_TPM2_EVICT)
	{
	  fprintf (stderr, N_("--tpm2-evict can only be specified once.\n"));
	  return EINVAL;
	}

      args->tpm2_evict = true;
      args->args |= PROTECT_ARG_TPM2_EVICT;
      break;

    case PROTECT_OPT_TPM2_TPM2KEY:
      if (args->args & PROTECT_ARG_TPM2_TPM2KEY)
	{
	  fprintf (stderr, N_("--tpm2-tpm2key can only be specified once.\n"));
	  return EINVAL;
	}

      args->tpm2_tpm2key = true;
      args->args |= PROTECT_ARG_TPM2_TPM2KEY;
      break;

    case PROTECT_OPT_TPM2_NVINDEX:
      if (args->args & PROTECT_ARG_TPM2_NVINDEX)
	{
	  fprintf (stderr, N_("--tpm2-nvindex can only be specified once.\n"));
	  return EINVAL;
	}

      err = grub_tpm2_protector_parse_tpm_handle (arg, &args->tpm2_nvindex);
      if (err != GRUB_ERR_NONE)
	{
	  if (grub_errno != GRUB_ERR_NONE)
	    grub_print_error ();
	  return EINVAL;
	}

      args->args |= PROTECT_ARG_TPM2_NVINDEX;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static grub_err_t
protect_args_verify (protect_args_t *args)
{
  if (args->action == PROTECT_ACTION_ERROR)
    {
      fprintf (stderr, N_("--action is mandatory.\n"));
      return GRUB_ERR_BAD_ARGUMENT;
    }

  /*
   * At the moment, the only configurable key protector is the TPM2 one, so it
   * is the only key protector supported by this tool.
   */
  if (args->protector != PROTECT_TYPE_TPM2)
    {
      fprintf (stderr, N_("--protector is mandatory and only 'tpm2' is currently supported.\n"));
      return GRUB_ERR_BAD_ARGUMENT;
    }

  switch (args->protector)
    {
    case PROTECT_TYPE_TPM2:
      return protect_tpm2_args_verify (args);
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
protect_dispatch (protect_args_t *args)
{
  switch (args->protector)
    {
    case PROTECT_TYPE_TPM2:
      return protect_tpm2_run (args);
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }
}

static void
protect_init (int *argc, char **argv[])
{
  grub_util_host_init (argc, argv);

  grub_util_biosdisk_init (NULL);

  grub_init_all ();

  grub_lvm_fini ();
  grub_mdraid09_fini ();
  grub_mdraid1x_fini ();
  grub_diskfilter_fini ();
  grub_diskfilter_init ();
  grub_mdraid09_init ();
  grub_mdraid1x_init ();
  grub_lvm_init ();
}

static void
protect_fini (void)
{
  grub_fini_all ();
  grub_util_biosdisk_fini ();
}

static struct argp protect_argp =
{
  .options     = protect_options,
  .parser      = protect_argp_parser,
  .args_doc    = NULL,
  .doc         =
    N_("Protect a cleartext key using a GRUB key protector that can retrieve "
       "the key during boot to unlock fully-encrypted disks automatically."),
  .children    = NULL,
  .help_filter = NULL,
  .argp_domain = NULL
};

int
main (int argc, char *argv[])
{
  grub_err_t err;
  protect_args_t args = {0};

  if (argp_parse (&protect_argp, argc, argv, 0, 0, &args) != 0)
    {
      fprintf (stderr, N_("Could not parse arguments.\n"));
      return EXIT_FAILURE;
    }

  protect_init (&argc, &argv);

  err = protect_args_verify (&args);
  if (err != GRUB_ERR_NONE)
    goto exit;

  err = protect_dispatch (&args);

 exit:
  protect_fini ();

  if (err != GRUB_ERR_NONE)
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
