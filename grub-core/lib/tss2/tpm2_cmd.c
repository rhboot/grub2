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

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/types.h>

#include <tss2_buffer.h>
#include <tss2_mu.h>
#include <tss2_structs.h>
#include <tcg2.h>
#include <tpm2_cmd.h>

static TPM_RC_t
tpm2_submit_command_real (const TPMI_ST_COMMAND_TAG_t tag,
			  const TPM_CC_t commandCode,
			  TPM_RC_t *responseCode,
			  const struct grub_tpm2_buffer *in,
			  struct grub_tpm2_buffer *out)
{
  grub_err_t err;
  struct grub_tpm2_buffer buf;
  TPMI_ST_COMMAND_TAG_t tag_out;
  grub_uint32_t command_size;
  grub_size_t max_output_size;

  /* Marshal */
  grub_tpm2_buffer_init (&buf);
  grub_tpm2_buffer_pack_u16 (&buf, tag);
  grub_tpm2_buffer_pack_u32 (&buf, 0);
  grub_tpm2_buffer_pack_u32 (&buf, commandCode);
  grub_tpm2_buffer_pack (&buf, in->data, in->size);

  if (buf.error != 0)
    return TPM_RC_FAILURE;

  /* Convert the command size to big endian to fill the u32 buffer below 'tag' */
  command_size = grub_cpu_to_be32 (buf.size);
  grub_memcpy (&buf.data[sizeof (grub_uint16_t)], &command_size, sizeof (command_size));

  /* Stay within output block limits */
  err = grub_tcg2_get_max_output_size (&max_output_size);
  if (err != GRUB_ERR_NONE || max_output_size > out->cap)
    max_output_size = out->cap - 1;

  /* Submit */
  err = grub_tcg2_submit_command (buf.size, buf.data, max_output_size, out->data);
  if (err != GRUB_ERR_NONE)
    return TPM_RC_FAILURE;

  /* Unmarshal */
  out->size = sizeof (grub_uint16_t) + sizeof (grub_uint32_t) + sizeof (grub_uint32_t);
  grub_tpm2_buffer_unpack_u16 (out, &tag_out);
  grub_tpm2_buffer_unpack_u32 (out, &command_size);
  grub_tpm2_buffer_unpack_u32 (out, responseCode);
  out->size = command_size;
  if (out->error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

static TPM_RC_t
tpm2_submit_command (const TPMI_ST_COMMAND_TAG_t tag,
		     const TPM_CC_t commandCode,
		     TPM_RC_t *responseCode,
		     const struct grub_tpm2_buffer *in,
		     struct grub_tpm2_buffer *out)
{
  TPM_RC_t err;
  int retry_cnt = 0;

  /* Catch TPM_RC_RETRY and send the command again */
  do {
    err = tpm2_submit_command_real (tag, commandCode, responseCode, in, out);
    if (*responseCode != TPM_RC_RETRY)
      break;

    retry_cnt++;
  } while (retry_cnt < 3);

  return err;
}

TPM_RC_t
grub_tpm2_createprimary (const TPMI_RH_HIERARCHY_t primaryHandle,
			 const TPMS_AUTH_COMMAND_t *authCommand,
			 const TPM2B_SENSITIVE_CREATE_t *inSensitive,
			 const TPM2B_PUBLIC_t *inPublic,
			 const TPM2B_DATA_t *outsideInfo,
			 const TPML_PCR_SELECTION_t *creationPCR,
			 TPM_HANDLE_t *objectHandle,
			 TPM2B_PUBLIC_t *outPublic,
			 TPM2B_CREATION_DATA_t *creationData,
			 TPM2B_DIGEST_t *creationHash,
			 TPMT_TK_CREATION_t *creationTicket,
			 TPM2B_NAME_t *name,
			 TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_HANDLE_t objectHandleTmp;
  TPM2B_PUBLIC_t outPublicTmp;
  TPM2B_CREATION_DATA_t creationDataTmp;
  TPM2B_DIGEST_t creationHashTmp;
  TPMT_TK_CREATION_t creationTicketTmp;
  TPM2B_NAME_t nameTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t parameterSize;

  if (inSensitive == NULL || inPublic == NULL || outsideInfo == NULL ||
      creationPCR == NULL)
    return TPM_RC_VALUE;

  if (objectHandle == NULL)
    objectHandle = &objectHandleTmp;
  if (outPublic == NULL)
    outPublic = &outPublicTmp;
  if (creationData == NULL)
    creationData = &creationDataTmp;
  if (creationHash == NULL)
    creationHash = &creationHashTmp;
  if (creationTicket == NULL)
    creationTicket = &creationTicketTmp;
  if (name == NULL)
    name = &nameTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (outPublic, 0, sizeof (*outPublic));
  grub_memset (creationData, 0, sizeof (*creationData));
  grub_memset (creationHash, 0, sizeof (*creationHash));
  grub_memset (creationTicket, 0, sizeof (*creationTicket));
  grub_memset (name, 0, sizeof (*name));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, primaryHandle);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPM2B_SENSITIVE_CREATE_Marshal (&in, inSensitive);
  grub_Tss2_MU_TPM2B_PUBLIC_Marshal (&in, inPublic);
  grub_Tss2_MU_TPM2B_Marshal (&in, outsideInfo->size, outsideInfo->buffer);
  grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (&in, creationPCR);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_CreatePrimary, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, objectHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (&out, outPublic);
  grub_Tss2_MU_TPM2B_CREATION_DATA_Unmarshal (&out, creationData);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (&out, creationHash);
  grub_Tss2_MU_TPMT_TK_CREATION_Unmarshal (&out, creationTicket);
  grub_Tss2_MU_TPM2B_NAME_Unmarshal (&out, name);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_startauthsession (const TPMI_DH_OBJECT_t tpmKey,
			    const TPMI_DH_ENTITY_t bind,
			    const TPMS_AUTH_COMMAND_t *authCommand,
			    const TPM2B_NONCE_t *nonceCaller,
			    const TPM2B_ENCRYPTED_SECRET_t *encryptedSalt,
			    const TPM_SE_t sessionType,
			    const TPMT_SYM_DEF_t *symmetric,
			    const TPMI_ALG_HASH_t authHash,
			    TPMI_SH_AUTH_SESSION_t *sessionHandle,
			    TPM2B_NONCE_t *nonceTpm,
			    TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_SH_AUTH_SESSION_t sessionHandleTmp;
  TPM2B_NONCE_t nonceTpmTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (nonceCaller == NULL || symmetric == NULL)
    return TPM_RC_VALUE;

  if (tpmKey == TPM_RH_NULL &&
      (encryptedSalt && encryptedSalt->size != 0))
    return TPM_RC_VALUE;

  if (sessionHandle == NULL)
    sessionHandle = &sessionHandleTmp;
  if (nonceTpm == NULL)
    nonceTpm = &nonceTpmTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (sessionHandle, 0, sizeof (*sessionHandle));
  grub_memset (nonceTpm, 0, sizeof (*nonceTpm));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, tpmKey);
  grub_tpm2_buffer_pack_u32 (&in, bind);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPM2B_Marshal (&in, nonceCaller->size, nonceCaller->buffer);
  if (encryptedSalt != NULL)
    grub_Tss2_MU_TPM2B_Marshal (&in, encryptedSalt->size, encryptedSalt->secret);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_buffer_pack_u8 (&in, sessionType);
  grub_Tss2_MU_TPMT_SYM_DEF_Marshal (&in, symmetric);
  grub_tpm2_buffer_pack_u16 (&in, authHash);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_StartAuthSession, &responseCode,
				 &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, sessionHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPM2B_NONCE_Unmarshal (&out, nonceTpm);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_policypcr (const TPMI_SH_POLICY_t policySessions,
		     const TPMS_AUTH_COMMAND_t *authCommand,
		     const TPM2B_DIGEST_t *pcrDigest,
		     const TPML_PCR_SELECTION_t *pcrs,
		     TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (pcrs == NULL)
    return TPM_RC_VALUE;

  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, policySessions);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (pcrDigest != NULL)
    grub_Tss2_MU_TPM2B_Marshal (&in, pcrDigest->size, pcrDigest->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (&in, pcrs);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_PolicyPCR, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_readpublic (const TPMI_DH_OBJECT_t objectHandle,
		      const TPMS_AUTH_COMMAND_t *authCommand,
		      TPM2B_PUBLIC_t *outPublic)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t parameterSize;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, objectHandle);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_ReadPublic, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (&out, outPublic);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_load (const TPMI_DH_OBJECT_t parent_handle,
		const TPMS_AUTH_COMMAND_t *authCommand,
		const TPM2B_PRIVATE_t *inPrivate,
		const TPM2B_PUBLIC_t *inPublic,
		TPM_HANDLE_t *objectHandle,
		TPM2B_NAME_t *name,
		TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_HANDLE_t objectHandleTmp;
  TPM2B_NAME_t nameTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (inPrivate == NULL || inPublic == NULL)
    return TPM_RC_VALUE;

  if (objectHandle == NULL)
    objectHandle = &objectHandleTmp;
  if (name == NULL)
    name = &nameTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (objectHandle, 0, sizeof (*objectHandle));
  grub_memset (name, 0, sizeof (*name));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, parent_handle);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPM2B_Marshal (&in, inPrivate->size, inPrivate->buffer);
  grub_Tss2_MU_TPM2B_PUBLIC_Marshal (&in, inPublic);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_Load, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, objectHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPM2B_NAME_Unmarshal (&out, name);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_loadexternal (const TPMS_AUTH_COMMAND_t *authCommand,
			const TPM2B_SENSITIVE_t *inPrivate,
			const TPM2B_PUBLIC_t *inPublic,
			const TPMI_RH_HIERARCHY_t hierarchy,
			TPM_HANDLE_t *objectHandle,
			TPM2B_NAME_t *name,
			TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_HANDLE_t objectHandleTmp;
  TPM2B_NAME_t nameTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (inPublic == NULL)
    return TPM_RC_VALUE;

  if (objectHandle == NULL)
    objectHandle = &objectHandleTmp;
  if (name == NULL)
    name = &nameTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (objectHandle, 0, sizeof (*objectHandle));
  grub_memset (name, 0, sizeof (*name));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (inPrivate != NULL)
    grub_Tss2_MU_TPM2B_SENSITIVE_Marshal (&in, inPrivate);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_Tss2_MU_TPM2B_PUBLIC_Marshal (&in, inPublic);
  grub_tpm2_buffer_pack_u32 (&in, hierarchy);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_LoadExternal, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, objectHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPM2B_NAME_Unmarshal (&out, name);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_unseal (const TPMI_DH_OBJECT_t itemHandle,
		  const TPMS_AUTH_COMMAND_t *authCommand,
		  TPM2B_SENSITIVE_DATA_t *outData,
		  TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM2B_SENSITIVE_DATA_t outDataTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (outData == NULL)
    outData = &outDataTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (outData, 0, sizeof (*outData));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, itemHandle);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_Unseal, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPM2B_SENSITIVE_DATA_Unmarshal (&out, outData);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_flushcontext (const TPMI_DH_CONTEXT_t handle)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_RC_t responseCode;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, handle);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (TPM_ST_NO_SESSIONS, TPM_CC_FlushContext, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_pcr_event (const TPMI_DH_PCR_t pcrHandle,
		     const TPMS_AUTH_COMMAND_t *authCommand,
		     const TPM2B_EVENT_t *eventData,
		     TPML_DIGEST_VALUES_t *digests,
		     TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPML_DIGEST_VALUES_t digestsTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPM_RC_t responseCode;
  grub_uint32_t parameterSize;

  if (eventData == NULL)
    return TPM_RC_VALUE;
  if (authCommand == NULL)
    return TPM_RC_VALUE;

  if (digests == NULL)
    digests = &digestsTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, pcrHandle);
  grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPM2B_Marshal (&in, eventData->size, eventData->buffer);
  if (in.error == true)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (TPM_ST_SESSIONS, TPM_CC_PCR_Event, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_Tss2_MU_TPML_DIGEST_VALUE_Unmarshal (&out, digests);
  grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error == true)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_pcr_read (const TPMS_AUTH_COMMAND_t *authCommand,
		    const TPML_PCR_SELECTION_t *pcrSelectionIn,
		    grub_uint32_t *pcrUpdateCounter,
		    TPML_PCR_SELECTION_t *pcrSelectionOut,
		    TPML_DIGEST_t *pcrValues,
		    TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  grub_uint32_t pcrUpdateCounterTmp;
  TPML_PCR_SELECTION_t pcrSelectionOutTmp;
  TPML_DIGEST_t pcrValuesTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t parameterSize;

  if (pcrSelectionIn == NULL)
    return TPM_RC_VALUE;

  if (pcrUpdateCounter == NULL)
    pcrUpdateCounter = &pcrUpdateCounterTmp;
  if (pcrSelectionOut == NULL)
    pcrSelectionOut = &pcrSelectionOutTmp;
  if (pcrValues == NULL)
    pcrValues = &pcrValuesTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (&in, pcrSelectionIn);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_PCR_Read, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_buffer_unpack_u32 (&out, pcrUpdateCounter);
  grub_Tss2_MU_TPML_PCR_SELECTION_Unmarshal (&out, pcrSelectionOut);
  grub_Tss2_MU_TPML_DIGEST_Unmarshal (&out, pcrValues);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_policygetdigest (const TPMI_SH_POLICY_t policySession,
			   const TPMS_AUTH_COMMAND_t *authCommand,
			   TPM2B_DIGEST_t *policyDigest,
			   TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPM2B_DIGEST_t policyDigestTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t parameterSize;

  if (authResponse == NULL)
    authResponse = &authResponseTmp;
  if (policyDigest == NULL)
    policyDigest = &policyDigestTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));
  grub_memset (policyDigest, 0, sizeof (*policyDigest));

  /* Submit */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, policySession);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_PolicyGetDigest, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (&out, policyDigest);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_create (const TPMI_DH_OBJECT_t parentHandle,
		  const TPMS_AUTH_COMMAND_t *authCommand,
		  const TPM2B_SENSITIVE_CREATE_t *inSensitive,
		  const TPM2B_PUBLIC_t *inPublic,
		  const TPM2B_DATA_t *outsideInfo,
		  const TPML_PCR_SELECTION_t *creationPCR,
		  TPM2B_PRIVATE_t *outPrivate,
		  TPM2B_PUBLIC_t *outPublic,
		  TPM2B_CREATION_DATA_t *creationData,
		  TPM2B_DIGEST_t *creationHash,
		  TPMT_TK_CREATION_t *creationTicket,
		  TPMS_AUTH_RESPONSE_t *authResponse)
{
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM2B_PUBLIC_t outPublicTmp;
  TPM2B_PRIVATE_t outPrivateTmp;
  TPM2B_CREATION_DATA_t creationDataTmp;
  TPM2B_DIGEST_t creationHashTmp;
  TPMT_TK_CREATION_t creationTicketTmp;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS:TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  TPM_RC_t rc;
  grub_uint32_t parameterSize;

  if (inSensitive == NULL || inPublic == NULL || outsideInfo == NULL ||
      creationPCR == NULL)
    return TPM_RC_VALUE;

  if (outPrivate == NULL)
    outPrivate = &outPrivateTmp;
  if (outPublic == NULL)
    outPublic = &outPublicTmp;
  if (creationData == NULL)
    creationData = &creationDataTmp;
  if (creationHash == NULL)
    creationHash = &creationHashTmp;
  if (creationTicket == NULL)
    creationTicket = &creationTicketTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (outPrivate, 0, sizeof (*outPrivate));
  grub_memset (outPublic, 0, sizeof (*outPublic));
  grub_memset (creationData, 0, sizeof (*creationData));
  grub_memset (creationHash, 0, sizeof (*creationHash));
  grub_memset (creationTicket, 0, sizeof (*creationTicket));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, parentHandle);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPM2B_SENSITIVE_CREATE_Marshal (&in, inSensitive);
  grub_Tss2_MU_TPM2B_PUBLIC_Marshal (&in, inPublic);
  grub_Tss2_MU_TPM2B_Marshal (&in, outsideInfo->size, outsideInfo->buffer);
  grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (&in, creationPCR);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_Create, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
   grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_Tss2_MU_TPM2B_PRIVATE_Unmarshal (&out, outPrivate);
  grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (&out, outPublic);
  grub_Tss2_MU_TPM2B_CREATION_DATA_Unmarshal (&out, creationData);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (&out, creationHash);
  grub_Tss2_MU_TPMT_TK_CREATION_Unmarshal (&out, creationTicket);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal(&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_evictcontrol (const TPMI_RH_PROVISION_t auth,
			const TPMI_DH_OBJECT_t objectHandle,
			const TPMS_AUTH_COMMAND_t *authCommand,
			const TPMI_DH_PERSISTENT_t persistentHandle,
			TPMS_AUTH_RESPONSE_t *authResponse)
{
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  TPM_RC_t rc;
  grub_uint32_t parameterSize;

  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, auth);
  grub_tpm2_buffer_pack_u32 (&in, objectHandle);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_buffer_pack_u32 (&in, persistentHandle);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_EvictControl, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    {
      grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
      grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal(&out, authResponse);
    }
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_hash (const TPMS_AUTH_COMMAND_t *authCommand,
		const TPM2B_MAX_BUFFER_t *data,
		const TPMI_ALG_HASH_t hashAlg,
		const TPMI_RH_HIERARCHY_t hierarchy,
		TPM2B_DIGEST_t *outHash,
		TPMT_TK_HASHCHECK_t *validation,
		TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPM2B_DIGEST_t outHashTmp;
  TPMT_TK_HASHCHECK_t validationTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (hashAlg == TPM_ALG_NULL)
    return TPM_RC_VALUE;

  if (outHash == NULL)
    outHash = &outHashTmp;
  if (validation == NULL)
    validation = &validationTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (outHash, 0, sizeof (*outHash));
  grub_memset (validation, 0, sizeof (*validation));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (data != NULL)
    grub_Tss2_MU_TPM2B_Marshal (&in, data->size, data->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_buffer_pack_u16 (&in, hashAlg);
  grub_tpm2_buffer_pack_u32 (&in, hierarchy);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_Hash, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (&out, outHash);
  grub_Tss2_MU_TPMT_TK_HASHCHECK_Unmarshal (&out, validation);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_verifysignature (const TPMI_DH_OBJECT_t keyHandle,
			   const TPMS_AUTH_COMMAND_t *authCommand,
			   const TPM2B_DIGEST_t *digest,
			   const TPMT_SIGNATURE_t *signature,
			   TPMT_TK_VERIFIED_t *validation,
			   TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPMT_TK_VERIFIED_t validationTmp;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (digest == NULL || signature == NULL)
    return TPM_RC_VALUE;

  if (validation == NULL)
    validation = &validationTmp;
  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (validation, 0, sizeof (*validation));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_buffer_pack_u32 (&in, keyHandle);
  grub_Tss2_MU_TPM2B_Marshal (&in, digest->size, digest->buffer);
  grub_Tss2_MU_TPMT_SIGNATURE_Marshal (&in, signature);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_VerifySignature, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPMT_TK_VERIFIED_Unmarshal (&out, validation);
  if (tag == TPM_ST_SESSIONS)
    grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_policyauthorize (const TPMI_SH_POLICY_t policySession,
			   const TPMS_AUTH_COMMAND_t *authCommand,
			   const TPM2B_DIGEST_t *approvedPolicy,
			   const TPM2B_NONCE_t *policyRef,
			   const TPM2B_NAME_t *keySign,
			   const TPMT_TK_VERIFIED_t *checkTicket,
			   TPMS_AUTH_RESPONSE_t *authResponse)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE_t authResponseTmp;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  if (approvedPolicy == NULL || keySign == NULL || checkTicket == NULL)
    return TPM_RC_VALUE;

  if (authResponse == NULL)
    authResponse = &authResponseTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, policySession);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPM2B_Marshal (&in, approvedPolicy->size, approvedPolicy->buffer);
  if (policyRef != NULL)
    grub_Tss2_MU_TPM2B_Marshal (&in, policyRef->size, policyRef->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_Tss2_MU_TPM2B_Marshal (&in, keySign->size, keySign->name);
  grub_Tss2_MU_TPMT_TK_VERIFIED_Marshal (&in, checkTicket);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_PolicyAuthorize, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    {
      grub_tpm2_buffer_unpack_u32 (&out, &param_size);
      grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
    }
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_testparms (const TPMT_PUBLIC_PARMS_t *parms,
		     const TPMS_AUTH_COMMAND_t *authCommand)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;

  if (parms == NULL)
    return TPM_RC_VALUE;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_Tss2_MU_TPMT_PUBLIC_PARMS_Marshal (&in, parms);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_TestParms, &responseCode, &in,
				 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_nv_definespace (const TPMI_RH_PROVISION_t authHandle,
			  const TPMS_AUTH_COMMAND_t *authCommand,
			  const TPM2B_AUTH_t *auth,
			  const TPM2B_NV_PUBLIC_t *publicInfo)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;

  if (publicInfo == NULL)
    return TPM_RC_VALUE;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, authHandle);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (auth != NULL)
    grub_Tss2_MU_TPM2B_Marshal (&in, auth->size, auth->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_Tss2_MU_TPM2B_NV_PUBLIC_Marshal (&in, publicInfo);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_NV_DefineSpace, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_nv_undefinespace (const TPMI_RH_PROVISION_t authHandle,
			    const TPMI_RH_NV_INDEX_t nvIndex,
			    const TPMS_AUTH_COMMAND_t *authCommand)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, authHandle);
  grub_tpm2_buffer_pack_u32 (&in, nvIndex);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_NV_UndefineSpace, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_nv_readpublic (const TPMI_RH_NV_INDEX_t nvIndex,
			 const TPMS_AUTH_COMMAND_t *authCommand,
			 TPM2B_NV_PUBLIC_t *nvPublic,
			 TPM2B_NAME_t *nvName)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, nvIndex);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_NV_ReadPublic, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPM2B_NV_PUBLIC_Unmarshal (&out, nvPublic);
  grub_Tss2_MU_TPM2B_NAME_Unmarshal (&out, nvName);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_nv_read (const TPMI_RH_NV_AUTH_t authHandle,
		   const TPMI_RH_NV_INDEX_t nvIndex,
		   const TPMS_AUTH_COMMAND_t *authCommand,
		   const grub_uint16_t size,
		   const grub_uint16_t offset,
		   TPM2B_MAX_NV_BUFFER_t *data)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;
  grub_uint32_t param_size;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, authHandle);
  grub_tpm2_buffer_pack_u32 (&in, nvIndex);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_buffer_pack_u16 (&in, size);
  grub_tpm2_buffer_pack_u16 (&in, offset);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_NV_Read, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_Tss2_MU_TPM2B_NAX_NV_BUFFER_Unmarshal (&out, data);
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC_t
grub_tpm2_nv_write (const TPMI_RH_NV_AUTH_t authHandle,
		    const TPMI_RH_NV_INDEX_t nvIndex,
		    const TPMS_AUTH_COMMAND_t *authCommand,
		    const TPM2B_MAX_NV_BUFFER_t *data,
		    const grub_uint16_t offset)
{
  TPM_RC_t rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG_t tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC_t responseCode;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, authHandle);
  grub_tpm2_buffer_pack_u32 (&in, nvIndex);
  if (authCommand != NULL)
    grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_Tss2_MU_TPM2B_Marshal (&in, data->size, data->buffer);
  grub_tpm2_buffer_pack_u16 (&in, offset);
  if (in.error != 0)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = tpm2_submit_command (tag, TPM_CC_NV_Write, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  if (out.error != 0)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}
