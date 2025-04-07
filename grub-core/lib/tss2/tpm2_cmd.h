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

#ifndef GRUB_TPM2_COMMANDS_HEADER
#define GRUB_TPM2_COMMANDS_HEADER 1

#include <tss2_structs.h>

extern TPM_RC_t
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
			 TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
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
			    TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_policypcr (const TPMI_SH_POLICY_t policySession,
		     const TPMS_AUTH_COMMAND_t *authCommand,
		     const TPM2B_DIGEST_t *pcrDigest,
		     const TPML_PCR_SELECTION_t *pcrs,
		     TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_readpublic (const TPMI_DH_OBJECT_t objectHandle,
		      const TPMS_AUTH_COMMAND_t *authCommand,
		      TPM2B_PUBLIC_t *outPublic);

extern TPM_RC_t
grub_tpm2_load (const TPMI_DH_OBJECT_t parent_handle,
		const TPMS_AUTH_COMMAND_t *authCommand,
		const TPM2B_PRIVATE_t *inPrivate,
		const TPM2B_PUBLIC_t *inPublic,
		TPM_HANDLE_t *objectHandle,
		TPM2B_NAME_t *name,
		TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_loadexternal (const TPMS_AUTH_COMMAND_t *authCommand,
			const TPM2B_SENSITIVE_t *inPrivate,
			const TPM2B_PUBLIC_t *inPublic,
			const TPMI_RH_HIERARCHY_t hierarchy,
			TPM_HANDLE_t *objectHandle,
			TPM2B_NAME_t *name,
			TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_unseal (const TPMI_DH_OBJECT_t item_handle,
		  const TPMS_AUTH_COMMAND_t *authCommand,
		  TPM2B_SENSITIVE_DATA_t *outData,
		  TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_flushcontext (const TPMI_DH_CONTEXT_t handle);

extern TPM_RC_t
grub_tpm2_pcr_read (const TPMS_AUTH_COMMAND_t *authCommand,
		    const TPML_PCR_SELECTION_t *pcrSelectionIn,
		    grub_uint32_t *pcrUpdateCounter,
		    TPML_PCR_SELECTION_t *pcrSelectionOut,
		    TPML_DIGEST_t *pcrValues,
		    TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_policygetdigest (const TPMI_SH_POLICY_t policySession,
			   const TPMS_AUTH_COMMAND_t *authCommand,
			   TPM2B_DIGEST_t *policyDigest,
			   TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
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
		  TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_evictcontrol (const TPMI_RH_PROVISION_t auth,
			const TPMI_DH_OBJECT_t objectHandle,
			const TPMS_AUTH_COMMAND_t *authCommand,
			const TPMI_DH_PERSISTENT_t persistentHandle,
			TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_hash (const TPMS_AUTH_COMMAND_t *authCommand,
		const TPM2B_MAX_BUFFER_t *data,
		const TPMI_ALG_HASH_t hashAlg,
		const TPMI_RH_HIERARCHY_t hierarchy,
		TPM2B_DIGEST_t *outHash,
		TPMT_TK_HASHCHECK_t *validation,
		TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_verifysignature (const TPMI_DH_OBJECT_t keyHandle,
			   const TPMS_AUTH_COMMAND_t *authCommand,
			   const TPM2B_DIGEST_t *digest,
			   const TPMT_SIGNATURE_t *signature,
			   TPMT_TK_VERIFIED_t *validation,
			   TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_policyauthorize (const TPMI_SH_POLICY_t policySession,
			   const TPMS_AUTH_COMMAND_t *authCommand,
			   const TPM2B_DIGEST_t *approvedPolicy,
			   const TPM2B_NONCE_t *policyRef,
			   const TPM2B_NAME_t *keySign,
			   const TPMT_TK_VERIFIED_t *checkTicket,
			   TPMS_AUTH_RESPONSE_t *authResponse);

extern TPM_RC_t
grub_tpm2_testparms (const TPMT_PUBLIC_PARMS_t *parms,
		     const TPMS_AUTH_COMMAND_t *authCommand);

extern TPM_RC_t
grub_tpm2_nv_definespace (const TPMI_RH_PROVISION_t authHandle,
			  const TPMS_AUTH_COMMAND_t *authCommand,
			  const TPM2B_AUTH_t *auth,
			  const TPM2B_NV_PUBLIC_t *publicInfo);

extern TPM_RC_t
grub_tpm2_nv_undefinespace (const TPMI_RH_PROVISION_t authHandle,
			    const TPMI_RH_NV_INDEX_t nvIndex,
			    const TPMS_AUTH_COMMAND_t *authCommand);

extern TPM_RC_t
grub_tpm2_nv_readpublic (const TPMI_RH_NV_INDEX_t nvIndex,
			 const TPMS_AUTH_COMMAND_t *authCommand,
			 TPM2B_NV_PUBLIC_t *nvPublic,
			 TPM2B_NAME_t *nvName);

extern TPM_RC_t
grub_tpm2_nv_read (const TPMI_RH_NV_AUTH_t authHandle,
		   const TPMI_RH_NV_INDEX_t nvIndex,
		   const TPMS_AUTH_COMMAND_t *authCommand,
		   const grub_uint16_t size,
		   const grub_uint16_t offset,
		   TPM2B_MAX_NV_BUFFER_t *data);

extern TPM_RC_t
grub_tpm2_nv_write (const TPMI_RH_NV_AUTH_t authHandle,
		    const TPMI_RH_NV_INDEX_t nvIndex,
		    const TPMS_AUTH_COMMAND_t *authCommand,
		    const TPM2B_MAX_NV_BUFFER_t *data,
		    const grub_uint16_t offset);

#endif /* ! GRUB_TPM2_COMMANDS_HEADER */
