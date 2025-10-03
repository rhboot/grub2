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

#ifndef GRUB_TPM2_MU_HEADER
#define GRUB_TPM2_MU_HEADER 1

#include <tss2_buffer.h>
#include <tss2_structs.h>

extern void
grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (grub_tpm2_buffer_t buffer,
					const TPMS_AUTH_COMMAND_t *authCommand);

extern void
grub_Tss2_MU_TPM2B_Marshal (grub_tpm2_buffer_t buffer,
			    const grub_uint16_t size,
			    const grub_uint8_t *b);

extern void
grub_Tss2_MU_TPMU_SYM_KEY_BITS_Marshal (grub_tpm2_buffer_t buffer,
					const TPMI_ALG_SYM_OBJECT_t algorithm,
					const TPMU_SYM_KEY_BITS_t *p);

extern void
grub_Tss2_MU_TPMU_SYM_MODE_Marshal (grub_tpm2_buffer_t buffer,
				    const TPMI_ALG_SYM_OBJECT_t algorithm,
				    const TPMU_SYM_MODE_t *p);

extern void
grub_Tss2_MU_TPMT_SYM_DEF_Marshal (grub_tpm2_buffer_t buffer,
				   const TPMT_SYM_DEF_t *p);

extern void
grub_Tss2_MU_TPMS_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buffer,
					 const TPMS_PCR_SELECTION_t *pcrSelection);

extern void
grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buffer,
					 const TPML_PCR_SELECTION_t *pcrSelection);

extern void
grub_Tss2_MU_TPMA_OBJECT_Marshal (grub_tpm2_buffer_t buffer,
				  const TPMA_OBJECT_t *p);

extern void
grub_Tss2_MU_TPMS_SCHEME_XOR_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMS_SCHEME_XOR_t *p);

extern void
grub_Tss2_MU_TPMS_SCHEME_HMAC_Marshal (grub_tpm2_buffer_t buffer,
				       const TPMS_SCHEME_HMAC_t *p);

extern void
grub_Tss2_MU_TPMU_SCHEME_KEYEDHASH_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMI_ALG_KEYEDHASH_SCHEME_t scheme,
					    const TPMU_SCHEME_KEYEDHASH_t *p);

extern void
grub_Tss2_MU_TPMT_KEYEDHASH_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMT_KEYEDHASH_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMS_KEYEDHASH_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					   const TPMS_KEYEDHASH_PARMS_t *p);

extern void
grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Marshal (grub_tpm2_buffer_t buffer,
					  const TPMT_SYM_DEF_OBJECT_t *p);

extern void
grub_Tss2_MU_TPMU_ASYM_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				       const TPMI_ALG_RSA_DECRYPT_t scheme,
				       const TPMU_ASYM_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMT_RSA_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_RSA_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMS_RSA_PARMS_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_RSA_PARMS_t *p);

extern void
grub_Tss2_MU_TPMS_SYMCIPHER_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					   const TPMS_SYMCIPHER_PARMS_t *p);

extern void
grub_Tss2_MU_TPMT_ECC_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_ECC_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMU_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMI_ALG_KDF_t scheme,
				      const TPMU_KDF_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMT_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_KDF_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMS_ECC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_ECC_PARMS_t *p);

extern void
grub_Tss2_MU_TPMU_PUBLIC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					const grub_uint32_t type,
					const TPMU_PUBLIC_PARMS_t *p);

extern void
grub_Tss2_MU_TPMS_ECC_POINT_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_ECC_POINT_t *p);

extern void
grub_Tss2_MU_TPMU_PUBLIC_ID_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMI_ALG_PUBLIC_t type,
				     const TPMU_PUBLIC_ID_t *p);

extern void
grub_Tss2_MU_TPMT_PUBLIC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					const TPMT_PUBLIC_PARMS_t *p);

extern void
grub_Tss2_MU_TPMT_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				  const TPMT_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPM2B_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				   const TPM2B_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPMS_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMS_SENSITIVE_CREATE_t *p);

extern void
grub_Tss2_MU_TPM2B_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buffer,
					     const TPM2B_SENSITIVE_CREATE_t *sensitiveCreate);

extern void
grub_Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Marshal (grub_tpm2_buffer_t buffer,
                                               const TPMI_ALG_PUBLIC_t type,
                                               const TPMU_SENSITIVE_COMPOSITE_t *p);
extern void
grub_Tss2_MU_TPMT_SENSITIVE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMT_SENSITIVE_t *p);

extern void
grub_Tss2_MU_TPM2B_SENSITIVE_Marshal (grub_tpm2_buffer_t buffer,
                                      const TPM2B_SENSITIVE_t *p);

extern void
grub_Tss2_MU_TPMS_SIGNATURE_RSA_Marshal (grub_tpm2_buffer_t buffer,
                                         const TPMS_SIGNATURE_RSA_t *p);

extern void
grub_Tss2_MU_TPMS_SIGNATURE_ECC_Marshal (grub_tpm2_buffer_t buffer,
                                         const TPMS_SIGNATURE_ECC_t *p);

extern void
grub_Tss2_MU_TPMU_HA_Marshal (grub_tpm2_buffer_t buffer,
                              const TPMI_ALG_HASH_t hashAlg,
                              const TPMU_HA_t *p);

extern void
grub_Tss2_MU_TPMT_HA_Marshal (grub_tpm2_buffer_t buffer,
                              const TPMT_HA_t *p);

extern void
grub_Tss2_MU_TPMU_SIGNATURE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMI_ALG_SIG_SCHEME_t sigAlg,
                                     const TPMU_SIGNATURE_t *p);

extern void
grub_Tss2_MU_TPMT_SIGNATURE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMT_SIGNATURE_t *p);

extern void
grub_Tss2_MU_TPMT_TK_VERIFIED_Marshal (grub_tpm2_buffer_t buffer,
                                       const TPMT_TK_VERIFIED_t *p);

extern void
grub_Tss2_MU_TPMS_NV_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_NV_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPM2B_NV_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				      const TPM2B_NV_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPMS_AUTH_RESPONSE_t *p);

extern void
grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (grub_tpm2_buffer_t buffer,
				     TPM2B_DIGEST_t *digest);

extern void
grub_Tss2_MU_TPM2B_NONCE_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPM2B_NONCE_t *nonce);

extern void
grub_Tss2_MU_TPM2B_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
				   TPM2B_DATA_t *data);

extern void
grub_Tss2_MU_TPMS_CREATION_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPMS_CREATION_DATA_t *data);

extern void
grub_Tss2_MU_TPM2B_CREATION_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPM2B_CREATION_DATA_t *data);

extern void
grub_Tss2_MU_TPM2B_PRIVATE_Unmarshal (grub_tpm2_buffer_t buffer,
				      TPM2B_PRIVATE_t *private);

extern void
grub_Tss2_MU_TPM2B_SENSITIVE_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPM2B_SENSITIVE_DATA_t *data);

extern void
grub_Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPM2B_PUBLIC_KEY_RSA_t *rsa);

extern void
grub_Tss2_MU_TPM2B_ECC_PARAMETER_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPM2B_ECC_PARAMETER_t *param);

extern void
grub_Tss2_MU_TPMA_OBJECT_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPMA_OBJECT_t *p);

extern void
grub_Tss2_MU_TPMS_SCHEME_HMAC_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMS_SCHEME_HMAC_t *p);

extern void
grub_Tss2_MU_TPMS_SCHEME_XOR_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMS_SCHEME_XOR_t *p);

extern void
grub_Tss2_MU_TPMU_SCHEME_KEYEDHASH_Unmarshal (grub_tpm2_buffer_t buffer,
					      TPMI_ALG_KEYEDHASH_SCHEME_t scheme,
					      TPMU_SCHEME_KEYEDHASH_t *p);

extern void
grub_Tss2_MU_TPMT_KEYEDHASH_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					      TPMT_KEYEDHASH_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMS_KEYEDHASH_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_KEYEDHASH_PARMS_t *p);

extern void
grub_Tss2_MU_TPMU_SYM_KEY_BITS_Unmarshal (grub_tpm2_buffer_t buffer,
					  TPMI_ALG_SYM_OBJECT_t algorithm,
					  TPMU_SYM_KEY_BITS_t *p);

extern void
grub_Tss2_MU_TPMU_SYM_MODE_Unmarshal (grub_tpm2_buffer_t buffer,
				      TPMI_ALG_SYM_OBJECT_t algorithm,
				      TPMU_SYM_MODE_t *p);

extern void
grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPMT_SYM_DEF_OBJECT_t *p);

extern void
grub_Tss2_MU_TPMS_SYMCIPHER_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_SYMCIPHER_PARMS_t *p);

extern void
grub_Tss2_MU_TPMU_ASYM_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMI_ALG_RSA_DECRYPT_t scheme,
					 TPMU_ASYM_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMT_RSA_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_RSA_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMS_RSA_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_RSA_PARMS_t *p);

extern void
grub_Tss2_MU_TPMT_ECC_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_ECC_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMU_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMI_ALG_KDF_t scheme,
					TPMU_KDF_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMT_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_KDF_SCHEME_t *p);

extern void
grub_Tss2_MU_TPMS_ECC_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_ECC_PARMS_t *p);

extern void
grub_Tss2_MU_TPMU_PUBLIC_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					  grub_uint32_t type,
					  TPMU_PUBLIC_PARMS_t *p);

extern void
grub_Tss2_MU_TPMS_ECC_POINT_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_ECC_POINT_t *p);

extern void
grub_Tss2_MU_TPMU_PUBLIC_ID_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMI_ALG_PUBLIC_t type,
				       TPMU_PUBLIC_ID_t *p);

extern void
grub_Tss2_MU_TPMT_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPMT_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				     TPM2B_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPMS_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_NV_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPM2B_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
					TPM2B_NV_PUBLIC_t *p);

extern void
grub_Tss2_MU_TPM2B_NAX_NV_BUFFER_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPM2B_MAX_NV_BUFFER_t *p);

extern void
grub_Tss2_MU_TPM2B_NAME_Unmarshal (grub_tpm2_buffer_t buffer,
				   TPM2B_NAME_t *n);

extern void
grub_Tss2_MU_TPMS_TAGGED_PROPERTY_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_TAGGED_PROPERTY_t *property);

extern void
grub_Tss2_MU_TPMT_TK_CREATION_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMT_TK_CREATION_t *p);

extern void
grub_Tss2_MU_TPMT_TK_HASHCHECK_Unmarshal (grub_tpm2_buffer_t buffer,
                                          TPMT_TK_HASHCHECK_t *p);

extern void
grub_Tss2_MU_TPMT_TK_VERIFIED_Unmarshal (grub_tpm2_buffer_t buffer,
                                         TPMT_TK_VERIFIED_t *p);

extern void
grub_Tss2_MU_TPMS_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPMS_PCR_SELECTION_t *pcrSelection);

extern void
grub_Tss2_MU_TPML_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPML_PCR_SELECTION_t *pcrSelection);

extern void
grub_Tss2_MU_TPML_DIGEST_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPML_DIGEST_t *digest);

extern void
grub_Tss2_MU_TPML_DIGEST_VALUE_Unmarshal (grub_tpm2_buffer_t buffer,
					  TPML_DIGEST_VALUES_t *digests);

extern void
grub_Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal (grub_tpm2_buffer_t buffer,
                                           TPMS_SIGNATURE_RSA_t *p);

extern void
grub_Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal (grub_tpm2_buffer_t buffer,
                                           TPMS_SIGNATURE_ECC_t *p);

extern void
grub_Tss2_MU_TPMU_HA_Unmarshal (grub_tpm2_buffer_t buffer,
                                TPMI_ALG_HASH_t hashAlg,
                                TPMU_HA_t *p);

extern void
grub_Tss2_MU_TPMT_HA_Unmarshal (grub_tpm2_buffer_t buffer,
                                TPMT_HA_t *p);

extern void
grub_Tss2_MU_TPMU_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buffer,
                                       TPMI_ALG_SIG_SCHEME_t sigAlg,
                                       TPMU_SIGNATURE_t *p);

extern void
grub_Tss2_MU_TPMT_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buffer,
                                       TPMT_SIGNATURE_t *p);

#endif /* ! GRUB_TPM2_MU_HEADER */
