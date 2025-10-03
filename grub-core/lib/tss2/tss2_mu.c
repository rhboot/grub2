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

#include <grub/mm.h>
#include <grub/misc.h>

#include <tss2_mu.h>

void
grub_Tss2_MU_TPMS_AUTH_COMMAND_Marshal (grub_tpm2_buffer_t buffer,
					const TPMS_AUTH_COMMAND_t *authCommand)
{
  grub_uint32_t start;
  grub_uint32_t tmp;

  grub_tpm2_buffer_pack_u32 (buffer, 0);
  start = buffer->size;

  grub_tpm2_buffer_pack_u32 (buffer, authCommand->sessionHandle);

  grub_tpm2_buffer_pack_u16 (buffer, authCommand->nonce.size);
  grub_tpm2_buffer_pack (buffer, authCommand->nonce.buffer, authCommand->nonce.size);

  grub_tpm2_buffer_pack_u8 (buffer, *((const grub_uint8_t *) &authCommand->sessionAttributes));

  grub_tpm2_buffer_pack_u16 (buffer, authCommand->hmac.size);
  grub_tpm2_buffer_pack (buffer, authCommand->hmac.buffer, authCommand->hmac.size);

  tmp = grub_cpu_to_be32 (buffer->size - start);
  grub_memcpy (&buffer->data[start - sizeof (grub_uint32_t)], &tmp, sizeof (tmp));
}

void
grub_Tss2_MU_TPM2B_Marshal (grub_tpm2_buffer_t buffer,
			    const grub_uint16_t size,
			    const grub_uint8_t *b)
{
  grub_uint16_t i;

  grub_tpm2_buffer_pack_u16 (buffer, size);

  for (i = 0; i < size; i++)
    grub_tpm2_buffer_pack_u8 (buffer, b[i]);
}

void
grub_Tss2_MU_TPMU_SYM_KEY_BITS_Marshal (grub_tpm2_buffer_t buffer,
					const TPMI_ALG_SYM_OBJECT_t algorithm,
					const TPMU_SYM_KEY_BITS_t *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
    case TPM_ALG_XOR:
      grub_tpm2_buffer_pack_u16 (buffer, *((const grub_uint16_t *) p));
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMU_SYM_MODE_Marshal (grub_tpm2_buffer_t buffer,
				    const TPMI_ALG_SYM_OBJECT_t algorithm,
				    const TPMU_SYM_MODE_t *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
      grub_tpm2_buffer_pack_u16 (buffer, *((const grub_uint16_t *) p));
      break;
    case TPM_ALG_XOR:
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_SYM_DEF_Marshal (grub_tpm2_buffer_t buffer,
				   const TPMT_SYM_DEF_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->algorithm);
  grub_Tss2_MU_TPMU_SYM_KEY_BITS_Marshal (buffer, p->algorithm, &p->keyBits);
  grub_Tss2_MU_TPMU_SYM_MODE_Marshal (buffer, p->algorithm, &p->mode);
}

void
grub_Tss2_MU_TPMS_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buffer,
					 const TPMS_PCR_SELECTION_t *pcrSelection)
{
  grub_uint32_t i;

  grub_tpm2_buffer_pack_u16 (buffer, pcrSelection->hash);
  grub_tpm2_buffer_pack_u8 (buffer, pcrSelection->sizeOfSelect);

  for (i = 0; i < pcrSelection->sizeOfSelect; i++)
    grub_tpm2_buffer_pack_u8 (buffer, pcrSelection->pcrSelect[i]);
}

void
grub_Tss2_MU_TPML_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buffer,
					 const TPML_PCR_SELECTION_t *pcrSelection)
{
  grub_uint32_t i;

  grub_tpm2_buffer_pack_u32 (buffer, pcrSelection->count);

  for (i = 0; i < pcrSelection->count; i++)
    grub_Tss2_MU_TPMS_PCR_SELECTION_Marshal (buffer, &pcrSelection->pcrSelections[i]);
}

void
grub_Tss2_MU_TPMA_OBJECT_Marshal (grub_tpm2_buffer_t buffer,
				  const TPMA_OBJECT_t *p)
{
  grub_tpm2_buffer_pack_u32 (buffer, *((const grub_uint32_t *) p));
}

void
grub_Tss2_MU_TPMS_SCHEME_XOR_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMS_SCHEME_XOR_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hashAlg);
  grub_tpm2_buffer_pack_u16 (buffer, p->kdf);
}

void
grub_Tss2_MU_TPMS_SCHEME_HMAC_Marshal (grub_tpm2_buffer_t buffer,
				       const TPMS_SCHEME_HMAC_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hashAlg);
}

void
grub_Tss2_MU_TPMU_SCHEME_KEYEDHASH_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMI_ALG_KEYEDHASH_SCHEME_t scheme,
					    const TPMU_SCHEME_KEYEDHASH_t *p)
{
  switch (scheme)
    {
    case TPM_ALG_HMAC:
      grub_Tss2_MU_TPMS_SCHEME_HMAC_Marshal (buffer, &p->hmac);
      break;
    case TPM_ALG_XOR:
      grub_Tss2_MU_TPMS_SCHEME_XOR_Marshal (buffer, &p->exclusiveOr);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_KEYEDHASH_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMT_KEYEDHASH_SCHEME_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_Tss2_MU_TPMU_SCHEME_KEYEDHASH_Marshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMS_KEYEDHASH_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					   const TPMS_KEYEDHASH_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_KEYEDHASH_SCHEME_Marshal (buffer, &p->scheme);
}

void
grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Marshal (grub_tpm2_buffer_t buffer,
					  const TPMT_SYM_DEF_OBJECT_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->algorithm);
  grub_Tss2_MU_TPMU_SYM_KEY_BITS_Marshal (buffer, p->algorithm, &p->keyBits);
  grub_Tss2_MU_TPMU_SYM_MODE_Marshal (buffer, p->algorithm, &p->mode);
}

void
grub_Tss2_MU_TPMU_ASYM_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				       const TPMI_ALG_RSA_DECRYPT_t scheme,
				       const TPMU_ASYM_SCHEME_t *p __attribute__ ((unused)))
{
  switch (scheme)
    {
    case TPM_ALG_NULL:
      break;
    default:
      /* Unsupported */
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_RSA_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_RSA_SCHEME_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_Tss2_MU_TPMU_ASYM_SCHEME_Marshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMS_RSA_PARMS_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_RSA_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Marshal (buffer, &p->symmetric);
  grub_Tss2_MU_TPMT_RSA_SCHEME_Marshal (buffer, &p->scheme);
  grub_tpm2_buffer_pack_u16 (buffer, p->keyBits);
  grub_tpm2_buffer_pack_u32 (buffer, p->exponent);
}

void
grub_Tss2_MU_TPMS_SYMCIPHER_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					   const TPMS_SYMCIPHER_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Marshal (buffer, &p->sym);
}

void
grub_Tss2_MU_TPMT_ECC_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_ECC_SCHEME_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_Tss2_MU_TPMU_ASYM_SCHEME_Marshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMU_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMI_ALG_KDF_t scheme,
				      const TPMU_KDF_SCHEME_t *p)
{
  switch (scheme)
    {
    case TPM_ALG_MGF1:
      grub_tpm2_buffer_pack_u16 (buffer, p->mgf1.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_56A:
      grub_tpm2_buffer_pack_u16 (buffer, p->kdf1_sp800_56a.hashAlg);
      break;
    case TPM_ALG_KDF2:
      grub_tpm2_buffer_pack_u16 (buffer, p->kdf2.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_108:
      grub_tpm2_buffer_pack_u16 (buffer, p->kdf1_sp800_108.hashAlg);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_KDF_SCHEME_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_Tss2_MU_TPMU_KDF_SCHEME_Marshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMS_ECC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_ECC_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Marshal (buffer, &p->symmetric);
  grub_Tss2_MU_TPMT_ECC_SCHEME_Marshal (buffer, &p->scheme);
  grub_tpm2_buffer_pack_u16 (buffer, p->curveID);
  grub_Tss2_MU_TPMT_KDF_SCHEME_Marshal (buffer, &p->kdf);
}

void
grub_Tss2_MU_TPMU_PUBLIC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					const grub_uint32_t type,
					const TPMU_PUBLIC_PARMS_t *p)
{
  switch (type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_Tss2_MU_TPMS_KEYEDHASH_PARMS_Marshal (buffer, &p->keyedHashDetail);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_Tss2_MU_TPMS_SYMCIPHER_PARMS_Marshal (buffer, &p->symDetail);
      break;
    case TPM_ALG_RSA:
      grub_Tss2_MU_TPMS_RSA_PARMS_Marshal (buffer, &p->rsaDetail);
      break;
    case TPM_ALG_ECC:
      grub_Tss2_MU_TPMS_ECC_PARMS_Marshal (buffer, &p->eccDetail);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMS_ECC_POINT_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_ECC_POINT_t *p)
{
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->x.size, p->x.buffer);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->y.size, p->y.buffer);
}

void
grub_Tss2_MU_TPMU_PUBLIC_ID_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMI_ALG_PUBLIC_t type,
				     const TPMU_PUBLIC_ID_t *p)
{
  switch(type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_Tss2_MU_TPM2B_Marshal (buffer, p->keyedHash.size, p->keyedHash.buffer);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_Tss2_MU_TPM2B_Marshal (buffer, p->sym.size, p->sym.buffer);
      break;
    case TPM_ALG_RSA:
      grub_Tss2_MU_TPM2B_Marshal (buffer, p->rsa.size, p->rsa.buffer);
      break;
    case TPM_ALG_ECC:
      grub_Tss2_MU_TPMS_ECC_POINT_Marshal (buffer, &p->ecc);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_PUBLIC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					const TPMT_PUBLIC_PARMS_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->type);
  grub_Tss2_MU_TPMU_PUBLIC_PARMS_Marshal (buffer, p->type, &p->parameters);
}

void
grub_Tss2_MU_TPMT_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				  const TPMT_PUBLIC_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->type);
  grub_tpm2_buffer_pack_u16 (buffer, p->nameAlg);
  grub_Tss2_MU_TPMA_OBJECT_Marshal (buffer, &p->objectAttributes);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->authPolicy.size, p->authPolicy.buffer);
  grub_Tss2_MU_TPMU_PUBLIC_PARMS_Marshal (buffer, p->type, &p->parameters);
  grub_Tss2_MU_TPMU_PUBLIC_ID_Marshal (buffer, p->type, &p->unique);
}

void
grub_Tss2_MU_TPM2B_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				   const TPM2B_PUBLIC_t *p)
{
  grub_uint32_t start;
  grub_uint16_t size;

  if (p)
    {
      grub_tpm2_buffer_pack_u16 (buffer, p->size);

      start = buffer->size;
      grub_Tss2_MU_TPMT_PUBLIC_Marshal (buffer, &p->publicArea);
      size = grub_cpu_to_be16 (buffer->size - start);
      grub_memcpy (&buffer->data[start - sizeof (grub_uint16_t)], &size, sizeof (size));
    }
  else
    grub_tpm2_buffer_pack_u16 (buffer, 0);
}

void
grub_Tss2_MU_TPMS_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMS_SENSITIVE_CREATE_t *p)
{
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->userAuth.size, p->userAuth.buffer);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->data.size, p->data.buffer);
}

void
grub_Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Marshal (grub_tpm2_buffer_t buffer,
                                               const TPMI_ALG_PUBLIC_t type,
                                               const TPMU_SENSITIVE_COMPOSITE_t *p)
{
  switch(type)
    {
    case TPM_ALG_RSA:
      grub_Tss2_MU_TPM2B_Marshal (buffer, p->rsa.size, p->rsa.buffer);
      break;
    case TPM_ALG_ECC:
      grub_Tss2_MU_TPM2B_Marshal (buffer, p->ecc.size, p->ecc.buffer);
      break;
    case TPM_ALG_KEYEDHASH:
      grub_Tss2_MU_TPM2B_Marshal (buffer, p->bits.size, p->bits.buffer);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_Tss2_MU_TPM2B_Marshal (buffer, p->sym.size, p->sym.buffer);
      break;
    default:
      buffer->error = 1;
    }
}

void
grub_Tss2_MU_TPMT_SENSITIVE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMT_SENSITIVE_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->sensitiveType);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->authValue.size, p->authValue.buffer);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->seedValue.size, p->seedValue.buffer);
  grub_Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Marshal (buffer, p->sensitiveType, &p->sensitive);
}

void
grub_Tss2_MU_TPM2B_SENSITIVE_Marshal (grub_tpm2_buffer_t buffer,
                                      const TPM2B_SENSITIVE_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->size);
  grub_Tss2_MU_TPMT_SENSITIVE_Marshal (buffer, &p->sensitiveArea);
}

void
grub_Tss2_MU_TPM2B_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buffer,
					     const TPM2B_SENSITIVE_CREATE_t *sensitiveCreate)
{
  grub_uint32_t start;
  grub_uint16_t size;

  if (sensitiveCreate)
    {
      grub_tpm2_buffer_pack_u16 (buffer, sensitiveCreate->size);
      start = buffer->size;
      grub_Tss2_MU_TPMS_SENSITIVE_CREATE_Marshal (buffer, &sensitiveCreate->sensitive);
      size = grub_cpu_to_be16 (buffer->size - start);

      grub_memcpy (&buffer->data[start - sizeof (grub_uint16_t)], &size, sizeof (size));
    }
  else
    grub_tpm2_buffer_pack_u16 (buffer, 0);
}

void
grub_Tss2_MU_TPMS_SIGNATURE_RSA_Marshal (grub_tpm2_buffer_t buffer,
                                         const TPMS_SIGNATURE_RSA_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hash);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->sig.size, p->sig.buffer);
}

void
grub_Tss2_MU_TPMS_SIGNATURE_ECC_Marshal (grub_tpm2_buffer_t buffer,
                                         const TPMS_SIGNATURE_ECC_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hash);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->signatureR.size, p->signatureR.buffer);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->signatureS.size, p->signatureS.buffer);
}

void
grub_Tss2_MU_TPMU_HA_Marshal (grub_tpm2_buffer_t buffer,
                              const TPMI_ALG_HASH_t hashAlg,
                              const TPMU_HA_t *p)
{
  grub_uint16_t i;

  switch (hashAlg)
    {
    case TPM_ALG_SHA1:
      for (i = 0; i < TPM_SHA1_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha1[i]);
      break;
    case TPM_ALG_SHA256:
      for (i = 0; i < TPM_SHA256_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha256[i]);
      break;
    case TPM_ALG_SHA384:
      for (i = 0; i < TPM_SHA384_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha384[i]);
      break;
    case TPM_ALG_SHA512:
      for (i = 0; i < TPM_SHA512_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha512[i]);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_HA_Marshal (grub_tpm2_buffer_t buffer,
                              const TPMT_HA_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hashAlg);
  grub_Tss2_MU_TPMU_HA_Marshal (buffer, p->hashAlg, &p->digest);
}

void
grub_Tss2_MU_TPMU_SIGNATURE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMI_ALG_SIG_SCHEME_t sigAlg,
                                     const TPMU_SIGNATURE_t *p)
{
  switch (sigAlg)
    {
    case TPM_ALG_RSASSA:
      grub_Tss2_MU_TPMS_SIGNATURE_RSA_Marshal (buffer, (TPMS_SIGNATURE_RSA_t *) &p->rsassa);
      break;
    case TPM_ALG_RSAPSS:
      grub_Tss2_MU_TPMS_SIGNATURE_RSA_Marshal (buffer, (TPMS_SIGNATURE_RSA_t *) &p->rsapss);
      break;
    case TPM_ALG_ECDSA:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC_t *) &p->ecdsa);
      break;
    case TPM_ALG_ECDAA:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC_t *) &p->ecdaa);
      break;
    case TPM_ALG_SM2:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC_t *) &p->sm2);
      break;
    case TPM_ALG_ECSCHNORR:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC_t *) &p->ecschnorr);
      break;
    case TPM_ALG_HMAC:
      grub_Tss2_MU_TPMT_HA_Marshal (buffer, &p->hmac);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_SIGNATURE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMT_SIGNATURE_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->sigAlg);
  grub_Tss2_MU_TPMU_SIGNATURE_Marshal (buffer, p->sigAlg, &p->signature);
}

void
grub_Tss2_MU_TPMT_TK_VERIFIED_Marshal (grub_tpm2_buffer_t buffer,
                                       const TPMT_TK_VERIFIED_t *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->tag);
  grub_tpm2_buffer_pack_u32 (buffer, p->hierarchy);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->digest.size, p->digest.buffer);
}

void
grub_Tss2_MU_TPMS_NV_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_NV_PUBLIC_t *p)
{
  grub_tpm2_buffer_pack_u32 (buffer, p->nvIndex);
  grub_tpm2_buffer_pack_u16 (buffer, p->nameAlg);
  grub_tpm2_buffer_pack_u32 (buffer, p->attributes);
  grub_Tss2_MU_TPM2B_Marshal (buffer, p->authPolicy.size, p->authPolicy.buffer);
  grub_tpm2_buffer_pack_u16 (buffer, p->dataSize);
}

void
grub_Tss2_MU_TPM2B_NV_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				      const TPM2B_NV_PUBLIC_t *p)
{
  grub_uint32_t start;
  grub_uint16_t size;

  if (p != NULL)
    {
      grub_tpm2_buffer_pack_u16 (buffer, p->size);

      start = buffer->size;
      grub_Tss2_MU_TPMS_NV_PUBLIC_Marshal (buffer, &p->nvPublic);
      size = grub_cpu_to_be16 (buffer->size - start);
      grub_memcpy (&buffer->data[start - sizeof (grub_uint16_t)], &size, sizeof (size));
    }
  else
    grub_tpm2_buffer_pack_u16 (buffer, 0);
}

static void
__Tss2_MU_TPM2B_BUFFER_Unmarshal (grub_tpm2_buffer_t buffer,
				  TPM2B_t *p, grub_uint16_t bound)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->size);

  if (p->size > bound)
    {
      buffer->error = 1;
      return;
    }

  grub_tpm2_buffer_unpack (buffer, &p->buffer, p->size);
}

#define TPM2B_BUFFER_UNMARSHAL(buffer, type, data) \
  __Tss2_MU_TPM2B_BUFFER_Unmarshal(buffer, (TPM2B_t *)data, sizeof(type) - sizeof(grub_uint16_t))

void
grub_Tss2_MU_TPMS_AUTH_RESPONSE_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPMS_AUTH_RESPONSE_t *p)
{
  grub_uint8_t tmp;
  grub_uint32_t tmp32;

  grub_tpm2_buffer_unpack_u16 (buffer, &p->nonce.size);

  if (p->nonce.size)
    grub_tpm2_buffer_unpack (buffer, &p->nonce.buffer, p->nonce.size);

  grub_tpm2_buffer_unpack_u8 (buffer, &tmp);
  tmp32 = tmp;
  grub_memcpy (&p->sessionAttributes, &tmp32, sizeof (grub_uint32_t));

  grub_tpm2_buffer_unpack_u16 (buffer, &p->hmac.size);

  if (p->hmac.size)
    grub_tpm2_buffer_unpack (buffer, &p->hmac.buffer, p->hmac.size);
}

void
grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (grub_tpm2_buffer_t buffer,
				     TPM2B_DIGEST_t *digest)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_DIGEST_t, digest);
}

void
grub_Tss2_MU_TPM2B_NONCE_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPM2B_NONCE_t *nonce)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_NONCE_t, nonce);
}

void
grub_Tss2_MU_TPM2B_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
				   TPM2B_DATA_t *data)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_DATA_t, data);
}

void
grub_Tss2_MU_TPMS_CREATION_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPMS_CREATION_DATA_t *data)
{
  grub_Tss2_MU_TPML_PCR_SELECTION_Unmarshal (buffer, &data->pcrSelect);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &data->pcrDigest);
  grub_tpm2_buffer_unpack_u8 (buffer, (grub_uint8_t *)&data->locality);
  grub_tpm2_buffer_unpack_u16 (buffer, &data->parentNameAlg);
  grub_Tss2_MU_TPM2B_NAME_Unmarshal (buffer, &data->parentName);
  grub_Tss2_MU_TPM2B_NAME_Unmarshal (buffer, &data->parentQualifiedName);
  grub_Tss2_MU_TPM2B_DATA_Unmarshal (buffer, &data->outsideInfo);
}

void
grub_Tss2_MU_TPM2B_CREATION_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPM2B_CREATION_DATA_t *data)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &data->size);
  grub_Tss2_MU_TPMS_CREATION_DATA_Unmarshal (buffer, &data->creationData);
}

void
grub_Tss2_MU_TPM2B_PRIVATE_Unmarshal (grub_tpm2_buffer_t buffer,
				      TPM2B_PRIVATE_t *private)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_PRIVATE_t, private);
}

void
grub_Tss2_MU_TPM2B_SENSITIVE_DATA_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPM2B_SENSITIVE_DATA_t *data)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_SENSITIVE_DATA_t, data);
}

void
grub_Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPM2B_PUBLIC_KEY_RSA_t *rsa)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_PUBLIC_KEY_RSA_t, rsa);
}

void
grub_Tss2_MU_TPM2B_ECC_PARAMETER_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPM2B_ECC_PARAMETER_t *param)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_ECC_PARAMETER_t, param);
}

void
grub_Tss2_MU_TPMA_OBJECT_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPMA_OBJECT_t *p)
{
  grub_tpm2_buffer_unpack_u32 (buffer, (grub_uint32_t *) p);
}

void
grub_Tss2_MU_TPMS_SCHEME_HMAC_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMS_SCHEME_HMAC_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->hashAlg);
}

void
grub_Tss2_MU_TPMS_SCHEME_XOR_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMS_SCHEME_XOR_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->hashAlg);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf);
}

void
grub_Tss2_MU_TPMU_SCHEME_KEYEDHASH_Unmarshal (grub_tpm2_buffer_t buffer,
					      TPMI_ALG_KEYEDHASH_SCHEME_t scheme,
					      TPMU_SCHEME_KEYEDHASH_t *p)
{
  switch (scheme)
    {
    case TPM_ALG_HMAC:
      grub_Tss2_MU_TPMS_SCHEME_HMAC_Unmarshal (buffer, &p->hmac);
      break;
    case TPM_ALG_XOR:
      grub_Tss2_MU_TPMS_SCHEME_XOR_Unmarshal (buffer, &p->exclusiveOr);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_KEYEDHASH_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					      TPMT_KEYEDHASH_SCHEME_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_Tss2_MU_TPMU_SCHEME_KEYEDHASH_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMS_KEYEDHASH_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_KEYEDHASH_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_KEYEDHASH_SCHEME_Unmarshal (buffer, &p->scheme);
}

void
grub_Tss2_MU_TPMU_SYM_KEY_BITS_Unmarshal (grub_tpm2_buffer_t buffer,
					  TPMI_ALG_SYM_OBJECT_t algorithm,
					  TPMU_SYM_KEY_BITS_t *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
    case TPM_ALG_XOR:
      grub_tpm2_buffer_unpack_u16 (buffer, (grub_uint16_t *) p);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMU_SYM_MODE_Unmarshal (grub_tpm2_buffer_t buffer,
				      TPMI_ALG_SYM_OBJECT_t algorithm,
				      TPMU_SYM_MODE_t *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
      grub_tpm2_buffer_unpack_u16 (buffer, (grub_uint16_t *) p);
      break;
    case TPM_ALG_XOR:
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPMT_SYM_DEF_OBJECT_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->algorithm);
  grub_Tss2_MU_TPMU_SYM_KEY_BITS_Unmarshal (buffer, p->algorithm, &p->keyBits);
  grub_Tss2_MU_TPMU_SYM_MODE_Unmarshal (buffer, p->algorithm, &p->mode);
}

void
grub_Tss2_MU_TPMS_SYMCIPHER_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_SYMCIPHER_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Unmarshal (buffer, &p->sym);
}

void
grub_Tss2_MU_TPMU_ASYM_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMI_ALG_RSA_DECRYPT_t scheme,
					 TPMU_ASYM_SCHEME_t *p __attribute__((unused)))
{
  switch (scheme)
    {
    case TPM_ALG_NULL:
      break;
    default:
      /* Unsupported */
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_RSA_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_RSA_SCHEME_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_Tss2_MU_TPMU_ASYM_SCHEME_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMS_RSA_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_RSA_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Unmarshal (buffer, &p->symmetric);
  grub_Tss2_MU_TPMT_RSA_SCHEME_Unmarshal (buffer, &p->scheme);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->keyBits);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->exponent);
}

void
grub_Tss2_MU_TPMT_ECC_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_ECC_SCHEME_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_Tss2_MU_TPMU_ASYM_SCHEME_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMU_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMI_ALG_KDF_t scheme,
					TPMU_KDF_SCHEME_t *p)
{
  switch (scheme)
    {
    case TPM_ALG_MGF1:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->mgf1.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_56A:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf1_sp800_56a.hashAlg);
      break;
    case TPM_ALG_KDF2:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf2.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_108:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf1_sp800_108.hashAlg);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_KDF_SCHEME_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_Tss2_MU_TPMU_KDF_SCHEME_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_Tss2_MU_TPMS_ECC_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_ECC_PARMS_t *p)
{
  grub_Tss2_MU_TPMT_SYM_DEF_OBJECT_Unmarshal (buffer, &p->symmetric);
  grub_Tss2_MU_TPMT_ECC_SCHEME_Unmarshal (buffer, &p->scheme );
  grub_tpm2_buffer_unpack_u16 (buffer, &p->curveID);
  grub_Tss2_MU_TPMT_KDF_SCHEME_Unmarshal (buffer, &p->kdf);
}

void
grub_Tss2_MU_TPMU_PUBLIC_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					  grub_uint32_t type,
					  TPMU_PUBLIC_PARMS_t *p)
{
  switch (type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_Tss2_MU_TPMS_KEYEDHASH_PARMS_Unmarshal (buffer, &p->keyedHashDetail);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_Tss2_MU_TPMS_SYMCIPHER_PARMS_Unmarshal (buffer, &p->symDetail);
      break;
    case TPM_ALG_RSA:
      grub_Tss2_MU_TPMS_RSA_PARMS_Unmarshal (buffer, &p->rsaDetail);
      break;
    case TPM_ALG_ECC:
      grub_Tss2_MU_TPMS_ECC_PARMS_Unmarshal (buffer, &p->eccDetail);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMS_ECC_POINT_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_ECC_POINT_t *p)
{
  grub_Tss2_MU_TPM2B_ECC_PARAMETER_Unmarshal (buffer, &p->x);
  grub_Tss2_MU_TPM2B_ECC_PARAMETER_Unmarshal (buffer, &p->y);
}

void
grub_Tss2_MU_TPMU_PUBLIC_ID_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMI_ALG_PUBLIC_t type,
				       TPMU_PUBLIC_ID_t *p)
{
  switch(type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &p->keyedHash);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &p->sym);
      break;
    case TPM_ALG_RSA:
      grub_Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Unmarshal (buffer, &p->rsa);
      break;
    case TPM_ALG_ECC:
      grub_Tss2_MU_TPMS_ECC_POINT_Unmarshal (buffer, &p->ecc);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPMT_PUBLIC_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->type);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->nameAlg);
  grub_Tss2_MU_TPMA_OBJECT_Unmarshal (buffer, &p->objectAttributes);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &p->authPolicy);
  grub_Tss2_MU_TPMU_PUBLIC_PARMS_Unmarshal (buffer, p->type, &p->parameters);
  grub_Tss2_MU_TPMU_PUBLIC_ID_Unmarshal (buffer, p->type, &p->unique);
}

void
grub_Tss2_MU_TPM2B_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				     TPM2B_PUBLIC_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->size);
  grub_Tss2_MU_TPMT_PUBLIC_Unmarshal (buffer, &p->publicArea);
}

void
grub_Tss2_MU_TPMS_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_NV_PUBLIC_t *p)
{
  grub_tpm2_buffer_unpack_u32 (buffer, &p->nvIndex);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->nameAlg);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->attributes);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &p->authPolicy);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->dataSize);
}

void
grub_Tss2_MU_TPM2B_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
					TPM2B_NV_PUBLIC_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->size);
  grub_Tss2_MU_TPMS_NV_PUBLIC_Unmarshal (buffer, &p->nvPublic);
}

void
grub_Tss2_MU_TPM2B_NAX_NV_BUFFER_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPM2B_MAX_NV_BUFFER_t *p)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_MAX_NV_BUFFER_t, p);
}

void
grub_Tss2_MU_TPM2B_NAME_Unmarshal (grub_tpm2_buffer_t buffer,
				   TPM2B_NAME_t *n)
{
  TPM2B_BUFFER_UNMARSHAL (buffer, TPM2B_NAME_t, n);
}

void
grub_Tss2_MU_TPMS_TAGGED_PROPERTY_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_TAGGED_PROPERTY_t *property)
{
  grub_tpm2_buffer_unpack_u32 (buffer, &property->property);
  grub_tpm2_buffer_unpack_u32 (buffer, &property->value);
}

void
grub_Tss2_MU_TPMT_TK_CREATION_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMT_TK_CREATION_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->tag);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->hierarchy);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &p->digest);
}

void
grub_Tss2_MU_TPMT_TK_HASHCHECK_Unmarshal (grub_tpm2_buffer_t buffer,
                                          TPMT_TK_HASHCHECK_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->tag);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->hierarchy);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &p->digest);
}

void
grub_Tss2_MU_TPMT_TK_VERIFIED_Unmarshal (grub_tpm2_buffer_t buffer,
                                         TPMT_TK_VERIFIED_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->tag);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->hierarchy);
  grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &p->digest);
}

void
grub_Tss2_MU_TPMS_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPMS_PCR_SELECTION_t *pcrSelection)
{
  grub_uint32_t i;

  grub_tpm2_buffer_unpack_u16 (buffer, &pcrSelection->hash);
  grub_tpm2_buffer_unpack_u8 (buffer, &pcrSelection->sizeOfSelect);

  if (pcrSelection->sizeOfSelect > TPM_PCR_SELECT_MAX)
    {
      buffer->error = 1;
      return;
    }

  for (i = 0; i < pcrSelection->sizeOfSelect; i++)
    grub_tpm2_buffer_unpack_u8 (buffer, &pcrSelection->pcrSelect[i]);
}

void
grub_Tss2_MU_TPML_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPML_PCR_SELECTION_t *pcrSelection)
{
  grub_uint32_t i;

  grub_tpm2_buffer_unpack_u32 (buffer, &pcrSelection->count);

  if (pcrSelection->count > TPM_NUM_PCR_BANKS)
    {
      buffer->error = 1;
      return;
    }

  for (i = 0; i < pcrSelection->count; i++)
    grub_Tss2_MU_TPMS_PCR_SELECTION_Unmarshal (buffer, &pcrSelection->pcrSelections[i]);
}

void
grub_Tss2_MU_TPML_DIGEST_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPML_DIGEST_t *digest)
{
  grub_uint32_t i;

  grub_tpm2_buffer_unpack_u32 (buffer, &digest->count);

  if (digest->count > 8)
    {
      buffer->error = 1;
      return;
    }

  for (i = 0; i < digest->count; i++)
    grub_Tss2_MU_TPM2B_DIGEST_Unmarshal (buffer, &digest->digests[i]);
}

void
grub_Tss2_MU_TPML_DIGEST_VALUE_Unmarshal (grub_tpm2_buffer_t buffer,
					  TPML_DIGEST_VALUES_t *digests)
{
  grub_uint32_t i;

  grub_tpm2_buffer_unpack_u32 (buffer, &digests->count);

  if (digests->count > TPM_NUM_PCR_BANKS)
    {
      buffer->error = true;
      return;
    }

  for (i = 0; i < digests->count; i++)
    grub_Tss2_MU_TPMT_HA_Unmarshal (buffer, &digests->digests[i]);
}

void
grub_Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal (grub_tpm2_buffer_t buffer,
                                           TPMS_SIGNATURE_RSA_t *rsa)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &rsa->hash);
  grub_Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Unmarshal (buffer, &rsa->sig);
}

void
grub_Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal (grub_tpm2_buffer_t buffer,
                                           TPMS_SIGNATURE_ECC_t *ecc)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &ecc->hash);
  grub_Tss2_MU_TPM2B_ECC_PARAMETER_Unmarshal (buffer, &ecc->signatureR);
  grub_Tss2_MU_TPM2B_ECC_PARAMETER_Unmarshal (buffer, &ecc->signatureS);
}

void
grub_Tss2_MU_TPMU_HA_Unmarshal (grub_tpm2_buffer_t buffer,
                                TPMI_ALG_HASH_t hashAlg,
                                TPMU_HA_t *p)
{
  switch (hashAlg)
    {
    case TPM_ALG_SHA1:
      grub_tpm2_buffer_unpack (buffer, &p->sha1, TPM_SHA1_DIGEST_SIZE);
      break;
    case TPM_ALG_SHA256:
      grub_tpm2_buffer_unpack (buffer, &p->sha256, TPM_SHA256_DIGEST_SIZE);
      break;
    case TPM_ALG_SHA384:
      grub_tpm2_buffer_unpack (buffer, &p->sha384, TPM_SHA384_DIGEST_SIZE);
      break;
    case TPM_ALG_SHA512:
      grub_tpm2_buffer_unpack (buffer, &p->sha512, TPM_SHA512_DIGEST_SIZE);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_HA_Unmarshal (grub_tpm2_buffer_t buffer,
                                TPMT_HA_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->hashAlg);
  grub_Tss2_MU_TPMU_HA_Unmarshal (buffer, p->hashAlg, &p->digest);
}

void
grub_Tss2_MU_TPMU_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buffer,
                                       TPMI_ALG_SIG_SCHEME_t sigAlg,
                                       TPMU_SIGNATURE_t *p)
{
  switch (sigAlg)
    {
    case TPM_ALG_RSASSA:
      grub_Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal (buffer, (TPMS_SIGNATURE_RSA_t *)&p->rsassa);
      break;
    case TPM_ALG_RSAPSS:
      grub_Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal (buffer, (TPMS_SIGNATURE_RSA_t *)&p->rsapss);
      break;
    case TPM_ALG_ECDSA:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC_t *)&p->ecdsa);
      break;
    case TPM_ALG_ECDAA:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC_t *)&p->ecdaa);
      break;
    case TPM_ALG_SM2:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC_t *)&p->sm2);
      break;
    case TPM_ALG_ECSCHNORR:
      grub_Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC_t *)&p->ecschnorr);
      break;
    case TPM_ALG_HMAC:
      grub_Tss2_MU_TPMT_HA_Unmarshal (buffer, &p->hmac);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_Tss2_MU_TPMT_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buffer,
                                       TPMT_SIGNATURE_t *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->sigAlg);
  grub_Tss2_MU_TPMU_SIGNATURE_Unmarshal (buffer, p->sigAlg, &p->signature);
}
