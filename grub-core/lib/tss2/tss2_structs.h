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

#ifndef GRUB_TPM2_INTERNAL_STRUCTS_HEADER
#define GRUB_TPM2_INTERNAL_STRUCTS_HEADER 1

#include <tss2_types.h>

/*
 * TPM response header
 *   This struct is used to calculate the minimum size of the TPM 2.0 response.
 *   The format of the response:
 *
 *   +----------------------+
 *   | UINT16 tag           |
 *   +----------------------+
 *   | UINT32 repsonse_size |
 *   +----------------------+
 *   | UINT32 response_code |
 *   +======================+
 *   | response_data        | (optional)
 *   +======================+
 */
struct __attribute__ ((__packed__)) TPM_RESPONSE_HEADER
{
  grub_uint16_t tag;
  grub_uint32_t response_size;
  TPM_RC_t response_code;
};
typedef struct TPM_RESPONSE_HEADER TPM_RESPONSE_HEADER_t;

/* TPMS_TAGGED_PROPERTY Structure */
struct TPMS_TAGGED_PROPERTY
{
  TPM_PT_t property;
  grub_uint32_t value;
};
typedef struct TPMS_TAGGED_PROPERTY TPMS_TAGGED_PROPERTY_t;

/* TPML_TAGGED_TPM_PROPERTY Structure */
struct TPML_TAGGED_TPM_PROPERTY
{
  grub_uint32_t count;
  TPMS_TAGGED_PROPERTY_t tpmProperty[TPM_MAX_TPM_PROPERTIES];
};
typedef struct TPML_TAGGED_TPM_PROPERTY TPML_TAGGED_TPM_PROPERTY_t;

/* TPMU_CAPABILITIES Structure */
union TPMU_CAPABILITIES
{
  TPML_TAGGED_TPM_PROPERTY_t tpmProperties;
};
typedef union TPMU_CAPABILITIES TPMU_CAPABILITIES_t;

/* TPMS_CAPABILITY_DATA Structure */
struct TPMS_CAPABILITY_DATA
{
  TPM_CAP_t capability;
  TPMU_CAPABILITIES_t data;
};
typedef struct TPMS_CAPABILITY_DATA TPMS_CAPABILITY_DATA_t;

/* TPMS_PCR_SELECT Structure */
struct TPMS_PCR_SELECT
{
  grub_uint8_t sizeOfSelect;
  grub_uint8_t pcrSelect[TPM_PCR_SELECT_MAX];
};
typedef struct TPMS_PCR_SELECT TPMS_PCR_SELECT_t;

/* TPMS_PCR_SELECTION Structure */
struct TPMS_PCR_SELECTION
{
  TPMI_ALG_HASH_t hash;
  grub_uint8_t sizeOfSelect;
  grub_uint8_t pcrSelect[TPM_PCR_SELECT_MAX];
};
typedef struct TPMS_PCR_SELECTION TPMS_PCR_SELECTION_t;

static inline void TPMS_PCR_SELECTION_SelectPCR(TPMS_PCR_SELECTION_t *self, grub_uint32_t n)
{
  self->pcrSelect[(n / 8)] |= (1 << (n % 8));
}

/* TPML_PCR_SELECTION Structure */
struct TPML_PCR_SELECTION
{
  grub_uint32_t count;
  TPMS_PCR_SELECTION_t pcrSelections[TPM_NUM_PCR_BANKS];
};
typedef struct TPML_PCR_SELECTION TPML_PCR_SELECTION_t;

/* TPMU_HA Structure */
union TPMU_HA
{
  grub_uint8_t sha1[TPM_SHA1_DIGEST_SIZE];
  grub_uint8_t sha256[TPM_SHA256_DIGEST_SIZE];
  grub_uint8_t sha384[TPM_SHA384_DIGEST_SIZE];
  grub_uint8_t sha512[TPM_SHA512_DIGEST_SIZE];
  grub_uint8_t sm3_256[TPM_SM3_256_DIGEST_SIZE];
};
typedef union TPMU_HA TPMU_HA_t;

/* TPM2B Structure */
struct TPM2B
{
  grub_uint16_t size;
  grub_uint8_t buffer[1];
};
typedef struct TPM2B TPM2B_t;

/* TPM2B_DIGEST Structure */
struct TPM2B_DIGEST
{
  grub_uint16_t size;
  grub_uint8_t buffer[sizeof(TPMU_HA_t)];
};
typedef struct TPM2B_DIGEST TPM2B_DIGEST_t;

/* TPML_DIGEST Structure */
struct TPML_DIGEST
{
  grub_uint32_t count;
  TPM2B_DIGEST_t digests[8];
};
typedef struct TPML_DIGEST TPML_DIGEST_t;

/* TPM2B_NONCE Type */
typedef TPM2B_DIGEST_t TPM2B_NONCE_t;

/* TPM2B_EVENT Structure */
struct TPM2B_EVENT {
    grub_uint16_t size;
    grub_uint8_t buffer[1024];
};
typedef struct TPM2B_EVENT TPM2B_EVENT_t;

/* TPMA_SESSION Structure */
struct TPMA_SESSION
{
#ifdef GRUB_TARGET_WORDS_BIGENDIAN
  grub_uint8_t audit:1;
  grub_uint8_t encrypt:1;
  grub_uint8_t decrypt:1;
  grub_uint8_t reserved:2;
  grub_uint8_t auditReset:1;
  grub_uint8_t auditExclusive:1;
  grub_uint8_t continueSession:1;
#else
  grub_uint8_t continueSession:1;
  grub_uint8_t auditExclusive:1;
  grub_uint8_t auditReset:1;
  grub_uint8_t reserved:2;
  grub_uint8_t decrypt:1;
  grub_uint8_t encrypt:1;
  grub_uint8_t audit:1;
#endif
};
typedef struct TPMA_SESSION TPMA_SESSION_t;

/* TPM2B_AUTH Type */
typedef TPM2B_DIGEST_t TPM2B_AUTH_t;

/* TPMS_AUTH_COMMAND Structure */
struct TPMS_AUTH_COMMAND
{
  TPMI_SH_AUTH_SESSION_t sessionHandle;
  TPM2B_NONCE_t nonce;
  TPMA_SESSION_t sessionAttributes;
  TPM2B_AUTH_t hmac;
};
typedef struct TPMS_AUTH_COMMAND TPMS_AUTH_COMMAND_t;

/* TPMS_AUTH_RESPONSE Structure */
struct TPMS_AUTH_RESPONSE
{
  TPM2B_NONCE_t nonce;
  TPMA_SESSION_t sessionAttributes;
  TPM2B_AUTH_t hmac;
};
typedef struct TPMS_AUTH_RESPONSE TPMS_AUTH_RESPONSE_t;

/* TPM2B_SENSITIVE_DATA Structure */
struct TPM2B_SENSITIVE_DATA
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_SYM_DATA];
};
typedef struct TPM2B_SENSITIVE_DATA TPM2B_SENSITIVE_DATA_t;

/* TPMS_SENSITIVE_CREATE Structure */
struct TPMS_SENSITIVE_CREATE
{
  TPM2B_AUTH_t userAuth;
  TPM2B_SENSITIVE_DATA_t data;
};
typedef struct TPMS_SENSITIVE_CREATE TPMS_SENSITIVE_CREATE_t;

/* TPM2B_SENSITIVE_CREATE Structure */
struct TPM2B_SENSITIVE_CREATE
{
  grub_uint16_t size;
  TPMS_SENSITIVE_CREATE_t sensitive;
};
typedef struct TPM2B_SENSITIVE_CREATE TPM2B_SENSITIVE_CREATE_t;

/* TPMA_OBJECT Structure */
struct TPMA_OBJECT
{
#ifdef GRUB_TARGET_WORDS_BIGENDIAN
  grub_uint32_t reserved5:13;
  grub_uint32_t sign:1;
  grub_uint32_t decrypt:1;
  grub_uint32_t restricted:1;
  grub_uint32_t reserved4:4;
  grub_uint32_t encryptedDuplication:1;
  grub_uint32_t noDA:1;
  grub_uint32_t reserved3:2;
  grub_uint32_t adminWithPolicy:1;
  grub_uint32_t userWithAuth:1;
  grub_uint32_t sensitiveDataOrigin:1;
  grub_uint32_t fixedParent:1;
  grub_uint32_t reserved2:1;
  grub_uint32_t stClear:1;
  grub_uint32_t fixedTPM:1;
  grub_uint32_t reserved1:1;
#else
  grub_uint32_t reserved1:1;
  grub_uint32_t fixedTPM:1;
  grub_uint32_t stClear:1;
  grub_uint32_t reserved2:1;
  grub_uint32_t fixedParent:1;
  grub_uint32_t sensitiveDataOrigin:1;
  grub_uint32_t userWithAuth:1;
  grub_uint32_t adminWithPolicy:1;
  grub_uint32_t reserved3:2;
  grub_uint32_t noDA:1;
  grub_uint32_t encryptedDuplication:1;
  grub_uint32_t reserved4:4;
  grub_uint32_t restricted:1;
  grub_uint32_t decrypt:1;
  grub_uint32_t sign:1;
  grub_uint32_t reserved5:13;
#endif
};
typedef struct TPMA_OBJECT TPMA_OBJECT_t;

/* TPMS_SCHEME_HASH Structure */
struct TPMS_SCHEME_HASH
{
  TPMI_ALG_HASH_t hashAlg;
};
typedef struct TPMS_SCHEME_HASH TPMS_SCHEME_HASH_t;

/* TPMS_SCHEME_HASH Types */
typedef TPMS_SCHEME_HASH_t TPMS_KEY_SCHEME_ECDH_t;
typedef TPMS_SCHEME_HASH_t TPMS_KEY_SCHEME_ECMQV_t;
typedef TPMS_SCHEME_HASH_t TPMS_SIG_SCHEME_RSASSA_t;
typedef TPMS_SCHEME_HASH_t TPMS_SIG_SCHEME_RSAPSS_t;
typedef TPMS_SCHEME_HASH_t TPMS_SIG_SCHEME_ECDSA_t;
typedef TPMS_SCHEME_HASH_t TPMS_SIG_SCHEME_ECDAA_t;
typedef TPMS_SCHEME_HASH_t TPMS_SIG_SCHEME_SM2_t;
typedef TPMS_SCHEME_HASH_t TPMS_SIG_SCHEME_ECSCHNORR_t;
typedef TPMS_SCHEME_HASH_t TPMS_ENC_SCHEME_RSAES_t;
typedef TPMS_SCHEME_HASH_t TPMS_ENC_SCHEME_OAEP_t;
typedef TPMS_SCHEME_HASH_t TPMS_SCHEME_KDF2_t;
typedef TPMS_SCHEME_HASH_t TPMS_SCHEME_MGF1_t;
typedef TPMS_SCHEME_HASH_t TPMS_SCHEME_KDF1_SP800_56A_t;
typedef TPMS_SCHEME_HASH_t TPMS_SCHEME_KDF1_SP800_108_t;

/* TPMS_SCHEME_HMAC Type */
typedef TPMS_SCHEME_HASH_t TPMS_SCHEME_HMAC_t;

/* TPMS_SCHEME_XOR Structure */
struct TPMS_SCHEME_XOR
{
  TPMI_ALG_HASH_t hashAlg;
  TPMI_ALG_KDF_t kdf;
};
typedef struct TPMS_SCHEME_XOR TPMS_SCHEME_XOR_t;

/* TPMU_SCHEME_KEYEDHASH Union */
union TPMU_SCHEME_KEYEDHASH
{
  TPMS_SCHEME_HMAC_t hmac;
  TPMS_SCHEME_XOR_t exclusiveOr;
};
typedef union TPMU_SCHEME_KEYEDHASH TPMU_SCHEME_KEYEDHASH_t;

/* TPMT_KEYEDHASH_SCHEME Structure */
struct TPMT_KEYEDHASH_SCHEME
{
  TPMI_ALG_KEYEDHASH_SCHEME_t scheme;
  TPMU_SCHEME_KEYEDHASH_t details;
};
typedef struct TPMT_KEYEDHASH_SCHEME TPMT_KEYEDHASH_SCHEME_t;

/* TPMS_KEYEDHASH_PARMS Structure */
struct TPMS_KEYEDHASH_PARMS
{
  TPMT_KEYEDHASH_SCHEME_t scheme;
};
typedef struct TPMS_KEYEDHASH_PARMS TPMS_KEYEDHASH_PARMS_t;

/* TPMU_SYM_KEY_BITS Union */
union TPMU_SYM_KEY_BITS
{
  TPM_KEY_BITS_t aes;
  TPM_KEY_BITS_t exclusiveOr;
  TPM_KEY_BITS_t sm4;
  TPM_KEY_BITS_t camellia;
};
typedef union TPMU_SYM_KEY_BITS TPMU_SYM_KEY_BITS_t;

/* TPMU_SYM_MODE Union */
union TPMU_SYM_MODE
{
  TPMI_ALG_SYM_MODE_t aes;
  TPMI_ALG_SYM_MODE_t sm4;
  TPMI_ALG_SYM_MODE_t camellia;
  TPMI_ALG_SYM_MODE_t sym;
};
typedef union TPMU_SYM_MODE TPMU_SYM_MODE_t;

/* TPMT_SYM_DEF_OBJECT Structure */
struct TPMT_SYM_DEF_OBJECT
{
  TPMI_ALG_SYM_OBJECT_t algorithm;
  TPMU_SYM_KEY_BITS_t keyBits;
  TPMU_SYM_MODE_t mode;
};
typedef struct TPMT_SYM_DEF_OBJECT TPMT_SYM_DEF_OBJECT_t;

/* TPMS_SYMCIPHER_PARMS Structure */
struct TPMS_SYMCIPHER_PARMS
{
  TPMT_SYM_DEF_OBJECT_t sym;
};
typedef struct TPMS_SYMCIPHER_PARMS TPMS_SYMCIPHER_PARMS_t;

/* TPMU_ASYM_SCHEME Union */
union TPMU_ASYM_SCHEME
{
  TPMS_KEY_SCHEME_ECDH_t ecdh;
  TPMS_KEY_SCHEME_ECMQV_t ecmqv;
  TPMS_SIG_SCHEME_RSASSA_t rsassa;
  TPMS_SIG_SCHEME_RSAPSS_t rsapss;
  TPMS_SIG_SCHEME_ECDSA_t ecdsa;
  TPMS_SIG_SCHEME_ECDAA_t ecdaa;
  TPMS_SIG_SCHEME_SM2_t sm2;
  TPMS_SIG_SCHEME_ECSCHNORR_t ecschnorr;
  TPMS_ENC_SCHEME_RSAES_t rsaes;
  TPMS_ENC_SCHEME_OAEP_t oaep;
  TPMS_SCHEME_HASH_t anySig;
  unsigned char padding[4];
};
typedef union TPMU_ASYM_SCHEME TPMU_ASYM_SCHEME_t;

/* TPMT_RSA_SCHEME Structure */
struct TPMT_RSA_SCHEME
{
  TPMI_ALG_RSA_SCHEME_t scheme;
  TPMU_ASYM_SCHEME_t details;
};
typedef struct TPMT_RSA_SCHEME TPMT_RSA_SCHEME_t;

/* TPMS_RSA_PARMS Structure */
struct TPMS_RSA_PARMS
{
  TPMT_SYM_DEF_OBJECT_t symmetric;
  TPMT_RSA_SCHEME_t scheme;
  TPM_KEY_BITS_t keyBits;
  grub_uint32_t exponent;
};
typedef struct TPMS_RSA_PARMS TPMS_RSA_PARMS_t;

/* TPMT_ECC_SCHEME Structure */
struct TPMT_ECC_SCHEME
{
  TPMI_ALG_ECC_SCHEME_t scheme;
  TPMU_ASYM_SCHEME_t details;
};
typedef struct TPMT_ECC_SCHEME TPMT_ECC_SCHEME_t;

/* TPMU_KDF_SCHEME Union */
union TPMU_KDF_SCHEME
{
  TPMS_SCHEME_MGF1_t mgf1;
  TPMS_SCHEME_KDF1_SP800_56A_t kdf1_sp800_56a;
  TPMS_SCHEME_KDF2_t kdf2;
  TPMS_SCHEME_KDF1_SP800_108_t kdf1_sp800_108;
};
typedef union TPMU_KDF_SCHEME TPMU_KDF_SCHEME_t;

/* TPMT_KDF_SCHEME Structure */
struct TPMT_KDF_SCHEME
{
  TPMI_ALG_KDF_t scheme;
  TPMU_KDF_SCHEME_t details;
};
typedef struct TPMT_KDF_SCHEME TPMT_KDF_SCHEME_t;

/* TPMS_ECC_PARMS Structure */
struct TPMS_ECC_PARMS
{
  TPMT_SYM_DEF_OBJECT_t symmetric;
  TPMT_ECC_SCHEME_t scheme;
  TPMI_ECC_CURVE_t curveID;
  TPMT_KDF_SCHEME_t kdf;
};
typedef struct TPMS_ECC_PARMS TPMS_ECC_PARMS_t;

/* TPMT_ASYM_SCHEME Structure */
struct TPMT_ASYM_SCHEME
{
  TPMI_ALG_ASYM_SCHEME_t scheme;
  TPMU_ASYM_SCHEME_t details;
};
typedef struct TPMT_ASYM_SCHEME TPMT_ASYM_SCHEME_t;

/* TPMS_ASYM_PARMS Structure */
struct TPMS_ASYM_PARMS
{
  TPMT_SYM_DEF_OBJECT_t symmetric;
  TPMT_ASYM_SCHEME_t scheme;
};
typedef struct TPMS_ASYM_PARMS TPMS_ASYM_PARMS_t;

/* TPMU_PUBLIC_PARMS Union */
union TPMU_PUBLIC_PARMS
{
  TPMS_KEYEDHASH_PARMS_t keyedHashDetail;
  TPMS_SYMCIPHER_PARMS_t symDetail;
  TPMS_RSA_PARMS_t rsaDetail;
  TPMS_ECC_PARMS_t eccDetail;
  TPMS_ASYM_PARMS_t asymDetail;
};
typedef union TPMU_PUBLIC_PARMS TPMU_PUBLIC_PARMS_t;

/* TPMT_PUBLIC_PARMS Structure */
struct TPMT_PUBLIC_PARMS {
    TPMI_ALG_PUBLIC_t type;
    TPMU_PUBLIC_PARMS_t parameters;
};
typedef struct TPMT_PUBLIC_PARMS TPMT_PUBLIC_PARMS_t;

/* TPM2B_PUBLIC_KEY_RSA Structure */
struct TPM2B_PUBLIC_KEY_RSA
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_RSA_KEY_BYTES];
};
typedef struct TPM2B_PUBLIC_KEY_RSA TPM2B_PUBLIC_KEY_RSA_t;

/* TPM2B_ECC_PARAMETER Structure */
struct TPM2B_ECC_PARAMETER
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_ECC_KEY_BYTES];
};
typedef struct TPM2B_ECC_PARAMETER TPM2B_ECC_PARAMETER_t;

/* TPMS_ECC_POINT Structure */
struct TPMS_ECC_POINT
{
  TPM2B_ECC_PARAMETER_t x;
  TPM2B_ECC_PARAMETER_t y;
};
typedef struct TPMS_ECC_POINT TPMS_ECC_POINT_t;

/* TPMU_ENCRYPTED_SECRET Union */
union TPMU_ENCRYPTED_SECRET
{
  grub_uint8_t ecc[sizeof(TPMS_ECC_POINT_t)];
  grub_uint8_t rsa[TPM_MAX_RSA_KEY_BYTES];
  grub_uint8_t symmetric[sizeof(TPM2B_DIGEST_t)];
  grub_uint8_t keyedHash[sizeof(TPM2B_DIGEST_t)];
};
typedef union TPMU_ENCRYPTED_SECRET TPMU_ENCRYPTED_SECRET_t;

/* TPM2B_ENCRYPTED_SECRET Structure */
struct TPM2B_ENCRYPTED_SECRET
{
  grub_uint16_t size;
  grub_uint8_t secret[sizeof(TPMU_ENCRYPTED_SECRET_t)];
};
typedef struct TPM2B_ENCRYPTED_SECRET TPM2B_ENCRYPTED_SECRET_t;

/* TPMU_PUBLIC_ID Union */
union TPMU_PUBLIC_ID
{
  TPM2B_DIGEST_t keyedHash;
  TPM2B_DIGEST_t sym;
  TPM2B_PUBLIC_KEY_RSA_t rsa;
  TPMS_ECC_POINT_t ecc;
};
typedef union TPMU_PUBLIC_ID TPMU_PUBLIC_ID_t;

/* TPMT_PUBLIC Structure */
struct TPMT_PUBLIC
{
  TPMI_ALG_PUBLIC_t type;
  TPMI_ALG_HASH_t nameAlg;
  TPMA_OBJECT_t objectAttributes;
  TPM2B_DIGEST_t authPolicy;
  TPMU_PUBLIC_PARMS_t parameters;
  TPMU_PUBLIC_ID_t unique;
};
typedef struct TPMT_PUBLIC TPMT_PUBLIC_t;

/* TPM2B_PUBLIC Structure */
struct TPM2B_PUBLIC
{
  grub_uint16_t size;
  TPMT_PUBLIC_t publicArea;
};
typedef struct TPM2B_PUBLIC TPM2B_PUBLIC_t;

/* TPMT_HA Structure */
struct TPMT_HA
{
  TPMI_ALG_HASH_t hashAlg;
  TPMU_HA_t digest;
};
typedef struct TPMT_HA TPMT_HA_t;

/* TPM2B_DATA Structure */
struct TPM2B_DATA
{
  grub_uint16_t size;
  grub_uint8_t buffer[sizeof(TPMT_HA_t)];
};
typedef struct TPM2B_DATA TPM2B_DATA_t;

/* TPMA_LOCALITY Structure */
struct TPMA_LOCALITY
{
#ifdef GRUB_TARGET_WORDS_BIGENDIAN
  grub_uint8_t Extended:3;
  grub_uint8_t TPM_LOC_FOUR:1;
  grub_uint8_t TPM_LOC_THREE:1;
  grub_uint8_t TPM_LOC_TWO:1;
  grub_uint8_t TPM_LOC_ONE:1;
  grub_uint8_t TPM_LOC_ZERO:1;
#else
  grub_uint8_t TPM_LOC_ZERO:1;
  grub_uint8_t TPM_LOC_ONE:1;
  grub_uint8_t TPM_LOC_TWO:1;
  grub_uint8_t TPM_LOC_THREE:1;
  grub_uint8_t TPM_LOC_FOUR:1;
  grub_uint8_t Extended:3;
#endif
};
typedef struct TPMA_LOCALITY TPMA_LOCALITY_t;

/* TPMU_NAME Union */
union TPMU_NAME
{
  TPMT_HA_t digest;
  TPM_HANDLE_t handle;
};
typedef union TPMU_NAME TPMU_NAME_t;

/* TPM2B_NAME Structure */
struct TPM2B_NAME
{
  grub_uint16_t size;
  grub_uint8_t name[sizeof(TPMU_NAME_t)];
};
typedef struct TPM2B_NAME TPM2B_NAME_t;

/* TPMS_CREATION_DATA Structure */
struct TPMS_CREATION_DATA
{
  TPML_PCR_SELECTION_t pcrSelect;
  TPM2B_DIGEST_t pcrDigest;
  TPMA_LOCALITY_t locality;
  TPM_ALG_ID_t parentNameAlg;
  TPM2B_NAME_t parentName;
  TPM2B_NAME_t parentQualifiedName;
  TPM2B_DATA_t outsideInfo;
};
typedef struct TPMS_CREATION_DATA TPMS_CREATION_DATA_t;

/* TPM2B_CREATION_DATA Structure */
struct TPM2B_CREATION_DATA
{
  grub_uint16_t size;
  TPMS_CREATION_DATA_t creationData;
};
typedef struct TPM2B_CREATION_DATA TPM2B_CREATION_DATA_t;

/* TPMT_SYM_DEF Structure */
struct TPMT_SYM_DEF
{
  TPMI_ALG_SYM_t algorithm;
  TPMU_SYM_KEY_BITS_t keyBits;
  TPMU_SYM_MODE_t mode;
};
typedef struct TPMT_SYM_DEF TPMT_SYM_DEF_t;

/* TPM2B_MAX_BUFFER Structure */
struct TPM2B_MAX_BUFFER
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_DIGEST_BUFFER];
};
typedef struct TPM2B_MAX_BUFFER TPM2B_MAX_BUFFER_t;

/* TPMT_TK_HASHCHECK Structure */
struct TPMT_TK_HASHCHECK
{
  TPM_ST_t tag;
  TPMI_RH_HIERARCHY_t hierarchy;
  TPM2B_DIGEST_t digest;
};
typedef struct TPMT_TK_HASHCHECK TPMT_TK_HASHCHECK_t;

/* TPM2B_SYM_KEY Structure */
struct TPM2B_SYM_KEY
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_SYM_KEY_BYTES];
};
typedef struct TPM2B_SYM_KEY TPM2B_SYM_KEY_t;

/* TPM2B_PRIVATE_KEY_RSA Structure */
struct TPM2B_PRIVATE_KEY_RSA
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_RSA_KEY_BYTES/2];
};
typedef struct TPM2B_PRIVATE_KEY_RSA TPM2B_PRIVATE_KEY_RSA_t;

/* TPM2B_PRIVATE_VENDOR_SPECIFIC Structure */
struct TPM2B_PRIVATE_VENDOR_SPECIFIC
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_PRIVATE_VENDOR_SPECIFIC_BYTES];
};
typedef struct TPM2B_PRIVATE_VENDOR_SPECIFIC TPM2B_PRIVATE_VENDOR_SPECIFIC_t;

/* TPM2B_PRIVATE_VENDOR_SPECIFIC Union */
union TPMU_SENSITIVE_COMPOSITE
{
  TPM2B_PRIVATE_KEY_RSA_t rsa;
  TPM2B_ECC_PARAMETER_t ecc;
  TPM2B_SENSITIVE_DATA_t bits;
  TPM2B_SYM_KEY_t sym;
  TPM2B_PRIVATE_VENDOR_SPECIFIC_t any;
};
typedef union TPMU_SENSITIVE_COMPOSITE TPMU_SENSITIVE_COMPOSITE_t;

/* TPMT_SENSITIVE Structure */
struct TPMT_SENSITIVE
{
  TPMI_ALG_PUBLIC_t sensitiveType;
  TPM2B_AUTH_t authValue;
  TPM2B_DIGEST_t seedValue;
  TPMU_SENSITIVE_COMPOSITE_t sensitive;
};
typedef struct TPMT_SENSITIVE TPMT_SENSITIVE_t;

/* TPM2B_SENSITIVE Structure */
struct TPM2B_SENSITIVE
{
  grub_uint16_t size;
  TPMT_SENSITIVE_t sensitiveArea;
};
typedef struct TPM2B_SENSITIVE TPM2B_SENSITIVE_t;

/*
 * _PRIVATE Structure
 *
 * Although '_PRIVATE' is the name defined in the TPM2 SPEC, it is too generic,
 * so here we add the '__TPM2B' prefix to make the struct specific for 'TPM2B_PRIVATE'.
 */
struct __TPM2B_PRIVATE
{
  TPM2B_DIGEST_t integrityOuter;
  TPM2B_DIGEST_t integrityInner;
  TPM2B_SENSITIVE_t sensitive;
};
typedef struct __TPM2B_PRIVATE __TPM2B_PRIVATE_t;

/* TPM2B_PRIVATE Structure */
struct TPM2B_PRIVATE
{
  grub_uint16_t size;
  grub_uint8_t buffer[sizeof(__TPM2B_PRIVATE_t)];
};
typedef struct TPM2B_PRIVATE TPM2B_PRIVATE_t;

/* TPML_DIGEST_VALUES Structure */
struct TPML_DIGEST_VALUES
{
  grub_uint32_t count;
  TPMT_HA_t digests[TPM_NUM_PCR_BANKS];
};
typedef struct TPML_DIGEST_VALUES TPML_DIGEST_VALUES_t;

/* TPM2B_MAX_NV_BUFFER Structure */
struct TPM2B_MAX_NV_BUFFER
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_NV_BUFFER_SIZE];
};
typedef struct TPM2B_MAX_NV_BUFFER TPM2B_MAX_NV_BUFFER_t;

/* TPMS_NV_PUBLIC Structure */
struct TPMS_NV_PUBLIC
{
    TPMI_RH_NV_INDEX_t nvIndex;
    TPMI_ALG_HASH_t nameAlg;
    TPMA_NV_t attributes;
    TPM2B_DIGEST_t authPolicy;
    grub_uint16_t dataSize;
};
typedef struct TPMS_NV_PUBLIC TPMS_NV_PUBLIC_t;

/* TPM2B_NV_PUBLIC Structure */
struct TPM2B_NV_PUBLIC
{
    grub_uint16_t size;
    TPMS_NV_PUBLIC_t nvPublic;
};
typedef struct TPM2B_NV_PUBLIC TPM2B_NV_PUBLIC_t;

/* TPMT_TK_CREATION Structure */
struct TPMT_TK_CREATION
{
    TPM_ST_t tag;
    TPMI_RH_HIERARCHY_t hierarchy;
    TPM2B_DIGEST_t digest;
};
typedef struct TPMT_TK_CREATION TPMT_TK_CREATION_t;

/* TPMS_EMPTY Structure */
struct TPMS_EMPTY {
  grub_uint8_t empty[1]; /* a structure with no member */
};
typedef struct TPMS_EMPTY TPMS_EMPTY_t;

/* TPMS_SIGNATURE_RSA Structure */
struct TPMS_SIGNATURE_RSA {
  TPMI_ALG_HASH_t hash;
  TPM2B_PUBLIC_KEY_RSA_t sig;
};
typedef struct TPMS_SIGNATURE_RSA TPMS_SIGNATURE_RSA_t;

/* Definition of Types for RSA Signature */
typedef TPMS_SIGNATURE_RSA_t TPMS_SIGNATURE_RSASSA_t;
typedef TPMS_SIGNATURE_RSA_t TPMS_SIGNATURE_RSAPSS_t;

/* TPMS_SIGNATURE_ECC Structure */
struct TPMS_SIGNATURE_ECC {
  TPMI_ALG_HASH_t hash;
  TPM2B_ECC_PARAMETER_t signatureR;
  TPM2B_ECC_PARAMETER_t signatureS;
};
typedef struct TPMS_SIGNATURE_ECC TPMS_SIGNATURE_ECC_t;

/* Definition of Types for ECC TPMS_SIGNATURE_ECC */
typedef TPMS_SIGNATURE_ECC_t TPMS_SIGNATURE_ECDSA_t;
typedef TPMS_SIGNATURE_ECC_t TPMS_SIGNATURE_ECDAA_t;
typedef TPMS_SIGNATURE_ECC_t TPMS_SIGNATURE_SM2_t;
typedef TPMS_SIGNATURE_ECC_t TPMS_SIGNATURE_ECSCHNORR_t;

/* TPMU_SIGNATURE Structure */
union TPMU_SIGNATURE {
  TPMS_SIGNATURE_RSASSA_t rsassa;
  TPMS_SIGNATURE_RSAPSS_t rsapss;
  TPMS_SIGNATURE_ECDSA_t ecdsa;
  TPMS_SIGNATURE_ECDAA_t ecdaa;
  TPMS_SIGNATURE_SM2_t sm2;
  TPMS_SIGNATURE_ECSCHNORR_t ecschnorr;
  TPMT_HA_t hmac;
  TPMS_SCHEME_HASH_t any;
  TPMS_EMPTY_t null;
};
typedef union TPMU_SIGNATURE TPMU_SIGNATURE_t;

/* TPMT_SIGNATURE Structure */
struct TPMT_SIGNATURE {
  TPMI_ALG_SIG_SCHEME_t sigAlg;
  TPMU_SIGNATURE_t signature;
};
typedef struct TPMT_SIGNATURE TPMT_SIGNATURE_t;

static inline TPMI_ALG_HASH_t
TPMT_SIGNATURE_get_hash_alg (TPMT_SIGNATURE_t *sig)
{
  switch (sig->sigAlg)
    {
    case TPM_ALG_RSASSA:
      return sig->signature.rsassa.hash;
    case TPM_ALG_RSAPSS:
      return sig->signature.rsapss.hash;
    case TPM_ALG_ECDSA:
      return sig->signature.ecdsa.hash;
    case TPM_ALG_ECDAA:
      return sig->signature.ecdaa.hash;
    case TPM_ALG_SM2:
      return sig->signature.sm2.hash;
    case TPM_ALG_ECSCHNORR:
      return sig->signature.ecschnorr.hash;
    case TPM_ALG_HMAC:
      return sig->signature.hmac.hashAlg;
    default:
      break;
    }

  return TPM_ALG_NULL;
}

/* TPMT_TK_VERIFIED Structure */
struct TPMT_TK_VERIFIED {
  TPM_ST_t tag;
  TPMI_RH_HIERARCHY_t hierarchy;
  TPM2B_DIGEST_t digest;
};
typedef struct TPMT_TK_VERIFIED TPMT_TK_VERIFIED_t;

#endif /* ! GRUB_TPM2_INTERNAL_STRUCTS_HEADER */
