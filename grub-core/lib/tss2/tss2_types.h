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

#ifndef GRUB_TPM2_INTERNAL_TYPES_HEADER
#define GRUB_TPM2_INTERNAL_TYPES_HEADER 1

#include <grub/types.h>

/* TPM2_RC Constants */
typedef grub_uint32_t TPM_RC_t;

#define TPM_RC_1                 ((TPM_RC_t) 0x100)
#define TPM_RC_2                 ((TPM_RC_t) 0x200)
#define TPM_RC_3                 ((TPM_RC_t) 0x300)
#define TPM_RC_4                 ((TPM_RC_t) 0x400)
#define TPM_RC_5                 ((TPM_RC_t) 0x500)
#define TPM_RC_6                 ((TPM_RC_t) 0x600)
#define TPM_RC_7                 ((TPM_RC_t) 0x700)
#define TPM_RC_8                 ((TPM_RC_t) 0x800)
#define TPM_RC_9                 ((TPM_RC_t) 0x900)
#define TPM_RC_A                 ((TPM_RC_t) 0xA00)
#define TPM_RC_ASYMMETRIC        ((TPM_RC_t) 0x081)
#define TPM_RC_ATTRIBUTES        ((TPM_RC_t) 0x082)
#define TPM_RC_AUTH_CONTEXT      ((TPM_RC_t) 0x145)
#define TPM_RC_AUTH_FAIL         ((TPM_RC_t) 0x08E)
#define TPM_RC_AUTH_MISSING      ((TPM_RC_t) 0x125)
#define TPM_RC_AUTHSIZE          ((TPM_RC_t) 0x144)
#define TPM_RC_AUTH_TYPE         ((TPM_RC_t) 0x124)
#define TPM_RC_AUTH_UNAVAILABLE  ((TPM_RC_t) 0x12F)
#define TPM_RC_B                 ((TPM_RC_t) 0xB00)
#define TPM_RC_BAD_AUTH          ((TPM_RC_t) 0x0A2)
#define TPM_RC_BAD_CONTEXT       ((TPM_RC_t) 0x150)
#define TPM_RC_BAD_TAG           ((TPM_RC_t) 0x01E)
#define TPM_RC_BINDING           ((TPM_RC_t) 0x0A5)
#define TPM_RC_C                 ((TPM_RC_t) 0xC00)
#define TPM_RC_CANCELED          ((TPM_RC_t) 0x909)
#define TPM_RC_COMMAND_CODE      ((TPM_RC_t) 0x143)
#define TPM_RC_COMMAND_SIZE      ((TPM_RC_t) 0x142)
#define TPM_RC_CONTEXT_GAP       ((TPM_RC_t) 0x901)
#define TPM_RC_CPHASH            ((TPM_RC_t) 0x151)
#define TPM_RC_CURVE             ((TPM_RC_t) 0x0A6)
#define TPM_RC_D                 ((TPM_RC_t) 0xD00)
#define TPM_RC_DISABLED          ((TPM_RC_t) 0x120)
#define TPM_RC_E                 ((TPM_RC_t) 0xE00)
#define TPM_RC_ECC_POINT         ((TPM_RC_t) 0x0A7)
#define TPM_RC_EXCLUSIVE         ((TPM_RC_t) 0x121)
#define TPM_RC_EXPIRED           ((TPM_RC_t) 0x0A3)
#define TPM_RC_F                 ((TPM_RC_t) 0xF00)
#define TPM_RC_FAILURE           ((TPM_RC_t) 0x101)
#define TPM_RC_H                 ((TPM_RC_t) 0x000)
#define TPM_RC_HANDLE            ((TPM_RC_t) 0x08B)
#define TPM_RC_HASH              ((TPM_RC_t) 0x083)
#define TPM_RC_HIERARCHY         ((TPM_RC_t) 0x085)
#define TPM_RC_HMAC              ((TPM_RC_t) 0x119)
#define TPM_RC_INITIALIZE        ((TPM_RC_t) 0x100)
#define TPM_RC_INSUFFICIENT      ((TPM_RC_t) 0x09A)
#define TPM_RC_INTEGRITY         ((TPM_RC_t) 0x09F)
#define TPM_RC_KDF               ((TPM_RC_t) 0x08C)
#define TPM_RC_KEY               ((TPM_RC_t) 0x09C)
#define TPM_RC_KEY_SIZE          ((TPM_RC_t) 0x087)
#define TPM_RC_LOCALITY          ((TPM_RC_t) 0x907)
#define TPM_RC_LOCKOUT           ((TPM_RC_t) 0x921)
#define TPM_RC_MEMORY            ((TPM_RC_t) 0x904)
#define TPM_RC_MGF               ((TPM_RC_t) 0x088)
#define TPM_RC_MODE              ((TPM_RC_t) 0x089)
#define TPM_RC_NEEDS_TEST        ((TPM_RC_t) 0x153)
#define TPM_RC_N_MASK            ((TPM_RC_t) 0xF00)
#define TPM_RC_NONCE             ((TPM_RC_t) 0x08F)
#define TPM_RC_NO_RESULT         ((TPM_RC_t) 0x154)
#define TPM_RC_NOT_USED          ((TPM_RC_t) 0x97F)
#define TPM_RC_NV_AUTHORIZATION  ((TPM_RC_t) 0x149)
#define TPM_RC_NV_DEFINED        ((TPM_RC_t) 0x14C)
#define TPM_RC_NV_LOCKED         ((TPM_RC_t) 0x148)
#define TPM_RC_NV_RANGE          ((TPM_RC_t) 0x146)
#define TPM_RC_NV_RATE           ((TPM_RC_t) 0x920)
#define TPM_RC_NV_SIZE           ((TPM_RC_t) 0x147)
#define TPM_RC_NV_SPACE          ((TPM_RC_t) 0x14B)
#define TPM_RC_NV_UNAVAILABLE    ((TPM_RC_t) 0x923)
#define TPM_RC_NV_UNINITIALIZED  ((TPM_RC_t) 0x14A)
#define TPM_RC_OBJECT_HANDLES    ((TPM_RC_t) 0x906)
#define TPM_RC_OBJECT_MEMORY     ((TPM_RC_t) 0x902)
#define TPM_RC_P                 ((TPM_RC_t) 0x040)
#define TPM_RC_PARENT            ((TPM_RC_t) 0x152)
#define TPM_RC_PCR               ((TPM_RC_t) 0x127)
#define TPM_RC_PCR_CHANGED       ((TPM_RC_t) 0x128)
#define TPM_RC_POLICY            ((TPM_RC_t) 0x126)
#define TPM_RC_POLICY_CC         ((TPM_RC_t) 0x0A4)
#define TPM_RC_POLICY_FAIL       ((TPM_RC_t) 0x09D)
#define TPM_RC_PP                ((TPM_RC_t) 0x090)
#define TPM_RC_PRIVATE           ((TPM_RC_t) 0x10B)
#define TPM_RC_RANGE             ((TPM_RC_t) 0x08D)
#define TPM_RC_REBOOT            ((TPM_RC_t) 0x130)
#define TPM_RC_REFERENCE_H0      ((TPM_RC_t) 0x910)
#define TPM_RC_REFERENCE_H1      ((TPM_RC_t) 0x911)
#define TPM_RC_REFERENCE_H2      ((TPM_RC_t) 0x912)
#define TPM_RC_REFERENCE_H3      ((TPM_RC_t) 0x913)
#define TPM_RC_REFERENCE_H4      ((TPM_RC_t) 0x914)
#define TPM_RC_REFERENCE_H5      ((TPM_RC_t) 0x915)
#define TPM_RC_REFERENCE_H6      ((TPM_RC_t) 0x916)
#define TPM_RC_REFERENCE_S0      ((TPM_RC_t) 0x918)
#define TPM_RC_REFERENCE_S1      ((TPM_RC_t) 0x919)
#define TPM_RC_REFERENCE_S2      ((TPM_RC_t) 0x91A)
#define TPM_RC_REFERENCE_S3      ((TPM_RC_t) 0x91B)
#define TPM_RC_REFERENCE_S4      ((TPM_RC_t) 0x91C)
#define TPM_RC_REFERENCE_S5      ((TPM_RC_t) 0x91D)
#define TPM_RC_REFERENCE_S6      ((TPM_RC_t) 0x91E)
#define TPM_RC_RESERVED_BITS     ((TPM_RC_t) 0x0A1)
#define TPM_RC_RETRY             ((TPM_RC_t) 0x922)
#define TPM_RC_S                 ((TPM_RC_t) 0x800)
#define TPM_RC_SCHEME            ((TPM_RC_t) 0x092)
#define TPM_RC_SELECTOR          ((TPM_RC_t) 0x098)
#define TPM_RC_SENSITIVE         ((TPM_RC_t) 0x155)
#define TPM_RC_SEQUENCE          ((TPM_RC_t) 0x103)
#define TPM_RC_SESSION_HANDLES   ((TPM_RC_t) 0x905)
#define TPM_RC_SESSION_MEMORY    ((TPM_RC_t) 0x903)
#define TPM_RC_SIGNATURE         ((TPM_RC_t) 0x09B)
#define TPM_RC_SIZE              ((TPM_RC_t) 0x095)
#define TPM_RC_SUCCESS           ((TPM_RC_t) 0x000)
#define TPM_RC_SYMMETRIC         ((TPM_RC_t) 0x096)
#define TPM_RC_TAG               ((TPM_RC_t) 0x097)
#define TPM_RC_TESTING           ((TPM_RC_t) 0x90A)
#define TPM_RC_TICKET            ((TPM_RC_t) 0x0A0)
#define TPM_RC_TOO_MANY_CONTEXTS ((TPM_RC_t) 0x12E)
#define TPM_RC_TYPE              ((TPM_RC_t) 0x08A)
#define TPM_RC_UNBALANCED        ((TPM_RC_t) 0x131)
#define TPM_RC_UPGRADE           ((TPM_RC_t) 0x12D)
#define TPM_RC_VALUE             ((TPM_RC_t) 0x084)
#define TPM_RC_YIELDED           ((TPM_RC_t) 0x908)

/* TPMA_NV_t Constants */
typedef grub_uint32_t TPMA_NV_t;

#define TPMA_NV_PPWRITE        ((TPMA_NV_t) 0x00000001)
#define TPMA_NV_OWNERWRITE     ((TPMA_NV_t) 0x00000002)
#define TPMA_NV_AUTHWRITE      ((TPMA_NV_t) 0x00000004)
#define TPMA_NV_POLICYWRITE    ((TPMA_NV_t) 0x00000008)
#define TPMA_NV_TPM2_NT_MASK   ((TPMA_NV_t) 0x000000F0)
#define TPMA_NV_TPM2_NT_SHIFT  (4)
#define TPMA_NV_RESERVED1_MASK ((TPMA_NV_t) 0x00000300)
#define TPMA_NV_POLICY_DELETE  ((TPMA_NV_t) 0x00000400)
#define TPMA_NV_WRITELOCKED    ((TPMA_NV_t) 0x00000800)
#define TPMA_NV_WRITEALL       ((TPMA_NV_t) 0x00001000)
#define TPMA_NV_WRITEDEFINE    ((TPMA_NV_t) 0x00002000)
#define TPMA_NV_WRITE_STCLEAR  ((TPMA_NV_t) 0x00004000)
#define TPMA_NV_GLOBALLOCK     ((TPMA_NV_t) 0x00008000)
#define TPMA_NV_PPREAD         ((TPMA_NV_t) 0x00010000)
#define TPMA_NV_OWNERREAD      ((TPMA_NV_t) 0x00020000)
#define TPMA_NV_AUTHREAD       ((TPMA_NV_t) 0x00040000)
#define TPMA_NV_POLICYREAD     ((TPMA_NV_t) 0x00080000)
#define TPMA_NV_RESERVED2_MASK ((TPMA_NV_t) 0x01F00000)
#define TPMA_NV_NO_DA          ((TPMA_NV_t) 0x02000000)
#define TPMA_NV_ORDERLY        ((TPMA_NV_t) 0x04000000)
#define TPMA_NV_CLEAR_STCLEAR  ((TPMA_NV_t) 0x08000000)
#define TPMA_NV_READLOCKED     ((TPMA_NV_t) 0x10000000)
#define TPMA_NV_WRITTEN        ((TPMA_NV_t) 0x20000000)
#define TPMA_NV_PLATFORMCREATE ((TPMA_NV_t) 0x40000000)
#define TPMA_NV_READ_STCLEAR   ((TPMA_NV_t) 0x80000000)

/* TPM_ALG_ID_t Constants */
typedef grub_uint16_t TPM_ALG_ID_t;

#define TPM_ALG_ERROR          ((TPM_ALG_ID_t) 0x0000)
#define TPM_ALG_AES            ((TPM_ALG_ID_t) 0x0006)
#define TPM_ALG_CAMELLIA       ((TPM_ALG_ID_t) 0x0026)
#define TPM_ALG_CBC            ((TPM_ALG_ID_t) 0x0042)
#define TPM_ALG_CFB            ((TPM_ALG_ID_t) 0x0043)
#define TPM_ALG_ECB            ((TPM_ALG_ID_t) 0x0044)
#define TPM_ALG_ECC            ((TPM_ALG_ID_t) 0x0023)
#define TPM_ALG_ECDAA          ((TPM_ALG_ID_t) 0x001A)
#define TPM_ALG_ECDSA          ((TPM_ALG_ID_t) 0x0018)
#define TPM_ALG_ECSCHNORR      ((TPM_ALG_ID_t) 0x001C)
#define TPM_ALG_HMAC           ((TPM_ALG_ID_t) 0x0005)
#define TPM_ALG_KDF1_SP800_108 ((TPM_ALG_ID_t) 0x0022)
#define TPM_ALG_KDF1_SP800_56A ((TPM_ALG_ID_t) 0x0020)
#define TPM_ALG_KDF2           ((TPM_ALG_ID_t) 0x0021)
#define TPM_ALG_KEYEDHASH      ((TPM_ALG_ID_t) 0x0008)
#define TPM_ALG_MGF1           ((TPM_ALG_ID_t) 0x0007)
#define TPM_ALG_NULL           ((TPM_ALG_ID_t) 0x0010)
#define TPM_ALG_RSA            ((TPM_ALG_ID_t) 0x0001)
#define TPM_ALG_RSASSA         ((TPM_ALG_ID_t) 0x0014)
#define TPM_ALG_RSAPSS         ((TPM_ALG_ID_t) 0x0016)
#define TPM_ALG_SHA1           ((TPM_ALG_ID_t) 0x0004)
#define TPM_ALG_SHA256         ((TPM_ALG_ID_t) 0x000B)
#define TPM_ALG_SHA384         ((TPM_ALG_ID_t) 0x000C)
#define TPM_ALG_SHA512         ((TPM_ALG_ID_t) 0x000D)
#define TPM_ALG_SM2            ((TPM_ALG_ID_t) 0x001B)
#define TPM_ALG_SM3_256        ((TPM_ALG_ID_t) 0x0012)
#define TPM_ALG_SM4            ((TPM_ALG_ID_t) 0x0013)
#define TPM_ALG_SYMCIPHER      ((TPM_ALG_ID_t) 0x0025)
#define TPM_ALG_XOR            ((TPM_ALG_ID_t) 0x000A)

/* TPM_CAP_t Constants */
typedef grub_uint32_t TPM_CAP_t;

#define TPM_CAP_FIRST           ((TPM_CAP_t) 0x00000000)
#define TPM_CAP_ALGS            ((TPM_CAP_t) 0x00000000)
#define TPM_CAP_HANDLES         ((TPM_CAP_t) 0x00000001)
#define TPM_CAP_COMMANDS        ((TPM_CAP_t) 0x00000002)
#define TPM_CAP_PP_COMMANDS     ((TPM_CAP_t) 0x00000003)
#define TPM_CAP_AUDIT_COMMANDS  ((TPM_CAP_t) 0x00000004)
#define TPM_CAP_PCRS            ((TPM_CAP_t) 0x00000005)
#define TPM_CAP_TPM_PROPERTIES  ((TPM_CAP_t) 0x00000006)
#define TPM_CAP_PCR_PROPERTIES  ((TPM_CAP_t) 0x00000007)
#define TPM_CAP_ECC_CURVES      ((TPM_CAP_t) 0x00000008)
#define TPM_CAP_LAST            ((TPM_CAP_t) 0x00000008)
#define TPM_CAP_VENDOR_PROPERTY ((TPM_CAP_t) 0x00000100)

/* TPM_PT_t Constants */
typedef grub_uint32_t TPM_PT_t;

#define TPM_PT_NONE             ((TPM_PT_t) 0x00000000)
#define PT_GROUP                ((TPM_PT_t) 0x00000100)
#define PT_FIXED                ((TPM_PT_t) (PT_GROUP * 1))
#define TPM_PT_FAMILY_INDICATOR ((TPM_PT_t) (PT_FIXED + 0))
#define TPM_PT_LEVEL            ((TPM_PT_t) (PT_FIXED + 1))
#define TPM_PT_REVISION         ((TPM_PT_t) (PT_FIXED + 2))
#define TPM_PT_DAY_OF_YEAR      ((TPM_PT_t) (PT_FIXED + 3))
#define TPM_PT_YEAR             ((TPM_PT_t) (PT_FIXED + 4))
#define TPM_PT_PCR_COUNT        ((TPM_PT_t) (PT_FIXED + 18))

/* TPM_SE_t Constants */
typedef grub_uint8_t TPM_SE_t;

#define TPM_SE_HMAC   ((TPM_SE_t) 0x00)
#define TPM_SE_POLICY ((TPM_SE_t) 0x01)
#define TPM_SE_TRIAL  ((TPM_SE_t) 0x03)

/* TPMI_YES_NO_t Constants */
typedef grub_uint8_t TPMI_YES_NO_t;

#define TPM_NO  ((TPMI_YES_NO_t)0)
#define TPM_YES ((TPMI_YES_NO_t)1)

/* TPM_ST_t Constants */
typedef grub_uint16_t TPM_ST_t;
typedef TPM_ST_t TPMI_ST_COMMAND_TAG_t;

#define TPM_ST_NO_SESSIONS ((TPMI_ST_COMMAND_TAG_t) 0x8001)
#define TPM_ST_SESSIONS    ((TPMI_ST_COMMAND_TAG_t) 0x8002)

/* TPM_HANDLE_t Types */
typedef grub_uint32_t TPM_HANDLE_t;

typedef TPM_HANDLE_t TPMI_RH_HIERARCHY_t;
typedef TPM_HANDLE_t TPMI_RH_LOCKOUT_t;
typedef TPM_HANDLE_t TPMI_SH_AUTH_SESSION_t;
typedef TPM_HANDLE_t TPMI_DH_CONTEXT_t;
typedef TPM_HANDLE_t TPMI_DH_OBJECT_t;
typedef TPM_HANDLE_t TPMI_DH_ENTITY_t;
typedef TPM_HANDLE_t TPMI_SH_POLICY_t;
typedef TPM_HANDLE_t TPMI_DH_PCR_t;
typedef TPM_HANDLE_t TPMI_RH_NV_AUTH_t;
typedef TPM_HANDLE_t TPMI_RH_NV_INDEX_t;

/* TPM_HT_t Constants */
typedef grub_uint8_t TPM_HT_t;
#define TPM_HT_NV_INDEX   ((TPM_HT_t) 0x01)
#define TPM_HT_PERMANENT  ((TPM_HT_t) 0x40)
#define TPM_HT_PERSISTENT ((TPM_HT_t) 0x81)

/* TPM_RH_t Constants */
typedef TPM_HANDLE_t TPM_RH_t;

#define TPM_RH_FIRST       ((TPM_RH_t) 0x40000000)
#define TPM_RH_SRK         ((TPM_RH_t) 0x40000000)
#define TPM_RH_OWNER       ((TPM_RH_t) 0x40000001)
#define TPM_RH_REVOKE      ((TPM_RH_t) 0x40000002)
#define TPM_RH_TRANSPORT   ((TPM_RH_t) 0x40000003)
#define TPM_RH_OPERATOR    ((TPM_RH_t) 0x40000004)
#define TPM_RH_ADMIN       ((TPM_RH_t) 0x40000005)
#define TPM_RH_EK          ((TPM_RH_t) 0x40000006)
#define TPM_RH_NULL        ((TPM_RH_t) 0x40000007)
#define TPM_RH_UNASSIGNED  ((TPM_RH_t) 0x40000008)
#define TPM_RS_PW          ((TPM_RH_t) 0x40000009)
#define TPM_RH_LOCKOUT     ((TPM_RH_t) 0x4000000A)
#define TPM_RH_ENDORSEMENT ((TPM_RH_t) 0x4000000B)
#define TPM_RH_PLATFORM    ((TPM_RH_t) 0x4000000C)
#define TPM_RH_PLATFORM_NV ((TPM_RH_t) 0x4000000D)
#define TPM_RH_AUTH_00     ((TPM_RH_t) 0x40000010)
#define TPM_RH_AUTH_FF     ((TPM_RH_t) 0x4000010F)
#define TPM_RH_LAST        ((TPM_RH_t) 0x4000010F)

/* TPM_HC_t Constants */
typedef TPM_HANDLE_t TPM_HC_t;
#define TPM_HR_HANDLE_MASK   ((TPM_HC_t) 0x00FFFFFF)
#define TPM_HR_RANGE_MASK    ((TPM_HC_t) 0xFF000000)
#define TPM_HR_SHIFT         ((TPM_HC_t) 24)
#define TPM_HR_NV_INDEX      ((TPM_HC_t) (TPM_HT_NV_INDEX << TPM_HR_SHIFT))
#define TPM_HR_PERSISTENT    ((TPM_HC_t) (TPM_HT_PERSISTENT << TPM_HR_SHIFT))
#define TPM_HR_PERMANENT     ((TPM_HC_t) (TPM_HT_PERMANENT << TPM_HR_SHIFT))
#define TPM_PERSISTENT_FIRST ((TPM_HC_t) (TPM_HR_PERSISTENT + 0))
#define TPM_PERSISTENT_LAST  ((TPM_HC_t) (TPM_PERSISTENT_FIRST + 0x00FFFFFF))
#define TPM_PERMANENT_FIRST  ((TPM_HC_t) TPM_RH_FIRST)
#define TPM_PERMANENT_LAST   ((TPM_HC_t) TPM_RH_LAST)

/* TPM Handle Type Checks */
#define TPM_HT_IS_NVINDEX(HANDLE) (((HANDLE) >> TPM_HR_SHIFT) == TPM_HT_NV_INDEX)
#define TPM_HT_IS_PERMANENT(HANDLE) (((HANDLE) >> TPM_HR_SHIFT) == TPM_HT_PERMANENT)
#define TPM_HT_IS_PERSISTENT(HANDLE) (((HANDLE) >> TPM_HR_SHIFT) == TPM_HT_PERSISTENT)

/* TPM_ECC_CURVE_t Constants */
typedef grub_uint16_t TPM_ECC_CURVE_t;

#define TPM_ECC_NONE      ((TPM_ECC_CURVE_t) 0x0000)
#define TPM_ECC_NIST_P192 ((TPM_ECC_CURVE_t) 0x0001)
#define TPM_ECC_NIST_P224 ((TPM_ECC_CURVE_t) 0x0002)
#define TPM_ECC_NIST_P256 ((TPM_ECC_CURVE_t) 0x0003)
#define TPM_ECC_NIST_P384 ((TPM_ECC_CURVE_t) 0x0004)
#define TPM_ECC_NIST_P521 ((TPM_ECC_CURVE_t) 0x0005)
#define TPM_ECC_BN_P256   ((TPM_ECC_CURVE_t) 0x0010)
#define TPM_ECC_BN_P638   ((TPM_ECC_CURVE_t) 0x0011)
#define TPM_ECC_SM2_P256  ((TPM_ECC_CURVE_t) 0x0020)

/* TPM_CC_t Constants */
typedef grub_uint32_t TPM_CC_t;

#define TPM_CC_EvictControl     ((TPM_CC_t) 0x00000120)
#define TPM_CC_CreatePrimary    ((TPM_CC_t) 0x00000131)
#define TPM_CC_Create           ((TPM_CC_t) 0x00000153)
#define TPM_CC_FlushContext     ((TPM_CC_t) 0x00000165)
#define TPM_CC_ReadPublic       ((TPM_CC_t) 0x00000173)
#define TPM_CC_StartAuthSession ((TPM_CC_t) 0x00000176)
#define TPM_CC_PolicyPCR        ((TPM_CC_t) 0x0000017f)
#define TPM_CC_NV_DefineSpace   ((TPM_CC_t) 0x0000012a)
#define TPM_CC_NV_Read          ((TPM_CC_t) 0x0000014e)
#define TPM_CC_NV_ReadPublic    ((TPM_CC_t) 0x00000169)
#define TPM_CC_NV_Write         ((TPM_CC_t) 0x00000137)
#define TPM_CC_NV_UndefineSpace ((TPM_CC_t) 0x00000122)
#define TPM_CC_GetCapability    ((TPM_CC_t) 0x0000017a)
#define TPM_CC_PCR_Read         ((TPM_CC_t) 0x0000017e)
#define TPM_CC_Load             ((TPM_CC_t) 0x00000157)
#define TPM_CC_LoadExternal     ((TPM_CC_t) 0x00000167)
#define TPM_CC_Unseal           ((TPM_CC_t) 0x0000015e)
#define TPM_CC_PolicyGetDigest  ((TPM_CC_t) 0x00000189)
#define TPM_CC_Hash             ((TPM_CC_t) 0x0000017d)
#define TPM_CC_VerifySignature  ((TPM_CC_t) 0x00000177)
#define TPM_CC_PolicyAuthorize  ((TPM_CC_t) 0x0000016a)
#define TPM_CC_TestParms        ((TPM_CC_t) 0x0000018a)

/* Hash algorithm sizes */
#define TPM_SHA1_DIGEST_SIZE    20
#define TPM_SHA256_DIGEST_SIZE  32
#define TPM_SM3_256_DIGEST_SIZE 32
#define TPM_SHA384_DIGEST_SIZE  48
#define TPM_SHA512_DIGEST_SIZE  64

/* Encryption algorithm sizes */
#define TPM_MAX_SYM_BLOCK_SIZE 16
#define TPM_MAX_SYM_DATA       256
#define TPM_MAX_ECC_KEY_BYTES  128
#define TPM_MAX_SYM_KEY_BYTES  32
#define TPM_MAX_RSA_KEY_BYTES  512

/* Buffer Size Constants */
#define TPM_MAX_PCRS                      24
#define TPM_NUM_PCR_BANKS                 16
#define TPM_PCR_SELECT_MAX                ((TPM_MAX_PCRS + 7) / 8)
#define TPM_MAX_DIGEST_BUFFER             1024
#define TPM_MAX_TPM_PROPERTIES            8
#define TPM_MAX_NV_BUFFER_SIZE            2048
#define TPM_PRIVATE_VENDOR_SPECIFIC_BYTES 1280

/* TPM_GENERATED_t Constants */
typedef grub_uint32_t TPM_GENERATED_t;

#define TPM_GENERATED_VALUE ((TPM_GENERATED_t) 0xff544347)

/* TPM_ALG_ID_t Types */
typedef TPM_ALG_ID_t TPMI_ALG_PUBLIC_t;
typedef TPM_ALG_ID_t TPMI_ALG_HASH_t;
typedef TPM_ALG_ID_t TPMI_ALG_KEYEDHASH_SCHEME_t;
typedef TPM_ALG_ID_t TPMI_ALG_KDF_t;
typedef TPM_ALG_ID_t TPMI_ALG_SYM_OBJECT_t;
typedef TPM_ALG_ID_t TPMI_ALG_SYM_MODE_t;
typedef TPM_ALG_ID_t TPMI_ALG_RSA_DECRYPT_t;
typedef TPM_ALG_ID_t TPMI_ALG_ECC_SCHEME_t;
typedef TPM_ALG_ID_t TPMI_ALG_ASYM_SCHEME_t;
typedef TPM_ALG_ID_t TPMI_ALG_RSA_SCHEME_t;
typedef TPM_ALG_ID_t TPMI_ALG_SYM_t;
typedef TPM_ALG_ID_t TPMI_ALG_SIG_SCHEME_t;

/* TPM_KEY_BITS_t Type */
typedef grub_uint16_t TPM_KEY_BITS_t;

/* TPMI_ECC_CURVE_t Types */
typedef TPM_ECC_CURVE_t TPMI_ECC_CURVE_t;

/* TPMI_RH_PROVISION_t Type */
typedef TPM_HANDLE_t TPMI_RH_PROVISION_t;

/* TPMI_RH_PROVISION_t Type */
typedef TPM_HANDLE_t TPMI_DH_PERSISTENT_t;

#endif /* ! GRUB_TPM2_INTERNAL_TYPES_HEADER */
