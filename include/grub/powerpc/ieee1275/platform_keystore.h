/*
 * Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved. This
 * program and the accompanying materials are licensed and made available
 * under the terms and conditions of the 2-Clause BSD License which
 * accompanies this distribution.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * https://github.com/tianocore/edk2-staging (edk2-staging repo of tianocore),
 * the ImageAuthentication.h file under it, and here's the copyright and license.
 *
 * MdePkg/Include/Guid/ImageAuthentication.h
 *
 * Copyright 2024 IBM Corp.
 */

#ifndef __PLATFORM_KEYSTORE_H__
#define __PLATFORM_KEYSTORE_H__

#include <grub/symbol.h>
#include <grub/mm.h>
#include <grub/types.h>

#if __GNUC__ >= 9
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

#define GRUB_MAX_HASH_SIZE 64

typedef struct grub_esd grub_esd_t;
typedef struct grub_esl grub_esl_t;

/*
 * It is derived from EFI_SIGNATURE_DATA
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 *
 * The structure of an EFI signature database (ESD).*/
struct grub_esd
{
  /*
   * An identifier which identifies the agent which added
   * the signature to the list.
   */
  grub_uuid_t signatureowner;
  /* The format of the signature is defined by the SignatureType.*/
  grub_uint8_t signaturedata[];
} GRUB_PACKED;

/*
 * It is derived from EFI_SIGNATURE_LIST
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 *
 * The structure of an EFI signature list (ESL).*/
struct grub_esl
{
  /* Type of the signature. GUID signature types are defined in below.*/
  grub_uuid_t signaturetype;
  /* Total size of the signature list, including this header.*/
  grub_uint32_t signaturelistsize;
  /*
   * Size of the signature header which precedes
   * the array of signatures.
   */
  grub_uint32_t signatureheadersize;
  /* Size of each signature.*/
  grub_uint32_t signaturesize;
} GRUB_PACKED;

/*
 * It is derived from EFI_CERT_X509_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_GUID            \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94,  \
      0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15,  \
      0x5c, 0x2b, 0xf0, 0x72               \
    }                                      \
  }

/*
 * It is derived from EFI_CERT_SHA256_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_SHA256_GUID          \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50,  \
      0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9,  \
      0x36, 0x93, 0x43, 0x28               \
    }                                      \
  }

/*
 * It is derived from EFI_CERT_SHA384_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_SHA384_GUID          \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x07, 0x53, 0x3e, 0xff, 0xd0, 0x9f,  \
      0xc9, 0x48, 0x85, 0xf1, 0x8a, 0xd5,  \
      0x6c, 0x70, 0x1e, 0x1                \
    }                                      \
  }

/*
 * It is derived from EFI_CERT_SHA512_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_SHA512_GUID          \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0xae, 0x0f, 0x3e, 0x09, 0xc4, 0xa6,  \
      0x50, 0x4f, 0x9f, 0x1b, 0xd4, 0x1e,  \
      0x2b, 0x89, 0xc1, 0x9a               \
    }                                      \
  }

/*
 * It is derived from EFI_CERT_X509_SHA256_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_SHA256_GUID     \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x92, 0xa4, 0xd2, 0x3b, 0xc0, 0x96,  \
      0x79, 0x40, 0xb4, 0x20, 0xfc, 0xf9,  \
      0x8e, 0xf1, 0x03, 0xed               \
    }                                      \
  }

/*
 * It is derived from EFI_CERT_X509_SHA384_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_SHA384_GUID     \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x6e, 0x87, 0x76, 0x70, 0xc2, 0x80,  \
      0xe6, 0x4e, 0xaa, 0xd2, 0x28, 0xb3,  \
      0x49, 0xa6, 0x86, 0x5b               \
    }                                      \
  }

/*
 * It is derived from EFI_CERT_X509_SHA512_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_SHA512_GUID     \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x63, 0xbf, 0x6d, 0x44, 0x02, 0x25,  \
      0xda, 0x4c, 0xbc, 0xfa, 0x24, 0x65,  \
      0xd2, 0xb0, 0xfe, 0x9d               \
    }                                      \
  }

typedef struct grub_pks_sd grub_pks_sd_t;
typedef struct grub_pks grub_pks_t;

/* The structure of a PKS signature data.*/
struct grub_pks_sd
{
  grub_uuid_t guid;      /* signature type */
  grub_uint8_t *data;    /* signature data */
  grub_size_t data_size; /* size of signature data */
} GRUB_PACKED;

/* The structure of a PKS.*/
struct grub_pks
{
  grub_pks_sd_t *db;        /* signature database */
  grub_pks_sd_t *dbx;       /* forbidden signature database */
  grub_size_t db_entries;   /* size of signature database */
  grub_size_t dbx_entries;  /* size of forbidden signature database */
} GRUB_PACKED;

#ifdef __powerpc__

/* Initialization of the Platform Keystore */
grub_err_t grub_pks_keystore_init (void);
/* Free allocated memory */
void EXPORT_FUNC(grub_pks_free_keystore) (void);
extern grub_uint8_t EXPORT_VAR(grub_pks_use_keystore);
extern grub_pks_t EXPORT_VAR(grub_pks_keystore);

#else

#define grub_pks_use_keystore	0
grub_pks_t grub_pks_keystore = {NULL, NULL, 0, 0};
void grub_pks_free_keystore (void);

#endif

#endif
