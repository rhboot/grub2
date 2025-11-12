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
 * https://github.com/tianocore/edk2-staging (edk2-staging repo of tianocore),
 * the ImageAuthentication.h file under it, and here's the copyright and license.
 *
 * MdePkg/Include/Guid/ImageAuthentication.h
 *
 * Copyright 2022, 2023, 2024, 2025 IBM Corp.
 */

#ifndef PLATFORM_KEYSTORE_HEADER
#define PLATFORM_KEYSTORE_HEADER    1

#include <grub/symbol.h>
#include <grub/mm.h>
#include <grub/types.h>

/*
 * It is derived from EFI_SIGNATURE_DATA
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 *
 * The structure of an EFI Signature Database (ESD). */
struct grub_esd
{
  /*
   * An identifier which identifies the agent which added the signature to
   * the list.
   */
  grub_packed_guid_t signature_owner;
  /* The format of the signature is defined by the SignatureType. */
  grub_uint8_t signature_data[];
} GRUB_PACKED;
typedef struct grub_esd grub_esd_t;

/*
 * It is derived from EFI_SIGNATURE_LIST
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 *
 * The structure of an EFI Signature List (ESL). */
struct grub_esl
{
  /* Type of the signature. GUID signature types are defined in below. */
  grub_packed_guid_t signature_type;
  /* Total size of the signature list, including this header. */
  grub_uint32_t signature_list_size;
  /* Size of the signature header which precedes the array of signatures. */
  grub_uint32_t signature_header_size;
  /* Size of each signature.*/
  grub_uint32_t signature_size;
} GRUB_PACKED;
typedef struct grub_esl grub_esl_t;

/* The structure of a PKS Signature Database (SD). */
struct grub_pks_sd
{
  grub_packed_guid_t guid; /* Signature type. */
  grub_uint8_t *data;      /* Signature data. */
  grub_size_t data_size;   /* Size of signature data. */
} GRUB_PACKED;
typedef struct grub_pks_sd grub_pks_sd_t;

/* The structure of a Platform KeyStore (PKS). */
struct grub_pks
{
  grub_pks_sd_t *db;        /* Signature database. */
  grub_pks_sd_t *dbx;       /* Forbidden signature database. */
  grub_uint32_t db_entries; /* Size of signature database. */
  grub_uint32_t dbx_entries;/* Size of forbidden signature database. */
  bool db_exists;           /* Flag to indicate if the db exists or not in PKS. */
};
typedef struct grub_pks grub_pks_t;

#if defined(__powerpc__)
/* Initialization of the Platform Keystore. */
extern void
grub_pks_keystore_init (void);

/* Platform KeyStore db and dbx. */
extern grub_pks_t *
EXPORT_FUNC (grub_pks_get_keystore) (void);

/* Free allocated memory. */
extern void
EXPORT_FUNC (grub_pks_free_data) (void);
#else
static inline grub_pks_t *
grub_pks_get_keystore (void)
{
  return NULL;
}

static inline void
grub_pks_free_data (void)
{
}
#endif /* __powerpc__ */
#endif
