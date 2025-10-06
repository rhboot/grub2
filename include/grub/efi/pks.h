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

#ifndef PKS_HEADER
#define PKS_HEADER   1

#include <grub/types.h>

/*
 * It is derived from EFI_CERT_X509_GUID.
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_GUID \
  (grub_guid_t) \
  { 0xa159c0a5, 0xe494, 0xa74a, \
    { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } \
  }

/*
 * It is derived from EFI_CERT_SHA256_GUID.
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_SHA256_GUID \
  (grub_guid_t) \
  { 0x2616c4c1, 0x4c50, 0x9240, \
    { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } \
  }

/*
 * It is derived from EFI_CERT_SHA384_GUID.
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_SHA384_GUID \
  (grub_guid_t) \
  { 0x07533eff, 0xd09f, 0xc948, \
    { 0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x1 } \
  }

/*
 * It is derived from EFI_CERT_SHA512_GUID.
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_SHA512_GUID \
  (grub_guid_t) \
  { 0xae0f3e09, 0xc4a6, 0x504f, \
    { 0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a } \
  }

/*
 * It is derived from EFI_CERT_X509_SHA256_GUID.
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_SHA256_GUID \
  (grub_guid_t) \
  { 0x92a4d23b, 0xc096, 0x7940, \
    { 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed } \
  }

/*
 * It is derived from EFI_CERT_X509_SHA384_GUID.
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_SHA384_GUID     \
  (grub_guid_t) \
  { 0x6e877670, 0xc280, 0xe64e, \
    { 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b } \
  }

/*
 * It is derived from EFI_CERT_X509_SHA512_GUID.
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
#define GRUB_PKS_CERT_X509_SHA512_GUID \
  (grub_guid_t) \
  { 0x63bf6d44, 0x0225, 0xda4c, \
    { 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d } \
  }

#endif
