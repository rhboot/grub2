/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022  Free Software Foundation, Inc.
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

#ifndef GRUB_EFI_CC_H
#define GRUB_EFI_CC_H 1

#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/err.h>

#define GRUB_EFI_CC_MEASUREMENT_PROTOCOL_GUID \
  { 0x96751a3d, 0x72f4, 0x41a6, \
    { 0xa7, 0x94, 0xed, 0x5d, 0x0e, 0x67, 0xae, 0x6b } \
  };

struct grub_efi_cc_version
{
  grub_efi_uint8_t Major;
  grub_efi_uint8_t Minor;
};
typedef struct grub_efi_cc_version grub_efi_cc_version_t;

/* EFI_CC Type/SubType definition. */
#define GRUB_EFI_CC_TYPE_NONE	0
#define GRUB_EFI_CC_TYPE_SEV	1
#define GRUB_EFI_CC_TYPE_TDX	2

struct grub_efi_cc_type
{
  grub_efi_uint8_t Type;
  grub_efi_uint8_t SubType;
};
typedef struct grub_efi_cc_type grub_efi_cc_type_t;

typedef grub_efi_uint32_t grub_efi_cc_event_log_bitmap_t;
typedef grub_efi_uint32_t grub_efi_cc_event_log_format_t;
typedef grub_efi_uint32_t grub_efi_cc_event_algorithm_bitmap_t;
typedef grub_efi_uint32_t grub_efi_cc_mr_index_t;

/* Intel TDX measure register index. */
#define GRUB_TDX_MR_INDEX_MRTD	0
#define GRUB_TDX_MR_INDEX_RTMR0	1
#define GRUB_TDX_MR_INDEX_RTMR1	2
#define GRUB_TDX_MR_INDEX_RTMR2	3
#define GRUB_TDX_MR_INDEX_RTMR3	4

#define GRUB_EFI_CC_EVENT_LOG_FORMAT_TCG_2	0x00000002
#define GRUB_EFI_CC_BOOT_HASH_ALG_SHA384	0x00000004
#define GRUB_EFI_CC_EVENT_HEADER_VERSION	1

struct grub_efi_cc_event_header
{
  /* Size of the event header itself (sizeof(EFI_TD_EVENT_HEADER)). */
  grub_efi_uint32_t      HeaderSize;

  /*
   * Header version. For this version of this specification,
   * the value shall be 1.
   */
  grub_efi_uint16_t      HeaderVersion;

  /* Index of the MR that shall be extended. */
  grub_efi_cc_mr_index_t MrIndex;

  /* Type of the event that shall be extended (and optionally logged). */
  grub_efi_uint32_t      EventType;
} GRUB_PACKED;
typedef struct grub_efi_cc_event_header grub_efi_cc_event_header_t;

struct grub_efi_cc_event
{
  /* Total size of the event including the Size component, the header and the Event data. */
  grub_efi_uint32_t          Size;
  grub_efi_cc_event_header_t Header;
  grub_efi_uint8_t           Event[0];
} GRUB_PACKED;
typedef struct grub_efi_cc_event grub_efi_cc_event_t;

struct grub_efi_cc_boot_service_capability
{
  /* Allocated size of the structure. */
  grub_efi_uint8_t                     Size;

  /*
   * Version of the grub_efi_cc_boot_service_capability_t structure itself.
   * For this version of the protocol, the Major version shall be set to 1
   * and the Minor version shall be set to 1.
   */
  grub_efi_cc_version_t                StructureVersion;

  /*
   * Version of the EFI TD protocol.
   * For this version of the protocol, the Major version shall be set to 1
   * and the Minor version shall be set to 1.
   */
  grub_efi_cc_version_t                ProtocolVersion;

  /* Supported hash algorithms. */
  grub_efi_cc_event_algorithm_bitmap_t HashAlgorithmBitmap;

  /* Bitmap of supported event log formats. */
  grub_efi_cc_event_log_bitmap_t       SupportedEventLogs;

  /* Indicates the CC type. */
  grub_efi_cc_type_t CcType;
};
typedef struct grub_efi_cc_boot_service_capability grub_efi_cc_boot_service_capability_t;

struct grub_efi_cc_protocol
{
  grub_efi_status_t
  (__grub_efi_api *get_capability) (struct grub_efi_cc_protocol *this,
				    grub_efi_cc_boot_service_capability_t *ProtocolCapability);

  grub_efi_status_t
  (__grub_efi_api *get_event_log) (struct grub_efi_cc_protocol *this,
				   grub_efi_cc_event_log_format_t EventLogFormat,
				   grub_efi_physical_address_t *EventLogLocation,
				   grub_efi_physical_address_t *EventLogLastEntry,
				   grub_efi_boolean_t *EventLogTruncated);

  grub_efi_status_t
  (__grub_efi_api *hash_log_extend_event) (struct grub_efi_cc_protocol *this,
					   grub_efi_uint64_t Flags,
					   grub_efi_physical_address_t DataToHash,
					   grub_efi_uint64_t DataToHashLen,
					   grub_efi_cc_event_t *EfiCcEvent);

  grub_efi_status_t
  (__grub_efi_api *map_pcr_to_mr_index) (struct grub_efi_cc_protocol *this,
					 grub_efi_uint32_t PcrIndex,
					 grub_efi_cc_mr_index_t *MrIndex);
};
typedef struct grub_efi_cc_protocol grub_efi_cc_protocol_t;

#endif
