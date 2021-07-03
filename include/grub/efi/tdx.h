/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2015  Free Software Foundation, Inc.
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

#ifndef GRUB_EFI_TDX_HEADER
#define GRUB_EFI_TDX_HEADER 1

#define EFI_TD_PROTOCOL_GUID {0x96751a3d, 0x72f4, 0x41a6, {0xa7, 0x94, 0xed, 0x5d, 0x0e, 0x67, 0xae, 0x6b}};

typedef struct tdEFI_TD_VERSION {
  grub_efi_uint8_t Major;
  grub_efi_uint8_t Minor;
} GRUB_PACKED EFI_TD_VERSION;

typedef grub_efi_uint32_t EFI_TD_EVENT_LOG_BITMAP;
typedef grub_efi_uint32_t EFI_TD_EVENT_LOG_FORMAT;
typedef grub_efi_uint32_t EFI_TD_EVENT_ALGORITHM_BITMAP;
typedef grub_efi_uint32_t EFI_TD_MR_INDEX;

typedef struct tdEFI_TD_EVENT_HEADER {
  //
  // Size of the event header itself (sizeof(EFI_TD_EVENT_HEADER)).
  //
  grub_efi_uint32_t HeaderSize;
  //
  // Header version. For this version of this specification, the value shall be 1.
  //
  grub_efi_uint16_t HeaderVersion;
  //
  // Index of the MR that shall be extended.
  //
  EFI_TD_MR_INDEX MrIndex;
  //
  // Type of the event that shall be extended (and optionally logged).
  //
  grub_efi_uint32_t EventType;
} GRUB_PACKED EFI_TD_EVENT_HEADER;

typedef struct tdEFI_TD_EVENT {
  //
  // Total size of the event including the Size component, the header and the Event data.
  //
  grub_efi_uint32_t Size;
  EFI_TD_EVENT_HEADER Header;
  grub_efi_uint8_t Event[1];
} GRUB_PACKED EFI_TD_EVENT;

typedef struct tdEFI_TD_BOOT_SERVICE_CAPABILITY {
  //
  // Allocated size of the structure
  //
  grub_efi_uint8_t Size;
  //
  // Version of the EFI_TD_BOOT_SERVICE_CAPABILITY structure itself.
  // For this version of the protocol, the Major version shall be set to 1
  // and the Minor version shall be set to 1.
  //
  EFI_TD_VERSION StructureVersion;
  //
  // Version of the EFI TD protocol.
  // For this version of the protocol, the Major version shall be set to 1
  // and the Minor version shall be set to 1.
  //
  EFI_TD_VERSION ProtocolVersion;
  //
  // Supported hash algorithms
  //
  EFI_TD_EVENT_ALGORITHM_BITMAP HashAlgorithmBitmap;
  //
  // Bitmap of supported event log formats
  //
  EFI_TD_EVENT_LOG_BITMAP SupportedEventLogs;
  //
  // False = TD not present
  //
  grub_efi_boolean_t TdPresentFlag;
} EFI_TD_BOOT_SERVICE_CAPABILITY;

struct grub_efi_td_protocol
{
  grub_efi_status_t (*get_capability) (struct grub_efi_td_protocol *this,
				       EFI_TD_BOOT_SERVICE_CAPABILITY *ProtocolCapability);
  grub_efi_status_t (*get_event_log) (struct grub_efi_td_protocol *this,
				      EFI_TD_EVENT_LOG_FORMAT EventLogFormat,
				      grub_efi_physical_address_t *EventLogLocation,
				      grub_efi_physical_address_t *EventLogLastEntry,
				      grub_efi_boolean_t *EventLogTruncated);
  grub_efi_status_t (*hash_log_extend_event) (struct grub_efi_td_protocol *this,
					      grub_efi_uint64_t Flags,
					      grub_efi_physical_address_t DataToHash,
					      grub_efi_uint64_t DataToHashLen,
					      EFI_TD_EVENT *EfiTdEvent);
  grub_efi_status_t (*map_pcr_to_mr_index) (struct grub_efi_td_protocol *this,
                                            grub_efi_uint32_t PcrIndex,
                                            EFI_TD_MR_INDEX *MrIndex);
};

typedef struct grub_efi_td_protocol grub_efi_td_protocol_t;

#endif
