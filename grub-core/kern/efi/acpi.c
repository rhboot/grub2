/* acpi.c - get acpi tables. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
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

#include <grub/acpi.h>
#include <grub/efi/efi.h>

struct grub_acpi_rsdp_v10 *
grub_machine_acpi_get_rsdpv1 (void)
{
  static grub_guid_t acpi_guid = GRUB_EFI_ACPI_TABLE_GUID;

  return (struct grub_acpi_rsdp_v10 *) grub_efi_find_configuration_table (&acpi_guid);
}

struct grub_acpi_rsdp_v20 *
grub_machine_acpi_get_rsdpv2 (void)
{
  static grub_guid_t acpi20_guid = GRUB_EFI_ACPI_20_TABLE_GUID;

  return (struct grub_acpi_rsdp_v20 *) grub_efi_find_configuration_table (&acpi20_guid);
}
