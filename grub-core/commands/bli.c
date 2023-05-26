/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2023  Free Software Foundation, Inc.
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
 *
 *  Implementation of the Boot Loader Interface.
 */

#include <grub/charset.h>
#include <grub/efi/api.h>
#include <grub/efi/disk.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/extcmd.h>
#include <grub/gpt_partition.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/partition.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define MODNAME "bli"

static const grub_guid_t bli_vendor_guid = GRUB_EFI_VENDOR_BOOT_LOADER_INTERFACE_GUID;

static grub_err_t
get_part_uuid (const char *device_name, char **part_uuid)
{
  grub_device_t device;
  grub_err_t status = GRUB_ERR_NONE;
  grub_disk_t disk = NULL;
  struct grub_gpt_partentry entry;

  device = grub_device_open (device_name);
  if (device == NULL)
    return grub_error (grub_errno, N_("cannot open device: %s"), device_name);

  disk = grub_disk_open (device->disk->name);
  if (disk == NULL)
    {
      status = grub_error (grub_errno, N_("cannot open disk: %s"), device_name);
      grub_device_close (device);
      return status;
    }

  if (grub_strcmp (device->disk->partition->partmap->name, "gpt") != 0)
    {
      status = grub_error (GRUB_ERR_BAD_PART_TABLE,
			   N_("this is not a GPT partition table: %s"), device_name);
      goto fail;
    }

  if (grub_disk_read (disk, device->disk->partition->offset,
		      device->disk->partition->index, sizeof (entry), &entry) != GRUB_ERR_NONE)
    {
      status = grub_error (grub_errno, N_("read error: %s"), device_name);
      goto fail;
    }

  *part_uuid = grub_xasprintf ("%pG", &entry.guid);
  if (*part_uuid == NULL)
    status = grub_errno;

 fail:
  grub_disk_close (disk);
  grub_device_close (device);

  return status;
}

static grub_err_t
set_loader_device_part_uuid (void)
{
  grub_efi_loaded_image_t *image;
  char *device_name;
  grub_err_t status = GRUB_ERR_NONE;
  char *part_uuid = NULL;

  image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (image == NULL)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("unable to find boot device"));

  device_name = grub_efidisk_get_device_name (image->device_handle);
  if (device_name == NULL)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("unable to find boot device"));

  status = get_part_uuid (device_name, &part_uuid);

  if (status == GRUB_ERR_NONE)
    status = grub_efi_set_variable_to_string ("LoaderDevicePartUUID", &bli_vendor_guid, part_uuid,
					      GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS |
					      GRUB_EFI_VARIABLE_RUNTIME_ACCESS);
  else
    grub_error (status, N_("unable to determine partition UUID of boot device"));

  grub_free (part_uuid);
  grub_free (device_name);
  return status;
}

GRUB_MOD_INIT (bli)
{
  grub_efi_set_variable_to_string ("LoaderInfo", &bli_vendor_guid, PACKAGE_STRING,
				   GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS |
				   GRUB_EFI_VARIABLE_RUNTIME_ACCESS);
  set_loader_device_part_uuid ();
}
