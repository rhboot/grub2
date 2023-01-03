/*-*- Mode: C; c-basic-offset: 2; indent-tabs-mode: t -*-*/

/* boot-loader-interface.c - implementation of the boot loader interface
 */

/*
 *  GRUB  --  GRand Unified Bootloader
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

GRUB_MOD_LICENSE ("GPLv3+");

#define MODNAME "boot-loader-interface"

static const grub_efi_guid_t boot_loader_interface_vendor_guid =
  { 0x4a67b082, 0x0a4c, 0x41cf,
    {0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f} };

static char *
machine_get_bootdevice (void)
{
  grub_efi_loaded_image_t *image;

  image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (!image)
    return NULL;

  return grub_efidisk_get_device_name (image->device_handle);
}

static grub_err_t
get_part_uuid (grub_device_t dev, char **part_uuid)
{
  grub_err_t status = GRUB_ERR_NONE;
  grub_disk_t disk;
  struct grub_gpt_partentry entry;
  grub_gpt_part_guid_t *guid;

  if (!dev || !dev->disk || !dev->disk->partition)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid device"));

  disk = grub_disk_open (dev->disk->name);
  if (!disk)
    {
      status = grub_errno;
      grub_dprintf (MODNAME, "Error opening disk\n");
      return grub_errno;
    }

  if (grub_strcmp (dev->disk->partition->partmap->name, "gpt") != 0)
    {
      status = grub_error (GRUB_ERR_BAD_PART_TABLE,
                           N_("This is not a GPT partition table"));
      goto finish;
    }

  if (grub_disk_read (disk, dev->disk->partition->offset,
                      dev->disk->partition->index, sizeof (entry), &entry))
    {
      status = grub_errno;
      grub_dprintf (MODNAME, "%s: Read error\n", dev->disk->name);
      goto finish;
    }

  guid = &entry.guid;
  *part_uuid = grub_xasprintf (
      "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      grub_le_to_cpu32 (guid->data1), grub_le_to_cpu16 (guid->data2),
      grub_le_to_cpu16 (guid->data3), guid->data4[0], guid->data4[1],
      guid->data4[2], guid->data4[3], guid->data4[4], guid->data4[5],
      guid->data4[6], guid->data4[7]);
  if (!*part_uuid)
    {
      status = grub_errno;
    }

finish:
  grub_disk_close (disk);

  return status;
}

static grub_err_t
set_efi_str_variable (const char *name, const grub_efi_guid_t *guid,
                      const char *value)
{
  grub_size_t len;
  grub_size_t len16;
  grub_efi_char16_t *value_16;
  grub_err_t status;

  len = grub_strlen (value);
  len16 = len * GRUB_MAX_UTF16_PER_UTF8;

  value_16 = grub_calloc (len16 + 1, sizeof (value_16[0]));
  if (!value_16)
    return grub_errno;

  len16
      = grub_utf8_to_utf16 (value_16, len16, (grub_uint8_t *)value, len, NULL);
  value_16[len16] = 0;

  status = grub_efi_set_variable_with_attributes (
      name, guid, (void *)value_16, (len16 + 1) * sizeof (value_16[0]),
      GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS | GRUB_EFI_VARIABLE_RUNTIME_ACCESS);
  if (status != GRUB_ERR_NONE)
    {
      grub_dprintf (MODNAME, "Error setting EFI variable %s: %d\n", name,
                    status);
    }

  grub_free (value_16);

  return status;
}

static grub_err_t
set_loader_info (void)
{
  grub_err_t status;
  status = set_efi_str_variable (
      "LoaderInfo", &boot_loader_interface_vendor_guid, PACKAGE_STRING);
  return status;
}

static grub_err_t
set_loader_device_part_uuid (void)
{
  grub_err_t status = GRUB_ERR_NONE;
  char *device_name = NULL;
  grub_device_t device;
  char *part_uuid = NULL;

  device_name = machine_get_bootdevice ();
  if (!device_name)
    {
      return grub_error (GRUB_ERR_BAD_DEVICE,
                         N_("Unable to find boot device"));
    }

  device = grub_device_open (device_name);
  if (!device)
    {
      status = grub_errno;
      grub_dprintf (MODNAME, "Error opening device: %s", device_name);
      goto err;
    }

  status = get_part_uuid (device, &part_uuid);

  grub_device_close (device);

  if (status == GRUB_ERR_NONE)
    {
      status = set_efi_str_variable ("LoaderDevicePartUUID",
                                     &boot_loader_interface_vendor_guid,
                                     part_uuid);
    }

err:
  grub_free (part_uuid);
  grub_free (device_name);
  return status;
}

static grub_err_t
grub_cmd_boot_loader_interface (grub_extcmd_context_t ctxt UNUSED,
                                int argc UNUSED, char **args UNUSED)
{
  grub_err_t status;

  status = set_loader_info ();
  if (status != GRUB_ERR_NONE)
    return status;

  status = set_loader_device_part_uuid ();
  if (status != GRUB_ERR_NONE)
    return status;

  return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT (boot-loader-interface)
{
  grub_dprintf (MODNAME, "%s got here\n", __func__);
  cmd = grub_register_extcmd (
      "boot-loader-interface", grub_cmd_boot_loader_interface, 0, NULL,
      N_("Set EFI variables according to Boot Loader Interface spec."), NULL);
}

GRUB_MOD_FINI (boot-loader-interface) { grub_unregister_extcmd (cmd); }
