/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2014 Free Software Foundation, Inc.
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

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/cpu/linux.h>
#include <grub/efi/efi.h>
#include <grub/efi/pe32.h>
#include <grub/efi/linux.h>

#define SHIM_LOCK_GUID \
 { 0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} }

struct grub_efi_shim_lock
{
  grub_efi_status_t (*verify) (void *buffer, grub_uint32_t size);
};
typedef struct grub_efi_shim_lock grub_efi_shim_lock_t;

// Returns 1 on success, -1 on error, 0 when not available
int
grub_linuxefi_secure_validate (void *data, grub_uint32_t size)
{
  grub_efi_guid_t guid = SHIM_LOCK_GUID;
  grub_efi_shim_lock_t *shim_lock;
  grub_efi_status_t status;

  shim_lock = grub_efi_locate_protocol(&guid, NULL);
  grub_dprintf ("secureboot", "shim_lock: %p\n", shim_lock);
  if (!shim_lock)
    {
      grub_dprintf ("secureboot", "shim not available\n");
      return 0;
    }

  grub_dprintf ("secureboot", "Asking shim to verify kernel signature\n");
  status = shim_lock->verify (data, size);
  grub_dprintf ("secureboot", "shim_lock->verify(): %ld\n", (long int)status);
  if (status == GRUB_EFI_SUCCESS)
    {
      grub_dprintf ("secureboot", "Kernel signature verification passed\n");
      return 1;
    }

  grub_dprintf ("secureboot", "Kernel signature verification failed (0x%lx)\n",
		(unsigned long) status);

  return -1;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

typedef void (*handover_func) (void *, grub_efi_system_table_t *, void *);

grub_err_t
grub_efi_linux_boot (void *kernel_addr, grub_off_t handover_offset,
		     void *kernel_params)
{
  grub_efi_loaded_image_t *loaded_image = NULL;
  handover_func hf;
  int offset = 0;

#ifdef __x86_64__
  offset = 512;
#endif

  /*
   * Since the EFI loader is not calling the LoadImage() and StartImage()
   * services for loading the kernel and booting respectively, it has to
   * set the Loaded Image base address.
   */
  loaded_image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (loaded_image)
    loaded_image->image_base = kernel_addr;
  else
    grub_dprintf ("linux", "Loaded Image base address could not be set\n");

  grub_dprintf ("linux", "kernel_addr: %p handover_offset: %p params: %p\n",
		kernel_addr, (void *)(grub_efi_uintn_t)handover_offset, kernel_params);
  hf = (handover_func)((char *)kernel_addr + handover_offset + offset);
  grub_dprintf ("linux", "handover_func() = %p\n", hf);
  hf (grub_efi_image_handle, grub_efi_system_table, kernel_params);

  return GRUB_ERR_BUG;
}

#pragma GCC diagnostic pop
