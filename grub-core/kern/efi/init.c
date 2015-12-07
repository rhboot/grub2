/* init.c - generic EFI initialization and finalization */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007  Free Software Foundation, Inc.
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

#include <grub/efi/efi.h>
#include <grub/efi/console.h>
#include <grub/efi/disk.h>
#include <grub/term.h>
#include <grub/misc.h>
#include <grub/env.h>
#include <grub/mm.h>
#include <grub/kernel.h>
#include <grub/lib/envblk.h>

grub_addr_t grub_modbase;

#define GRUB_EFI_GRUB_VARIABLE_GUID \
  { 0x91376aff, 0xcba6, 0x42be, \
    { 0x94, 0x9d, 0x06, 0xfd, 0xe8, 0x11, 0x28, 0xe8 } \
  }

/* Helper for grub_efi_env_init */
static int
set_var (const char *name, const char *value,
	 void *whitelist __attribute__((__unused__)))
{
  grub_env_set (name, value);
  return 0;
}

static void
grub_efi_env_init (void)
{
  grub_efi_guid_t efi_grub_guid = GRUB_EFI_GRUB_VARIABLE_GUID;
  struct grub_envblk envblk_s = { NULL, 0 };
  grub_envblk_t envblk = &envblk_s;

  envblk_s.buf = grub_efi_get_variable ("GRUB_ENV", &efi_grub_guid,
					&envblk_s.size);
  if (!envblk_s.buf || envblk_s.size < 1)
    return;

  grub_envblk_iterate (envblk, NULL, set_var);
  grub_free (envblk_s.buf);
}

void
grub_efi_init (void)
{
  grub_modbase = grub_efi_modules_addr ();
  /* First of all, initialize the console so that GRUB can display
     messages.  */
  grub_console_init ();

  /* Initialize the memory management system.  */
  grub_efi_mm_init ();

  efi_call_4 (grub_efi_system_table->boot_services->set_watchdog_timer,
	      0, 0, 0, NULL);

  grub_efi_env_init ();
  grub_efidisk_init ();
}

void (*grub_efi_net_config) (grub_efi_handle_t hnd,
			     char **device,
			     char **path);

void
grub_machine_get_bootlocation (char **device, char **path)
{
  grub_efi_loaded_image_t *image = NULL;
  char *p;

  image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (!image)
    return;
  *device = grub_efidisk_get_device_name (image->device_handle);
  if (!*device && grub_efi_net_config)
    {
      grub_efi_net_config (image->device_handle, device, path);
      return;
    }

  *path = grub_efi_get_filename (image->file_path);
  if (*path)
    {
      /* Get the directory.  */
      p = grub_strrchr (*path, '/');
      if (p)
        *p = '\0';
    }
}

void
grub_efi_fini (void)
{
  grub_efidisk_fini ();
  grub_console_fini ();
  grub_efi_memory_fini ();
}
