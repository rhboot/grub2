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
#include <grub/efi/debug.h>
#include <grub/efi/disk.h>
#include <grub/efi/sb.h>
#include <grub/lockdown.h>
#include <grub/term.h>
#include <grub/misc.h>
#include <grub/env.h>
#include <grub/mm.h>
#include <grub/kernel.h>
#include <grub/stack_protector.h>

#ifdef GRUB_STACK_PROTECTOR

static grub_efi_char16_t stack_chk_fail_msg[] =
  L"* GRUB: STACK SMASHING DETECTED!!! *\r\n"
  L"* GRUB: ABORTED!!! *\r\n"
  L"* GRUB: REBOOTING IN 5 SECONDS... *\r\n";

static grub_guid_t rng_protocol_guid = GRUB_EFI_RNG_PROTOCOL_GUID;

/*
 * Don't put this on grub_efi_init()'s local stack to avoid it
 * getting a stack check.
 */
static grub_efi_uint8_t stack_chk_guard_buf[32];

/* Initialize canary in case there is no RNG protocol. */
grub_addr_t __stack_chk_guard = (grub_addr_t) GRUB_STACK_PROTECTOR_INIT;

void __attribute__ ((noreturn))
__stack_chk_fail (void)
{
  grub_efi_simple_text_output_interface_t *o;

  /*
   * Use ConOut here rather than StdErr. StdErr only goes to
   * the serial console, at least on EDK2.
   */
  o = grub_efi_system_table->con_out;
  o->output_string (o, stack_chk_fail_msg);

  grub_efi_system_table->boot_services->stall (5000000);
  grub_efi_system_table->runtime_services->reset_system (GRUB_EFI_RESET_SHUTDOWN,
							 GRUB_EFI_ABORTED, 0, NULL);

  /*
   * We shouldn't get here. It's unsafe to return because the stack
   * is compromised and this function is noreturn, so just busy
   * loop forever.
   */
  do
    {
      /* Do not optimize out the loop. */
      asm volatile ("");
    }
  while (1);
}

static void
stack_protector_init (void)
{
  grub_efi_rng_protocol_t *rng;

  /* Set up the stack canary. Make errors here non-fatal for now. */
  rng = grub_efi_locate_protocol (&rng_protocol_guid, NULL);
  if (rng != NULL)
    {
      grub_efi_status_t status;

      status = rng->get_rng (rng, NULL, sizeof (stack_chk_guard_buf),
			     stack_chk_guard_buf);
      if (status == GRUB_EFI_SUCCESS)
	grub_memcpy (&__stack_chk_guard, stack_chk_guard_buf, sizeof (__stack_chk_guard));
    }
}
#else
static void
stack_protector_init (void)
{
}
#endif

grub_addr_t grub_modbase;

__attribute__ ((__optimize__ ("-fno-stack-protector"))) void
grub_efi_init (void)
{
  grub_modbase = grub_efi_section_addr ("mods");
  /* First of all, initialize the console so that GRUB can display
     messages.  */
  grub_console_init ();

  stack_protector_init ();

  /* Initialize the memory management system.  */
  grub_efi_mm_init ();

  /*
   * Lockdown the GRUB and register the shim_lock verifier
   * if the UEFI Secure Boot is enabled.
   */
  if (grub_efi_get_secureboot () == GRUB_EFI_SECUREBOOT_MODE_ENABLED)
    {
      grub_lockdown ();
      grub_shim_lock_verifier_setup ();
    }

  grub_efi_system_table->boot_services->set_watchdog_timer (0, 0, 0, NULL);

  grub_efidisk_init ();

  grub_efi_register_debug_commands ();
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
}
