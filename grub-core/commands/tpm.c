/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2018  Free Software Foundation, Inc.
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
 *  Core TPM support code.
 */

#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/term.h>
#include <grub/verify.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_tpm_verify_init (grub_file_t io,
		      enum grub_file_type type __attribute__ ((unused)),
		      void **context, enum grub_verify_flags *flags)
{
  *context = io->name;
  *flags |= GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm_verify_write (void *context, void *buf, grub_size_t size)
{
  grub_err_t status = grub_tpm_measure (buf, size, GRUB_BINARY_PCR, context);

  if (status == GRUB_ERR_NONE)
    return GRUB_ERR_NONE;

  grub_dprintf ("tpm", "Measuring buffer failed: %d\n", status);
  return grub_is_tpm_fail_fatal () ? status : GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm_verify_string (char *str, enum grub_verify_string_type type)
{
  const char *prefix = NULL;
  char *description;
  grub_err_t status;

  switch (type)
    {
    case GRUB_VERIFY_KERNEL_CMDLINE:
      prefix = "kernel_cmdline: ";
      break;
    case GRUB_VERIFY_MODULE_CMDLINE:
      prefix = "module_cmdline: ";
      break;
    case GRUB_VERIFY_COMMAND:
      prefix = "grub_cmd: ";
      break;
    }
  description = grub_malloc (grub_strlen (str) + grub_strlen (prefix) + 1);
  if (!description)
    return grub_errno;
  grub_memcpy (description, prefix, grub_strlen (prefix));
  grub_memcpy (description + grub_strlen (prefix), str,
	       grub_strlen (str) + 1);
  status =
    grub_tpm_measure ((unsigned char *) str, grub_strlen (str),
		      GRUB_STRING_PCR, description);
  grub_free (description);
  if (status == GRUB_ERR_NONE)
    return GRUB_ERR_NONE;

  grub_dprintf ("tpm", "Measuring string %s failed: %d\n", str, status);
  return grub_is_tpm_fail_fatal () ? status : GRUB_ERR_NONE;
}

struct grub_file_verifier grub_tpm_verifier = {
  .name = "tpm",
  .init = grub_tpm_verify_init,
  .write = grub_tpm_verify_write,
  .verify_string = grub_tpm_verify_string,
};

GRUB_MOD_INIT (tpm)
{
  /*
   * Even though this now calls ibmvtpm's grub_tpm_present() from GRUB_MOD_INIT(),
   * it does seem to call it late enough in the initialization sequence so
   * that whatever discovered "device nodes" before this GRUB_MOD_INIT() is
   * called, enables the ibmvtpm driver to see the device nodes.
   */
  if (!grub_tpm_present())
    return;
  grub_verifier_register (&grub_tpm_verifier);
}

GRUB_MOD_FINI (tpm)
{
  if (!grub_tpm_present())
    return;
  grub_verifier_unregister (&grub_tpm_verifier);
}
