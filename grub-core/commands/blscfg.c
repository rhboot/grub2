/*-*- Mode: C; c-basic-offset: 2; indent-tabs-mode: t -*-*/

/* bls.c - implementation of the boot loader spec */

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

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/fs.h>
#include <grub/env.h>
#include <grub/file.h>
#include <grub/normal.h>

GRUB_MOD_LICENSE ("GPLv3+");

#ifdef GRUB_MACHINE_EFI
#define GRUB_LINUX_CMD "linuxefi"
#define GRUB_INITRD_CMD "initrdefi"
#define GRUB_BLS_CONFIG_PATH "/EFI/fedora/loader/entries/"
#define GRUB_BOOT_DEVICE "($boot)"
#else
#define GRUB_LINUX_CMD "linux"
#define GRUB_INITRD_CMD "initrd"
#define GRUB_BLS_CONFIG_PATH "/loader/entries/"
#define GRUB_BOOT_DEVICE "($root)"
#endif

static int parse_entry (
    const char *filename,
    const struct grub_dirhook_info *info __attribute__ ((unused)),
    void *data __attribute__ ((unused)))
{
  grub_size_t n;
  char *p;
  grub_file_t f = NULL;
  grub_off_t sz;
  char *title = NULL, *options = NULL, *clinux = NULL, *initrd = NULL, *src = NULL;
  const char *args[2] = { NULL, NULL };

  if (filename[0] == '.')
    return 0;

  n = grub_strlen (filename);
  if (n <= 5)
    return 0;

  if (grub_strcmp (filename + n - 5, ".conf") != 0)
    return 0;

  p = grub_xasprintf (GRUB_BLS_CONFIG_PATH "%s", filename);

  f = grub_file_open (p);
  if (!f)
    goto finish;

  sz = grub_file_size (f);
  if (sz == GRUB_FILE_SIZE_UNKNOWN || sz > 1024*1024)
    goto finish;

  for (;;)
    {
      char *buf;

      buf = grub_file_getline (f);
      if (!buf)
	break;

      if (grub_strncmp (buf, "title ", 6) == 0)
	{
	  grub_free (title);
	  title = grub_strdup (buf + 6);
	  if (!title)
	    goto finish;
	}
      else if (grub_strncmp (buf, "options ", 8) == 0)
	{
	  grub_free (options);
	  options = grub_strdup (buf + 8);
	  if (!options)
	    goto finish;
	}
      else if (grub_strncmp (buf, "linux ", 6) == 0)
	{
	  grub_free (clinux);
	  clinux = grub_strdup (buf + 6);
	  if (!clinux)
	    goto finish;
	}
      else if (grub_strncmp (buf, "initrd ", 7) == 0)
	{
	  grub_free (initrd);
	  initrd = grub_strdup (buf + 7);
	  if (!initrd)
	    goto finish;
	}

      grub_free(buf);
    }

  if (!linux)
    {
      grub_printf ("Skipping file %s with no 'linux' key.", p);
      goto finish;
    }

  args[0] = title ? title : filename;

  src = grub_xasprintf ("load_video\n"
			"set gfx_payload=keep\n"
			"insmod gzio\n"
			GRUB_LINUX_CMD " %s%s%s%s\n"
			"%s%s%s%s",
			GRUB_BOOT_DEVICE, clinux, options ? " " : "", options ? options : "",
			initrd ? GRUB_INITRD_CMD " " : "", initrd ? GRUB_BOOT_DEVICE : "", initrd ? initrd : "", initrd ? "\n" : "");

  grub_normal_add_menu_entry (1, args, NULL, NULL, "bls", NULL, NULL, src, 0);

finish:
  grub_free (p);
  grub_free (title);
  grub_free (options);
  grub_free (clinux);
  grub_free (initrd);
  grub_free (src);

  if (f)
    grub_file_close (f);

  return 0;
}

static grub_err_t
grub_cmd_bls_import (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		     int argc __attribute__ ((unused)),
		     char **args __attribute__ ((unused)))
{
  grub_fs_t fs;
  grub_device_t dev;
  static grub_err_t r;
  const char *devid;

  devid = grub_env_get ("root");
  if (!devid)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("variable `%s' isn't set"), "root");

  dev = grub_device_open (devid);
  if (!dev)
    return grub_errno;

  fs = grub_fs_probe (dev);
  if (!fs)
    {
      r = grub_errno;
      goto finish;
    }

  r = fs->dir (dev, GRUB_BLS_CONFIG_PATH, parse_entry, NULL);

finish:
  if (dev)
    grub_device_close (dev);

  return r;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(bls)
{
  cmd = grub_register_extcmd ("bls_import",
			      grub_cmd_bls_import,
			      0,
			      NULL,
			      N_("Import Boot Loader Specification snippets."),
			      NULL);
}

GRUB_MOD_FINI(bls)
{
  grub_unregister_extcmd (cmd);
}
