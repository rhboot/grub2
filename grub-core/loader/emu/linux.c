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
#include <grub/loader.h>
#include <grub/dl.h>
#include <grub/command.h>
#include <grub/time.h>

#include <grub/emu/exec.h>
#include <grub/emu/hostfile.h>
#include <grub/emu/misc.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;

static char *kernel_path;
static char *initrd_path;
static char *boot_cmdline;

static grub_err_t
grub_switch_root (void)
{
  char *tmp = NULL;
  char *options_cmd = NULL;
  char *options = NULL;
  char *subvol = NULL;
  char *root_uuid = NULL;
  char *kernel_release = NULL;
  grub_err_t rc = GRUB_ERR_NONE;
  const char *subvol_param = "subvol=";
  const char *kernel_release_prefix = "/boot/vmlinuz-";
  const char *root_prefix = "root=";
  const char *systemctl[] = {"systemctl", "--force", "switch-root", "/sysroot", NULL};
  const char *mountrootfs[] = {"mount", root_uuid, "/sysroot", options_cmd, options, NULL};
  const char *unamer[] = {"uname", "-r", NULL};
  char *uname_buf = NULL;
  int i = 0;

  /* Extract the kernel release tag from kernel_path */
  if (!kernel_path)
    {
      rc = GRUB_ERR_BAD_ARGUMENT;
      grub_dprintf ("linux", "switch_root: No kernel_path found\n");
      goto out;
    }

  if ((kernel_release = grub_xasprintf ("%s", (kernel_path + grub_strlen (kernel_release_prefix)))) == NULL)
    {
      grub_dprintf ("linux", "switch_root: Failed to allocate memory\n");
      rc = GRUB_ERR_BAD_ARGUMENT;
      goto out;
    }


  /* Check for kernel mismatch  */
  /* Retrieve the current kernel relase tag */
  grub_util_exec_redirect (unamer, NULL, "/tmp/version");

  grub_file_t f = grub_file_open ("/tmp/version", GRUB_FILE_TYPE_FS_SEARCH);

  if (f == NULL)
    {
      grub_dprintf ("linux", "failed opening file.\n");
      rc = GRUB_ERR_FILE_NOT_FOUND;
      goto out;
    }

  if ((uname_buf = grub_malloc (f->size)) == NULL)
    {
      grub_dprintf ("linux", "switch_root: Failed to allocate memory\n");
      rc = GRUB_ERR_OUT_OF_MEMORY;
      goto out;
    }

  if (grub_file_read (f, uname_buf, f->size) < 0)
    {
      grub_dprintf ("linux", "switch_root: failed to read from file\n");
      rc = GRUB_ERR_FILE_READ_ERROR;
      goto out;
    }

  grub_file_close (f);

  if (grub_strstr (uname_buf, kernel_release) == NULL)
    {
      grub_dprintf ("linux", "switch_root: kernel mismatch, not performing switch-root ...\n");
      rc = GRUB_ERR_NO_KERNEL;
      goto out;
    }

  /* Extract the root partition from boot_cmdline */
  if (!boot_cmdline)
    {
      rc = GRUB_ERR_BAD_ARGUMENT;
      goto out;
    }

  tmp = grub_strdup (boot_cmdline);

  if (tmp == NULL)
    {
      rc = GRUB_ERR_OUT_OF_MEMORY;
      goto out;
    }

  if ((root_uuid = grub_strstr (tmp, root_prefix)) == NULL)
    {
      rc = GRUB_ERR_BAD_ARGUMENT;
      grub_dprintf ("linux", "switch_root: Can't find rootfs\n");
      goto out;
    }

  root_uuid += grub_strlen (root_prefix);

  while (root_uuid[i] != ' ' && root_uuid[i] != '\0')
    i++;

  root_uuid[i] = '\0';

  /* Allocate a new buffer holding root_uuid */
  root_uuid = grub_xasprintf ("%s", root_uuid);

  if (root_uuid == NULL)
    {
      grub_dprintf ("linux", "switch_root: Failed to allocated memory\n");
      rc = GRUB_ERR_OUT_OF_MEMORY;
      goto out;
    }

  /* Check for subvol parameter */
  grub_strcpy (tmp, boot_cmdline);

  if ((subvol = grub_strstr(tmp, subvol_param)) != NULL)
    {
      i = 0;

      while (subvol[i] != ' ' && subvol[i] != '\0')
        i++;

      subvol[i] = '\0';

      /* Allocate a new buffer holding subvol */
      subvol = grub_xasprintf("%s", subvol);

      if (subvol == NULL)
        {
          grub_dprintf ("linux", "switch_root: Failed to allocated memory\n");
          rc = GRUB_ERR_OUT_OF_MEMORY;
          goto out;
        }

      options_cmd = grub_xasprintf("%s", "-o");
      options = grub_xasprintf("%s", subvol);
    }

  if (options == NULL)
    {
      mountrootfs[3] = NULL;
    }
  else
    {
      mountrootfs[3] = options_cmd;
      mountrootfs[4] = options;
    }

  mountrootfs[1] = root_uuid;

  grub_dprintf ("linux", "Executing:\n");
  grub_dprintf ("linux", "%s %s %s %s %s\n", mountrootfs[0], mountrootfs[1],
    mountrootfs[2], mountrootfs[3], mountrootfs[4]);

  /* Mount the rootfs */
  rc = grub_util_exec (mountrootfs);

  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("linux", "switch_root: Failed.\n");
      rc = GRUB_ERR_INVALID_COMMAND;
      goto out;
    }

  grub_dprintf ("linux", "Done.\n");

  grub_dprintf ("linux", "%s %s %s %s\n", systemctl[0], systemctl[1],
    systemctl[2], systemctl[3]);

  /* Switch root */
  rc = grub_util_exec (systemctl);

  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("linux", "switch_root: Failed.\n");
      rc = GRUB_ERR_INVALID_COMMAND;
      goto out;
    }

  grub_dprintf ("linux", "Done.\n");

out:
  grub_free (tmp);
  grub_free (options_cmd);
  grub_free (options);
  grub_free (subvol);
  grub_free (root_uuid);
  grub_free (uname_buf);
  grub_free (kernel_release);
  return rc;
}

static grub_err_t
grub_linux_boot (void)
{
  grub_err_t rc = GRUB_ERR_NONE;
  char *initrd_param;
  const char *kexec[] = {"kexec", "-la", kernel_path, boot_cmdline, NULL, NULL};
  const char *systemctl[] = {"systemctl", "kexec", NULL};
  int kexecute = grub_util_get_kexecute ();

  if (initrd_path)
    {
      initrd_param = grub_xasprintf ("--initrd=%s", initrd_path);
      kexec[3] = initrd_param;
      kexec[4] = boot_cmdline;
    }
  else
    initrd_param = grub_xasprintf ("%s", "");

  if (grub_util_get_switch_root() == 1)
    {
      rc = grub_switch_root();
      if (rc != GRUB_ERR_NONE)
        grub_fatal (N_("Failed to execute switch_root\n"));
    }
  else if (kexecute)
    {
      grub_dprintf ("linux", "%serforming 'kexec -la %s %s %s'\n",
                    (kexecute) ? "P" : "Not p",
                    kernel_path, initrd_param, boot_cmdline);

      rc = grub_util_exec (kexec);
    }

  grub_free (initrd_param);

  if (rc != GRUB_ERR_NONE)
    {
      grub_error (rc, N_("error trying to perform kexec load operation"));
      grub_sleep (3);
      return rc;
    }

  if (kexecute < 1)
    grub_fatal (N_("use '"PACKAGE"-emu --kexec' to force a system restart"));

  grub_dprintf ("linux", "Performing 'systemctl kexec' (%s) ",
		(kexecute==1) ? "do-or-die" : "just-in-case");
  rc = grub_util_exec (systemctl);

  /* `systemctl kexec` is "asynchronous" and will return even on success. */
  if (rc == 0)
    grub_sleep (10);

  if (kexecute == 1)
    grub_fatal (N_("error trying to perform 'systemctl kexec': %d"), rc);

  /*
   * WARNING: forcible reset should only be used in read-only environments.
   * grub-emu cannot check for these - users beware.
   */
  grub_dprintf ("linux", "Performing 'kexec -ex'");
  kexec[1] = "-ex";
  kexec[2] = NULL;
  rc = grub_util_exec (kexec);
  if (rc != GRUB_ERR_NONE)
    grub_fatal (N_("error trying to directly perform 'kexec -ex': %d"), rc);

  return rc;
}

static grub_err_t
grub_linux_unload (void)
{
  /* Unloading: we're no longer in use. */
  grub_dl_unref (my_mod);
  grub_free (boot_cmdline);
  boot_cmdline = NULL;
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)), int argc,
		char *argv[])
{
  int i;
  char *tempstr;

  /* Mark ourselves as in-use. */
  grub_dl_ref (my_mod);

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  if (!grub_util_is_regular (argv[0]))
    return grub_error (GRUB_ERR_FILE_NOT_FOUND,
		       N_("cannot find kernel file %s"), argv[0]);

  grub_free (kernel_path);
  kernel_path = grub_xasprintf ("%s", argv[0]);

  grub_free (boot_cmdline);
  boot_cmdline = NULL;

  if (argc > 1)
    {
      boot_cmdline = grub_xasprintf ("--command-line=%s", argv[1]);
      for (i = 2; i < argc; i++)
        {
          tempstr = grub_xasprintf ("%s %s", boot_cmdline, argv[i]);
          grub_free (boot_cmdline);
          boot_cmdline = tempstr;
        }
    }

  grub_loader_set (grub_linux_boot, grub_linux_unload, 0);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)), int argc,
		 char *argv[])
{
  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  if (!grub_util_is_regular (argv[0]))
    return grub_error (GRUB_ERR_FILE_NOT_FOUND,
		       N_("Cannot find initrd file %s"), argv[0]);

  grub_free (initrd_path);
  initrd_path = grub_xasprintf ("%s", argv[0]);

  /* We are done - mark ourselves as on longer in use. */
  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_linux, cmd_initrd;

GRUB_MOD_INIT (linux)
{
  cmd_linux = grub_register_command ("linux", grub_cmd_linux, 0,
				     N_("Load Linux."));
  cmd_initrd = grub_register_command ("initrd", grub_cmd_initrd, 0,
				      N_("Load initrd."));
  my_mod = mod;
}

GRUB_MOD_FINI (linux)
{
  grub_unregister_command (cmd_linux);
  grub_unregister_command (cmd_initrd);
}
