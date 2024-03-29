/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2006,2007,2008,2009,2010,2011,2012,2013  Free Software Foundation, Inc.
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

#include <config-util.h>
#include <config.h>

#include <grub/emu/hostdisk.h>
#include <grub/emu/exec.h>
#include <grub/emu/config.h>
#include <grub/util/install.h>
#include <grub/util/misc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>

const char *
grub_util_get_config_filename (void)
{
  static char *value = NULL;
  if (!value)
    value = grub_util_path_concat (3, GRUB_SYSCONFDIR,
				   "default", "grub");
  return value;
}

const char *
grub_util_get_pkgdatadir (void)
{
  const char *ret = getenv ("pkgdatadir");
  if (ret)
    return ret;
  return GRUB_DATADIR "/" PACKAGE;
}

const char *
grub_util_get_pkglibdir (void)
{
  return GRUB_LIBDIR "/" PACKAGE;
}

const char *
grub_util_get_localedir (void)
{
  return LOCALEDIR;
}

void
grub_util_load_config (struct grub_util_config *cfg)
{
  pid_t pid;
  const char *argv[4];
  char *script, *ptr;
  const char *cfgfile, *iptr;
  FILE *f = NULL;
  int fd;
  const char *v;

  memset (cfg, 0, sizeof (*cfg));

  v = getenv ("GRUB_ENABLE_CRYPTODISK");
  if (v && v[0] == 'y' && v[1] == '\0')
    cfg->is_cryptodisk_enabled = 1;

  v = getenv ("GRUB_DISTRIBUTOR");
  if (v)
    cfg->grub_distributor = xstrdup (v);

  v = getenv ("SUSE_BTRFS_SNAPSHOT_BOOTING");
  if (v)
    {
      if (grub_strncmp(v, "true", sizeof ("true") - 1) == 0)
        {
          cfg->is_suse_btrfs_snapshot_enabled = 1;
        }
      else
        {
          cfg->is_suse_btrfs_snapshot_enabled = 0;
        }
    }

  cfgfile = grub_util_get_config_filename ();
  if (!grub_util_is_regular (cfgfile))
    return;

  argv[0] = "sh";
  argv[1] = "-c";

  script = xcalloc (4, strlen (cfgfile) + 300);

  ptr = script;
  memcpy (ptr, ". '", 3);
  ptr += 3;
  for (iptr = cfgfile; *iptr; iptr++)
    {
      if (*iptr == '\\')
	{
	  memcpy (ptr, "'\\''", 4);
	  ptr += 4;
	  continue;
	}
      *ptr++ = *iptr;
    }

  strcpy (ptr, "'; printf \"GRUB_ENABLE_CRYPTODISK=%s\\nGRUB_DISTRIBUTOR=%s\\nSUSE_BTRFS_SNAPSHOT_BOOTING=%s\\n\" "
	  "\"$GRUB_ENABLE_CRYPTODISK\" \"$GRUB_DISTRIBUTOR\" \"$SUSE_BTRFS_SNAPSHOT_BOOTING\"");

  argv[2] = script;
  argv[3] = '\0';

  pid = grub_util_exec_pipe (argv, &fd);
  if (pid)
    f = fdopen (fd, "r");
  if (f)
    {
      grub_util_parse_config (f, cfg, 1);
      fclose (f);
    }
  if (pid)
    {
      close (fd);
      waitpid (pid, NULL, 0);
    }
  if (f)
    return;

  f = grub_util_fopen (cfgfile, "r");
  if (f)
    {
      grub_util_parse_config (f, cfg, 0);
      fclose (f);
    }
  else
    grub_util_warn (_("cannot open configuration file `%s': %s"),
		    cfgfile, strerror (errno));
}
