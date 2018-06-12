/* grub-set-bootflag.c - tool to set boot-flags in the grubenv. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2018 Free Software Foundation, Inc.
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

/*
 * NOTE this gets run by users as root (through pkexec), so this does not
 * use any grub library / util functions to allow for easy auditing.
 * The grub headers are only included to get certain defines.
 */

#include <config-util.h>     /* For *_DIR_NAME defines */
#include <grub/types.h>
#include <grub/lib/envblk.h> /* For GRUB_ENVBLK_DEFCFG define */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define GRUBENV "/" GRUB_BOOT_DIR_NAME "/" GRUB_DIR_NAME "/" GRUB_ENVBLK_DEFCFG
#define GRUBENV_SIZE 1024

const char *bootflags[] = {
  "boot_success",
  "menu_show_once",
  NULL
};

static void usage(void)
{
  int i;

  fprintf (stderr, "Usage: 'grub-set-bootflag <bootflag>', where <bootflag> is one of:\n");
  for (i = 0; bootflags[i]; i++)
    fprintf (stderr, "  %s\n", bootflags[i]);
}

int main(int argc, char *argv[])
{
  /* NOTE buf must be at least the longest bootflag length + 4 bytes */
  char env[GRUBENV_SIZE + 1], buf[64], *s;
  const char *bootflag;
  int i, len, ret;
  FILE *f;

  if (argc != 2)
    {
      usage();
      return 1;
    }

  for (i = 0; bootflags[i]; i++)
    if (!strcmp (argv[1], bootflags[i]))
      break;
  if (!bootflags[i])
    {
      fprintf (stderr, "Invalid bootflag: '%s'\n", argv[1]);
      usage();
      return 1;
    }

  bootflag = bootflags[i];
  len = strlen (bootflag);

  f = fopen (GRUBENV, "r");
  if (!f)
    {
      perror ("Error opening " GRUBENV " for reading");
      return 1;     
    }

  ret = fread (env, 1, GRUBENV_SIZE, f);
  fclose (f);
  if (ret != GRUBENV_SIZE)
    {
      perror ("Error reading from " GRUBENV);
      return 1;     
    }

  /* 0 terminate env */
  env[GRUBENV_SIZE] = 0;

  if (strncmp (env, GRUB_ENVBLK_SIGNATURE, strlen (GRUB_ENVBLK_SIGNATURE)))
    {
      fprintf (stderr, "Error invalid environment block\n");
      return 1;
    }

  /* Find a pre-existing definition of the bootflag */
  s = strstr (env, bootflag);
  while (s && s[len] != '=')
    s = strstr (s + len, bootflag);

  if (s && ((s[len + 1] != '0' && s[len + 1] != '1') || s[len + 2] != '\n'))
    {
      fprintf (stderr, "Pre-existing bootflag '%s' has unexpected value\n", bootflag);
      return 1;     
    }

  /* No pre-existing bootflag? -> find free space */
  if (!s)
    {
      for (i = 0; i < (len + 3); i++)
        buf[i] = '#';
      buf[i] = 0;
      s = strstr (env, buf);
    }

  if (!s)
    {
      fprintf (stderr, "No space in grubenv to store bootflag '%s'\n", bootflag);
      return 1;     
    }

  /* The grubenv is not 0 terminated, so memcpy the name + '=' , '1', '\n' */
  snprintf(buf, sizeof(buf), "%s=1\n", bootflag);
  memcpy(s, buf, len + 3);

  /* "r+", don't truncate so that the diskspace stays reserved */
  f = fopen (GRUBENV, "r+");
  if (!f)
    {
      perror ("Error opening " GRUBENV " for writing");
      return 1;     
    }

  ret = fwrite (env, 1, GRUBENV_SIZE, f);
  if (ret != GRUBENV_SIZE)
    {
      perror ("Error writing to " GRUBENV);
      return 1;     
    }

  ret = fflush (f);
  if (ret)
    {
      perror ("Error flushing " GRUBENV);
      return 1;     
    }

  fsync (fileno (f));
  fclose (f);

  return 0;
}
