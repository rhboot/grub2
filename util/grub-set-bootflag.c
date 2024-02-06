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
 * NOTE this gets run by users as root (its suid root), so this does not
 * use any grub library / util functions to allow for easy auditing.
 * The grub headers are only included to get certain defines.
 */

#include <config-util.h>     /* For *_DIR_NAME defines */
#include <grub/types.h>
#include <grub/lib/envblk.h> /* For GRUB_ENVBLK_DEFCFG define */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/resource.h>

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
  char env[GRUBENV_SIZE + 1 + 2], buf[64], *s;
  /* +1 for 0 termination, +11 for ".%u" in tmp filename */
  char env_filename[PATH_MAX + 1], tmp_filename[PATH_MAX + 11 + 1];
  const char *bootflag;
  int i, fd, len, ret;
  FILE *f;

  umask(077);

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

  /*
   * Exit calmly when not installed SUID root and invoked by non-root.  This
   * allows installing user/grub-boot-success.service unconditionally while
   * supporting non-SUID installation of the program for some limited usage.
   */
  if (geteuid())
    {
      printf ("grub-set-bootflag not running as root, no action taken\n");
      return 0;
    }

  /*
   * setegid avoids the new grubenv's gid being that of the user.
   */
  if (setegid(0))
    {
      perror ("setegid(0) failed");
      return 1;
    }

  /* Canonicalize GRUBENV filename, resolving symlinks, etc. */
  if (!realpath(GRUBENV, env_filename))
    {
      perror ("Error canonicalizing " GRUBENV " filename");
      return 1;
    }

  f = fopen (env_filename, "r");
  if (!f)
    {
      perror ("Error opening " GRUBENV " for reading");
      return 1;     
    }

  ret = fread (env, 1, GRUBENV_SIZE, f);
  fclose (f);
  if (ret != GRUBENV_SIZE)
    {
      errno = EINVAL;
      perror ("Error reading from " GRUBENV);
      return 1;     
    }

  /* 0 terminate env */
  env[GRUBENV_SIZE] = 0;
  /* not a valid flag value */
  env[GRUBENV_SIZE + 1] = 0;
  env[GRUBENV_SIZE + 2] = 0;

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
  if (!memcmp(s, buf, len + 3))
    return 0; /* nothing to do */
  memcpy(s, buf, len + 3);

  struct rlimit rlim;
  if (getrlimit(RLIMIT_FSIZE, &rlim) || rlim.rlim_cur < GRUBENV_SIZE || rlim.rlim_max < GRUBENV_SIZE)
    {
      fprintf (stderr, "Resource limits undetermined or too low\n");
      return 1;
    }

  /*
   * Here we work under the premise that we shouldn't write into the target
   * file directly because we might not be able to have all of our changes
   * written completely and atomically.  That was CVE-2019-14865, known to
   * have been triggerable via RLIMIT_FSIZE.  While we've dealt with that
   * specific attack via the check above, there may be other possibilities.
   */

  /*
   * Create a tempfile for writing the new env.  Use the canonicalized filename
   * for the template so that the tmpfile is in the same dir / on same fs.
   *
   * We now use per-user fixed temporary filenames, so that a user cannot cause
   * multiple files to accumulate.
   *
   * We don't use O_EXCL so that a stale temporary file doesn't prevent further
   * usage of the program by the user.
   */
  snprintf(tmp_filename, sizeof(tmp_filename), "%s.%u", env_filename, getuid());
  fd = open(tmp_filename, O_CREAT | O_WRONLY, 0600);
  if (fd == -1)
    {
      perror ("Creating tmpfile failed");
      return 1;
    }

  /*
   * The lock prevents the same user from reaching further steps ending in
   * rename() concurrently, in which case the temporary file only partially
   * written by one invocation could be renamed to the target file by another.
   *
   * The lock also guards the slow fsync() from concurrent calls.  After the
   * first time that and the rename() complete, further invocations for the
   * same flag become no-ops.
   *
   * We lock the temporary file rather than the target file because locking the
   * latter would allow any user having SIGSTOP'ed their process to make all
   * other users' invocations fail (or lock up if we'd use blocking mode).
   *
   * We use non-blocking mode (LOCK_NB) because the lock having been taken by
   * another process implies that the other process would normally have already
   * renamed the file to target by the time it releases the lock (and we could
   * acquire it), so we'd be working directly on the target if we proceeded,
   * which is undesirable, and we'd kind of fail on the already-done rename.
   */
  if (flock(fd, LOCK_EX | LOCK_NB))
    {
      perror ("Locking tmpfile failed");
      return 1;
    }

  /*
   * Deal with the potential that another invocation proceeded all the way to
   * rename() and process exit while we were between open() and flock().
   */
  {
    struct stat st1, st2;
    if (fstat(fd, &st1) || stat(tmp_filename, &st2))
      {
        perror ("stat of tmpfile failed");
        return 1;
      }
    if (st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino)
      {
        fprintf (stderr, "Another invocation won race\n");
        return 1;
      }
  }

  f = fdopen (fd, "w");
  if (!f)
    {
      perror ("Error fdopen of tmpfile failed");
      unlink(tmp_filename);
      return 1;     
    }

  ret = fwrite (env, 1, GRUBENV_SIZE, f);
  if (ret != GRUBENV_SIZE)
    {
      perror ("Error writing tmpfile");
      unlink(tmp_filename);
      return 1;     
    }

  ret = fflush (f);
  if (ret)
    {
      perror ("Error flushing tmpfile");
      unlink(tmp_filename);
      return 1;     
    }

  ret = ftruncate (fileno (f), GRUBENV_SIZE);
  if (ret)
    {
      perror ("Error truncating tmpfile");
      unlink(tmp_filename);
      return 1;
    }

  ret = fsync (fileno (f));
  if (ret)
    {
      perror ("Error syncing tmpfile");
      unlink(tmp_filename);
      return 1;
    }

  /*
   * We must not close the file before rename() as that would remove the lock.
   *
   * And finally rename the tmpfile with the new env over the old env, the
   * linux kernel guarantees that this is atomic (from a syscall pov).
   */
  ret = rename(tmp_filename, env_filename);
  if (ret)
    {
      perror ("Error renaming tmpfile to " GRUBENV " failed");
      unlink(tmp_filename);
      return 1;
    }

  return 0;
}
