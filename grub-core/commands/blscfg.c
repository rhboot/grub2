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
#include <grub/lib/envblk.h>

GRUB_MOD_LICENSE ("GPLv3+");

#include "loadenv.h"

#define GRUB_BLS_CONFIG_PATH "/loader/entries/"
#ifdef GRUB_MACHINE_EMU
#define GRUB_BOOT_DEVICE "/boot"
#else
#define GRUB_BOOT_DEVICE "($root)"
#endif

#ifdef GRUB_MACHINE_EFI
#define GRUB_LINUX_CMD "linuxefi"
#define GRUB_INITRD_CMD "initrdefi"
#else
#define GRUB_LINUX_CMD "linux"
#define GRUB_INITRD_CMD "initrd"
#endif

enum
  {
    PLATFORM_EFI,
    PLATFORM_EMU,
    PLATFORM_BIOS,
  };

#define grub_free(x) ({grub_dprintf("blscfg", "%s freeing %p\n", __func__, x); grub_free(x); })

struct keyval
{
  const char *key;
  char *val;
};

struct bls_entry
{
  struct keyval **keyvals;
  int nkeyvals;
  char *filename;
};

static struct bls_entry **entries;
static int nentries;

static struct bls_entry *bls_new_entry(void)
{
  struct bls_entry **new_entries;
  struct bls_entry *entry;
  int new_n = nentries + 1;

  new_entries = grub_realloc (entries,  new_n * sizeof (struct bls_entry *));
  if (!new_entries)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY,
		  "couldn't find space for BLS entry list");
      return NULL;
    }

  entries = new_entries;

  entry = grub_malloc (sizeof (*entry));
  if (!entry)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY,
		  "couldn't find space for BLS entry list");
      return NULL;
    }

  grub_memset (entry, 0, sizeof (*entry));
  entries[nentries] = entry;

  nentries = new_n;

  return entry;
}

static int bls_add_keyval(struct bls_entry *entry, char *key, char *val)
{
  char *k, *v;
  struct keyval **kvs, *kv;
  int new_n = entry->nkeyvals + 1;

  kvs = grub_realloc (entry->keyvals, new_n * sizeof (struct keyval *));
  if (!kvs)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       "couldn't find space for BLS entry");
  entry->keyvals = kvs;

  kv = grub_malloc (sizeof (struct keyval));
  if (!kv)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       "couldn't find space for BLS entry");

  k = grub_strdup (key);
  if (!k)
    {
      grub_free (kv);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "couldn't find space for BLS entry");
    }

  v = grub_strdup (val);
  if (!v)
    {
      grub_free (k);
      grub_free (kv);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			 "couldn't find space for BLS entry");
    }

  kv->key = k;
  kv->val = v;

  entry->keyvals[entry->nkeyvals] = kv;
  grub_dprintf("blscfg", "new keyval at %p:%p:%p\n", entry->keyvals[entry->nkeyvals], k, v);
  entry->nkeyvals = new_n;

  return 0;
}

static void bls_free_entry(struct bls_entry *entry)
{
  int i;

  grub_dprintf("blscfg", "%s got here\n", __func__);
  for (i = 0; i < entry->nkeyvals; i++)
    {
      struct keyval *kv = entry->keyvals[i];
      grub_free ((void *)kv->key);
      grub_free (kv->val);
      grub_free (kv);
    }

  grub_free (entry->keyvals);
  grub_memset (entry, 0, sizeof (*entry));
  grub_free (entry->filename);
  grub_free (entry);
}

/* Find they value of the key named by keyname.  If there are allowed to be
 * more than one, pass a pointer to an int set to -1 the first time, and pass
 * the same pointer through each time after, and it'll return them in sorted
 * order as defined in the BLS fragment file */
static char *bls_get_val(struct bls_entry *entry, const char *keyname, int *last)
{
  int idx, start = 0;
  struct keyval *kv = NULL;

  if (last)
    start = *last + 1;

  for (idx = start; idx < entry->nkeyvals; idx++) {
    kv = entry->keyvals[idx];

    if (!grub_strcmp (keyname, kv->key))
      break;
  }

  if (idx == entry->nkeyvals) {
    if (last)
      *last = -1;
    return NULL;
  }

  if (last)
    *last = idx;

  return kv->val;
}

#define goto_return(x) ({ ret = (x); goto finish; })

/* compare alpha and numeric segments of two versions */
/* return 1: a is newer than b */
/*        0: a and b are the same version */
/*       -1: b is newer than a */
static int vercmp(const char * a, const char * b)
{
    char oldch1, oldch2;
    char *abuf, *bbuf;
    char *str1, *str2;
    char * one, * two;
    int rc;
    int isnum;
    int ret = 0;

  grub_dprintf("blscfg", "%s got here\n", __func__);
    if (!grub_strcmp(a, b))
	    return 0;

    abuf = grub_malloc(grub_strlen(a) + 1);
    bbuf = grub_malloc(grub_strlen(b) + 1);
    str1 = abuf;
    str2 = bbuf;
    grub_strcpy(str1, a);
    grub_strcpy(str2, b);

    one = str1;
    two = str2;

    /* loop through each version segment of str1 and str2 and compare them */
    while (*one || *two) {
	while (*one && !grub_isalnum(*one) && *one != '~') one++;
	while (*two && !grub_isalnum(*two) && *two != '~') two++;

	/* handle the tilde separator, it sorts before everything else */
	if (*one == '~' || *two == '~') {
	    if (*one != '~') goto_return (1);
	    if (*two != '~') goto_return (-1);
	    one++;
	    two++;
	    continue;
	}

	/* If we ran to the end of either, we are finished with the loop */
	if (!(*one && *two)) break;

	str1 = one;
	str2 = two;

	/* grab first completely alpha or completely numeric segment */
	/* leave one and two pointing to the start of the alpha or numeric */
	/* segment and walk str1 and str2 to end of segment */
	if (grub_isdigit(*str1)) {
	    while (*str1 && grub_isdigit(*str1)) str1++;
	    while (*str2 && grub_isdigit(*str2)) str2++;
	    isnum = 1;
	} else {
	    while (*str1 && grub_isalpha(*str1)) str1++;
	    while (*str2 && grub_isalpha(*str2)) str2++;
	    isnum = 0;
	}

	/* save character at the end of the alpha or numeric segment */
	/* so that they can be restored after the comparison */
	oldch1 = *str1;
	*str1 = '\0';
	oldch2 = *str2;
	*str2 = '\0';

	/* this cannot happen, as we previously tested to make sure that */
	/* the first string has a non-null segment */
	if (one == str1) goto_return(-1);	/* arbitrary */

	/* take care of the case where the two version segments are */
	/* different types: one numeric, the other alpha (i.e. empty) */
	/* numeric segments are always newer than alpha segments */
	/* XXX See patch #60884 (and details) from bugzilla #50977. */
	if (two == str2) goto_return (isnum ? 1 : -1);

	if (isnum) {
	    grub_size_t onelen, twolen;
	    /* this used to be done by converting the digit segments */
	    /* to ints using atoi() - it's changed because long  */
	    /* digit segments can overflow an int - this should fix that. */

	    /* throw away any leading zeros - it's a number, right? */
	    while (*one == '0') one++;
	    while (*two == '0') two++;

	    /* whichever number has more digits wins */
	    onelen = grub_strlen(one);
	    twolen = grub_strlen(two);
	    if (onelen > twolen) goto_return (1);
	    if (twolen > onelen) goto_return (-1);
	}

	/* grub_strcmp will return which one is greater - even if the two */
	/* segments are alpha or if they are numeric.  don't return  */
	/* if they are equal because there might be more segments to */
	/* compare */
	rc = grub_strcmp(one, two);
	if (rc) goto_return (rc < 1 ? -1 : 1);

	/* restore character that was replaced by null above */
	*str1 = oldch1;
	one = str1;
	*str2 = oldch2;
	two = str2;
    }

    /* this catches the case where all numeric and alpha segments have */
    /* compared identically but the segment sepparating characters were */
    /* different */
    if ((!*one) && (!*two)) goto_return (0);

    /* whichever version still has characters left over wins */
    if (!*one) goto_return (-1); else goto_return (1);

finish:
    grub_free (abuf);
    grub_free (bbuf);
    return ret;
}

/* return 1: p0 is newer than p1 */
/*        0: p0 and p1 are the same version */
/*       -1: p1 is newer than p0 */
static int bls_cmp(const void *p0, const void *p1, void *state UNUSED)
{
  struct bls_entry * e0 = *(struct bls_entry **)p0;
  struct bls_entry * e1 = *(struct bls_entry **)p1;
  const char *v0, *v1;
  int r;

  v0 = bls_get_val(e0, "version", NULL);
  v1 = bls_get_val(e1, "version", NULL);

  if (v0 && !v1)
    return -1;
  if (!v0 && v1)
    return 1;

  if ((r = vercmp(v0, v1)) != 0)
    return r;

  return vercmp(e0->filename, e1->filename);
}

struct read_entry_info {
  const char *devid;
  const char *dirname;
};

static int read_entry (
    const char *filename,
    const struct grub_dirhook_info *dirhook_info UNUSED,
    void *data)
{
  grub_size_t n;
  char *p;
  grub_file_t f = NULL;
  grub_off_t sz;
  struct bls_entry *entry;
  struct read_entry_info *info = (struct read_entry_info *)data;

  grub_dprintf ("blscfg", "filename: \"%s\"\n", filename);

  if (filename[0] == '.')
    return 0;

  n = grub_strlen (filename);
  if (n <= 5)
    return 0;

  if (grub_strcmp (filename + n - 5, ".conf") != 0)
    return 0;

  p = grub_xasprintf ("(%s)%s/%s", info->devid, info->dirname, filename);

  f = grub_file_open (p);
  if (!f)
    goto finish;

  sz = grub_file_size (f);
  if (sz == GRUB_FILE_SIZE_UNKNOWN || sz > 1024*1024)
    goto finish;

  entry = bls_new_entry();
  if (!entry)
    goto finish;

  entry->filename = grub_strndup(filename, n - 5);
  if (!entry->filename)
    goto finish;

  entry->filename[n - 5] = '\0';

  for (;;)
    {
      char *buf;
      char *separator;
      int rc;

      buf = grub_file_getline (f);
      if (!buf)
	break;

      while (buf && buf[0] && (buf[0] == ' ' || buf[0] == '\t'))
	buf++;
      if (buf[0] == '#')
	continue;

      separator = grub_strchr (buf, ' ');

      if (!separator)
	separator = grub_strchr (buf, '\t');

      if (!separator || separator[1] == '\0')
	{
	  grub_free (buf);
	  break;
	}

      separator[0] = '\0';

      do {
	separator++;
      } while (*separator == ' ' || *separator == '\t');

      rc = bls_add_keyval (entry, buf, separator);
      grub_free (buf);
      if (rc < 0)
	break;
    }

finish:
  grub_free (p);

  if (f)
    grub_file_close (f);

  return 0;
}

static grub_envblk_t saved_env = NULL;

static int
save_var (const char *name, const char *value, void *whitelist UNUSED)
{
  const char *val = grub_env_get (name);
  grub_dprintf("blscfg", "saving \"%s\"\n", name);

  if (val)
    grub_envblk_set (saved_env, name, value);

  return 0;
}

static int
unset_var (const char *name, const char *value UNUSED, void *whitelist)
{
  grub_dprintf("blscfg", "restoring \"%s\"\n", name);
  if (! whitelist)
    {
      grub_env_unset (name);
      return 0;
    }

  if (test_whitelist_membership (name,
				 (const grub_env_whitelist_t *) whitelist))
    grub_env_unset (name);

  return 0;
}

static char **bls_make_list (struct bls_entry *entry, const char *key, int *num)
{
  int last = -1;
  char *val;

  int nlist = 0;
  char **list = NULL;

  list = grub_malloc (sizeof (char *));
  if (!list)
    return NULL;
  list[0] = NULL;

  while (1)
    {
      char **new;

      val = bls_get_val (entry, key, &last);
      if (!val)
	break;

      new = grub_realloc (list, (nlist + 2) * sizeof (char *));
      if (!new)
	break;

      list = new;
      list[nlist++] = val;
      list[nlist] = NULL;
  }

  if (num)
    *num = nlist;

  return list;
}

static void create_entry (struct bls_entry *entry)
{
  int argc = 0;
  const char **argv = NULL;

  char *title = NULL;
  char *clinux = NULL;
  char *options = NULL;
  char **initrds = NULL;
  char *initrd = NULL;
  char *id = entry->filename;
  char *hotkey = NULL;

  char *users = NULL;
  char **classes = NULL;

  char **args = NULL;

  char *src = NULL;
  int i;

  grub_dprintf("blscfg", "%s got here\n", __func__);
  clinux = bls_get_val (entry, "linux", NULL);
  if (!clinux)
    {
      grub_dprintf ("blscfg", "Skipping file %s with no 'linux' key.\n", entry->filename);
      goto finish;
    }

  title = bls_get_val (entry, "title", NULL);
  options = bls_get_val (entry, "options", NULL);
  initrds = bls_make_list (entry, "initrd", NULL);

  hotkey = bls_get_val (entry, "grub_hotkey", NULL);
  users = bls_get_val (entry, "grub_users", NULL);
  classes = bls_make_list (entry, "grub_class", NULL);
  args = bls_make_list (entry, "grub_arg", &argc);

  argc += 1;
  argv = grub_malloc ((argc + 1) * sizeof (char *));
  argv[0] = title ? title : clinux;
  for (i = 1; i < argc; i++)
    argv[i] = args[i-1];
  argv[argc] = NULL;

  grub_dprintf ("blscfg", "adding menu entry for \"%s\" with id \"%s\"\n",
		title, id);
  if (initrds)
    {
      int initrd_size = sizeof (GRUB_INITRD_CMD);
      char *tmp;

      for (i = 0; initrds != NULL && initrds[i] != NULL; i++)
	initrd_size += sizeof (" " GRUB_BOOT_DEVICE) \
		       + grub_strlen (initrds[i]) + 1;
      initrd_size += 1;

      initrd = grub_malloc (initrd_size);
      if (!initrd)
	{
	  grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	  goto finish;
	}


      tmp = grub_stpcpy(initrd, GRUB_INITRD_CMD);
      for (i = 0; initrds != NULL && initrds[i] != NULL; i++)
	{
	  grub_dprintf ("blscfg", "adding initrd %s\n", initrds[i]);
	  tmp = grub_stpcpy (tmp, " " GRUB_BOOT_DEVICE);
	  tmp = grub_stpcpy (tmp, initrds[i]);
	}
      tmp = grub_stpcpy (tmp, "\n");
    }

  src = grub_xasprintf ("load_video\n"
			"set gfx_payload=keep\n"
			"insmod gzio\n"
			GRUB_LINUX_CMD " %s%s%s%s\n"
			"%s",
			GRUB_BOOT_DEVICE, clinux, options ? " " : "", options ? options : "",
			initrd ? initrd : "");

  grub_normal_add_menu_entry (argc, argv, classes, id, users, hotkey, NULL, src, 0);

finish:
  grub_free (initrd);
  grub_free (initrds);
  grub_free (classes);
  grub_free (args);
  grub_free (argv);
  grub_free (src);
}

struct find_entry_info {
	grub_device_t dev;
	grub_fs_t fs;
	int platform;
};

/*
 * filename: if the directory is /EFI/something/ , filename is "something"
 * info: unused
 * data: the filesystem object the file is on.
 */
static int find_entry (const char *filename,
		       const struct grub_dirhook_info *dirhook_info UNUSED,
		       void *data)
{
  struct find_entry_info *info = (struct find_entry_info *)data;
  struct read_entry_info read_entry_info;
  grub_file_t f = NULL;
  char *grubenv_path = NULL;
  grub_envblk_t env = NULL;
  const char *default_blsdir = NULL;
  grub_fs_t blsdir_fs = NULL;
  grub_device_t blsdir_dev = NULL;
  const char *blsdir = NULL;
  char *saved_env_buf = NULL;
  int r = 0;
  const char *devid = grub_env_get ("boot");

  grub_dprintf("blscfg", "%s got here\n", __func__);
  if (filename && (!grub_strcmp (filename, ".") ||
		   !grub_strcmp (filename, "..")))
    return 0;

  if (info->platform == PLATFORM_EFI && !grub_strcasecmp (filename, "boot"))
    return 0;

  saved_env_buf = grub_malloc (512);

  // set a default blsdir
  if (info->platform == PLATFORM_EMU)
    default_blsdir = GRUB_BOOT_DEVICE GRUB_BLS_CONFIG_PATH;
  else
    default_blsdir = GRUB_BLS_CONFIG_PATH;

  grub_env_set ("blsdir", default_blsdir);
  grub_dprintf ("blscfg", "default_blsdir: \"%s\"\n", default_blsdir);

  /*
   * try to load a grubenv from /EFI/wherever/grubenv
   */
  if (info->platform == PLATFORM_EFI)
    grubenv_path = grub_xasprintf ("(%s)/EFI/%s/grubenv", devid, filename);
  else
    grubenv_path = grub_xasprintf ("(%s)/grub2/grubenv", devid);

  grub_dprintf ("blscfg", "looking for \"%s\"\n", grubenv_path);
  f = grub_file_open (grubenv_path);

  grub_dprintf ("blscfg", "%s it\n", f ? "found" : "did not find");
  grub_free (grubenv_path);
  if (f)
    {
      grub_off_t sz;

      grub_dprintf ("blscfg", "getting size\n");
      sz = grub_file_size (f);
      if (sz == GRUB_FILE_SIZE_UNKNOWN || sz > 1024*1024)
	goto finish;

      grub_dprintf ("blscfg", "reading env\n");
      env = read_envblk_file (f);
      if (!env)
	goto finish;
      grub_dprintf ("blscfg", "read env file\n");

      grub_memset (saved_env_buf, '#', 512);
      grub_memcpy (saved_env_buf, GRUB_ENVBLK_SIGNATURE,
		   sizeof (GRUB_ENVBLK_SIGNATURE));
      grub_dprintf ("blscfg", "saving env\n");
      saved_env = grub_envblk_open (saved_env_buf, 512);
      if (!saved_env)
	goto finish;

      // save everything listed in "env" with values from our existing grub env
      grub_envblk_iterate (env, NULL, save_var);
      // set everything from our loaded grubenv into the real grub env
      grub_envblk_iterate (env, NULL, set_var);
    }
  else
    {
      grub_err_t e;
      grub_dprintf ("blscfg", "no such file\n");
      do
	{
	  e = grub_error_pop();
	} while (e);

    }

  blsdir = grub_env_get ("blsdir");
  if (!blsdir)
    goto finish;

  grub_dprintf ("blscfg", "blsdir: \"%s\"\n", blsdir);
  blsdir = grub_strdup (blsdir);

  if (!blsdir)
    goto finish;

  grub_dprintf ("blscfg", "blsdir: \"%s\"\n", blsdir);
  if (info->platform == PLATFORM_EFI) {
    read_entry_info.devid = grub_env_get ("root");
    if (!read_entry_info.devid)
      goto finish;

    blsdir_dev = grub_device_open (read_entry_info.devid);
    if (!blsdir_dev)
      goto finish;

    blsdir_fs = grub_fs_probe (blsdir_dev);
    if (!blsdir_fs)
      goto finish;

  } else {
    read_entry_info.devid = devid;
    blsdir_dev = info->dev;
    blsdir_fs = info->fs;
  }
  read_entry_info.dirname = blsdir;

  r = blsdir_fs->dir (blsdir_dev, blsdir, read_entry, &read_entry_info);
  if (r != 0) {
      grub_dprintf ("blscfg", "read_entry returned error\n");
      grub_err_t e;
      do
	{
	  e = grub_error_pop();
	} while (e);
  }

  grub_dprintf ("blscfg", "Sorting %d entries\n", nentries);
  grub_qsort(&entries[0], nentries, sizeof (struct bls_entry *), bls_cmp, NULL);

  grub_dprintf ("blscfg", "%s Creating %d entries from bls\n", __func__, nentries);
  for (r = nentries - 1; r >= 0; r--)
      create_entry(entries[r]);

  for (r = 0; r < nentries; r++)
      bls_free_entry (entries[r]);
finish:
  if (info->platform == PLATFORM_EFI && blsdir_dev)
    grub_device_close (blsdir_dev);

  nentries = 0;

  grub_free (entries);
  entries = NULL;

  grub_free ((char *)blsdir);

  grub_env_unset ("blsdir");

  if (saved_env)
    {
      // remove everything from the real environment that's defined in env
      grub_envblk_iterate (env, NULL, unset_var);

      // re-set the things from our original environment
      grub_envblk_iterate (saved_env, NULL, set_var);
      grub_envblk_close (saved_env);
      saved_env = NULL;
    }
  else if (saved_env_buf)
    {
      // if we have a saved environment, grub_envblk_close() freed this.
      grub_free (saved_env_buf);
    }

  if (env)
    grub_envblk_close (env);

  if (f)
    grub_file_close (f);

  return 0;
}

static grub_err_t
grub_cmd_blscfg (grub_extcmd_context_t ctxt UNUSED,
		     int argc UNUSED,
		     char **args UNUSED)
{
  grub_fs_t fs;
  grub_device_t dev;
  static grub_err_t r;
  const char *devid;
  struct find_entry_info info =
    {
      .dev = NULL,
      .fs = NULL,
      .platform = PLATFORM_BIOS,
    };


  grub_dprintf ("blscfg", "finding boot\n");

#ifdef GRUB_MACHINE_EMU
  devid = "host";
  grub_env_set ("boot", devid);
#else
  devid = grub_env_get ("boot");
  if (!devid)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND,
		       N_("variable `%s' isn't set"), "boot");
#endif

  grub_dprintf ("blscfg", "opening %s\n", devid);
  dev = grub_device_open (devid);
  if (!dev)
    return grub_errno;

  grub_dprintf ("blscfg", "probing fs\n");
  fs = grub_fs_probe (dev);
  if (!fs)
    {
      r = grub_errno;
      goto finish;
    }

  info.dev = dev;
  info.fs = fs;
#ifdef GRUB_MACHINE_EFI
  info.platform = PLATFORM_EFI;
  grub_dprintf ("blscfg", "scanning /EFI/\n");
  r = fs->dir (dev, "/EFI/", find_entry, &info);
#elif GRUB_MACHINE_EMU
  info.platform = PLATFORM_EMU;
  grub_dprintf ("blscfg", "scanning %s%s\n", GRUB_BOOT_DEVICE,
		GRUB_BLS_CONFIG_PATH);
  find_entry(NULL, NULL, &info);
#else
  grub_dprintf ("blscfg", "scanning %s\n", GRUB_BLS_CONFIG_PATH);
  find_entry(NULL, NULL, &info);
#endif

finish:
  if (dev)
    grub_device_close (dev);

  return r;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(blscfg)
{
  grub_dprintf("blscfg", "%s got here\n", __func__);
  cmd = grub_register_extcmd ("blscfg",
			      grub_cmd_blscfg,
			      0,
			      NULL,
			      N_("Import Boot Loader Specification snippets."),
			      NULL);
}

GRUB_MOD_FINI(blscfg)
{
  grub_unregister_extcmd (cmd);
}
