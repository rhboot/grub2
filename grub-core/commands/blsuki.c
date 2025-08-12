/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025  Free Software Foundation, Inc.
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

#include <grub/list.h>
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
#include <grub/safemath.h>
#include <grub/lib/envblk.h>
#include <filevercmp.h>

#ifdef GRUB_MACHINE_EMU
#include <grub/emu/misc.h>
#define GRUB_BOOT_DEVICE "/boot"
#else
#define GRUB_BOOT_DEVICE ""
#endif

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_BLS_CONFIG_PATH "/loader/entries/"

#define BLS_EXT_LEN (sizeof (".conf") - 1)

/*
 * It is highly unlikely to ever receive a large amount of keyval pairs. A
 * limit of 10000 is more than enough.
 */
#define BLSUKI_KEYVALS_MAX 10000

static const struct grub_arg_option bls_opt[] =
  {
    {"path", 'p', 0, "Specify path to find BLS entries.", N_("DIR"), ARG_TYPE_PATHNAME},
    {"enable-fallback", 'f', 0, "Fallback to the default BLS path if --path fails to find BLS entries.", 0, ARG_TYPE_NONE},
    {"show-default", 'd', 0, "Allow the default BLS entry to be added to the GRUB menu.", 0, ARG_TYPE_NONE},
    {"show-non-default", 'n', 0, "Allow the non-default BLS entries to be added to the GRUB menu.", 0, ARG_TYPE_NONE},
    {"entry", 'e', 0, "Allow specific BLS entries to be added to the GRUB menu.", N_("FILE"), ARG_TYPE_FILE},
    {0, 0, 0, 0, 0, 0}
  };

struct keyval
{
  const char *key;
  char *val;
};

struct read_entry_info
{
  const char *devid;
  const char *dirname;
  grub_file_t file;
};

struct find_entry_info
{
  const char *dirname;
  const char *devid;
  grub_device_t dev;
  grub_fs_t fs;
};

static grub_blsuki_entry_t *entries;

#define FOR_BLSUKI_ENTRIES(var) FOR_LIST_ELEMENTS (var, entries)

/*
 * BLS appears to make paths relative to the filesystem that snippets are
 * on, not /. Attempt to cope.
 */
static char *blsuki_update_boot_device (char *tmp)
{
#ifdef GRUB_MACHINE_EMU
  static int separate_boot = -1;
  char *ret;

  if (separate_boot != -1)
    goto probed;

  separate_boot = 0;

  ret = grub_make_system_path_relative_to_its_root (GRUB_BOOT_DEVICE);

  if (ret != NULL && ret[0] == '\0')
    separate_boot = 1;

 probed:
  if (separate_boot == 0)
    return tmp;
#endif

  return grub_stpcpy (tmp, GRUB_BOOT_DEVICE);
}

/*
 * This function will add a new keyval pair to a list of keyvals stored in the
 * entry parameter.
 */
static grub_err_t
blsuki_add_keyval (grub_blsuki_entry_t *entry, char *key, char *val)
{
  char *k, *v;
  struct keyval **kvs, *kv;
  grub_size_t size;
  int new_n = entry->nkeyvals + 1;

  if (new_n > BLSUKI_KEYVALS_MAX)
    return grub_error (GRUB_ERR_BAD_NUMBER, "too many keyval pairs");

  if (entry->keyvals_size == 0)
    {
      size = sizeof (struct keyval *);
      kvs = grub_malloc (size);
      if (kvs == NULL)
	return grub_error (GRUB_ERR_OUT_OF_MEMORY, "couldn't allocate space for BLS key values");

      entry->keyvals = kvs;
      entry->keyvals_size = size;
    }
  else if (entry->keyvals_size < new_n * sizeof (struct keyval *))
    {
      size = entry->keyvals_size * 2;
      kvs = grub_realloc (entry->keyvals, size);
      if (kvs == NULL)
	return grub_error (GRUB_ERR_OUT_OF_MEMORY, "couldn't reallocate space for BLS key values");

      entry->keyvals = kvs;
      entry->keyvals_size = size;
    }

  kv = grub_malloc (sizeof (struct keyval));
  if (kv == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "couldn't find space for new BLS key value");

  k = grub_strdup (key);
  if (k == NULL)
    {
      grub_free (kv);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "couldn't find space for new BLS key value");
    }

  v = grub_strdup (val);
  if (v == NULL)
    {
      grub_free (k);
      grub_free (kv);
      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "couldn't find space for new BLS key value");
    }

  kv->key = k;
  kv->val = v;
  entry->keyvals[entry->nkeyvals] = kv;
  entry->nkeyvals = new_n;

  return GRUB_ERR_NONE;
}

/*
 * Find the value of the key named by keyname. If there are allowed to be
 * more than one, pass a pointer set to -1 to the last parameter the first
 * time, and pass the same pointer through each time after, and it'll return
 * them in sorted order as defined in the BLS fragment file.
 */
static char *
blsuki_get_val (grub_blsuki_entry_t *entry, const char *keyname, int *last)
{
  int idx, start = (last != NULL) ? (*last + 1) : 0;
  struct keyval *kv = NULL;
  char *ret = NULL;

  for (idx = start; idx < entry->nkeyvals; idx++)
    {
      kv = entry->keyvals[idx];

      if (grub_strcmp (keyname, kv->key) == 0)
	{
	  ret = kv->val;
	  break;
	}
    }

  if (last != NULL)
    {
      if (idx == entry->nkeyvals)
	*last = -1;
      else
	*last = idx;
    }

  return ret;
}

/*
 * Add a new grub_blsuki_entry_t struct to the entries list and sort it's
 * position on the list.
 */
static grub_err_t
blsuki_add_entry (grub_blsuki_entry_t *entry)
{
  grub_blsuki_entry_t *e, *last = NULL;
  int rc;

  if (entries == NULL)
    {
      grub_dprintf ("blsuki", "Add entry with id \"%s\"\n", entry->filename);
      entries = entry;
      return GRUB_ERR_NONE;
    }

  FOR_BLSUKI_ENTRIES (e)
    {
      rc = filevercmp (entry->filename, e->filename);
      if (rc == 0)
	return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("duplicate file: `%s'"), entry->filename);

      if (rc > 0)
	{
	  grub_dprintf ("blsuki", "Add entry with id \"%s\"\n", entry->filename);
	  grub_list_push (GRUB_AS_LIST_P (&e), GRUB_AS_LIST (entry));
	  if (entry->next == entries)
	    {
	      entries = entry;
	      entry->prev = NULL;
	    }
	  else if (last != NULL)
	    last->next = entry;

	  return GRUB_ERR_NONE;
	}
      last = e;
    }

  if (last != NULL)
    {
      grub_dprintf ("blsuki", "Add entry with id \"%s\"\n", entry->filename);
      last->next = entry;
      entry->prev = &last;
    }

  return GRUB_ERR_NONE;
}

/*
 * This function parses each line of a BLS config file to obtain the key value
 * pairs that will be used to setup the GRUB menu entries. The key value pair
 * will be stored in a list in the entry parameter.
 */
static grub_err_t
bls_parse_keyvals (grub_file_t f, grub_blsuki_entry_t *entry)
{
  grub_err_t err = GRUB_ERR_NONE;

  for (;;)
    {
      char *line, *key, *val;

      line = grub_file_getline (f);
      if (line == NULL)
	break;

      key = grub_strtok_r (line, " \t", &val);
      if (key == NULL)
	{
	  grub_free (line);
	  break;
	}
      if (*key == '#')
	{
	  grub_free (line);
	  continue;
	}

      while (*val == ' ' || *val == '\t')
	val++;

      if (*val == '\0')
	{
	  grub_free (line);
	  break;
	}

      err = blsuki_add_keyval (entry, key, val);
      grub_free (line);
      if (err != GRUB_ERR_NONE)
	break;
    }

  return err;
}

/*
 * If a file hasn't already been opened, this function opens a BLS config file
 * and initializes entry data before parsing keyvals and adding the entry to
 * the list of BLS entries.
 */
static int
blsuki_read_entry (const char *filename,
		   const struct grub_dirhook_info *dirhook_info __attribute__ ((__unused__)),
		   void *data)
{
  grub_size_t path_len = 0, filename_len;
  grub_err_t err;
  char *p = NULL;
  grub_file_t f = NULL;
  grub_blsuki_entry_t *entry;
  struct read_entry_info *info = (struct read_entry_info *) data;

  grub_dprintf ("blsuki", "filename: \"%s\"\n", filename);

  filename_len = grub_strlen (filename);

  if (info->file != NULL)
    f = info->file;
  else
    {
      if (filename_len < BLS_EXT_LEN ||
	  grub_strcmp (filename + filename_len - BLS_EXT_LEN, ".conf") != 0)
	return 0;

      p = grub_xasprintf ("(%s)%s/%s", info->devid, info->dirname, filename);

      f = grub_file_open (p, GRUB_FILE_TYPE_CONFIG);
      grub_free (p);
      if (f == NULL)
	goto finish;
    }

  entry = grub_zalloc (sizeof (*entry));
  if (entry == NULL)
    goto finish;

  /*
   * If a file is opened before this function, the filename may have a path.
   * Since the filename is used for the ID of the GRUB menu entry, we can
   * remove the path.
   */
  if (info->file != NULL)
    {
      char *slash;

      slash = grub_strrchr (filename, '/');
      if (slash != NULL)
	path_len = slash - filename + 1;
    }
  filename_len -= path_len;

  entry->filename = grub_strndup (filename + path_len, filename_len);
  if (entry->filename == NULL)
    {
      grub_free (entry);
      goto finish;
    }

  err = bls_parse_keyvals (f, entry);

  if (err == GRUB_ERR_NONE)
    blsuki_add_entry (entry);
  else
    grub_free (entry);

 finish:
  if (f != NULL)
    grub_file_close (f);

  return 0;
}

/*
 * This function returns a list of values that had the same key in the BLS
 * config file. The number of entries in this list is returned by the len
 * parameter.
 */
static char **
blsuki_make_list (grub_blsuki_entry_t *entry, const char *key, int *len)
{
  int last = -1;
  char *val;
  int nlist = 0;
  char **list;

  list = grub_zalloc (sizeof (char *));
  if (list == NULL)
    return NULL;

  while (1)
    {
      char **new;

      /*
       * Since the same key might appear more than once, the 'last' variable
       * starts at -1 and increments to indicate the last index in the list
       * we obtained from blsuki_get_val().
       */
      val = blsuki_get_val (entry, key, &last);
      if (val == NULL)
	break;

      new = grub_realloc (list, (nlist + 2) * sizeof (char *));
      if (new == NULL)
	break;

      list = new;
      list[nlist++] = val;
      list[nlist] = NULL;
  }

  if (nlist == 0)
    {
      grub_free (list);
      return NULL;
    }

  if (len != NULL)
    *len = nlist;

  return list;
}

/*
 * This function appends a field to the end of a buffer. If the field given is
 * an enviornmental variable, it gets the value stored for that variable and
 * appends that to the buffer instead.
 */
static char *
blsuki_field_append (bool is_env_var, char *buffer, const char *start, const char *end)
{
  char *tmp;
  const char *field;
  grub_size_t size = 0;

  tmp = grub_strndup (start, end - start + 1);
  if (tmp == NULL)
    return NULL;

  field = tmp;

  if (is_env_var == true)
    {
      field = grub_env_get (tmp);
      if (field == NULL)
	return buffer;
    }

  if (grub_add (grub_strlen (field), 1, &size))
    return NULL;

  if (buffer == NULL)
    buffer = grub_zalloc (size);
  else
    {
      if (grub_add (size, grub_strlen (buffer), &size))
	return NULL;

      buffer = grub_realloc (buffer, size);
    }

  if (buffer == NULL)
    return NULL;

  tmp = buffer + grub_strlen (buffer);
  tmp = grub_stpcpy (tmp, field);

  if (is_env_var == true)
    tmp = grub_stpcpy (tmp, " ");

  return buffer;
}

/*
 * This function takes a value string, checks for environmental variables, and
 * returns the value string with all environmental variables replaced with the
 * value stored in the variable.
 */
static char *
blsuki_expand_val (const char *value)
{
  char *buffer = NULL;
  const char *start = value;
  const char *end = value;
  bool is_env_var = false;

  if (value == NULL)
    return NULL;

  while (*value != '\0')
    {
      if (*value == '$')
	{
	  if (start != end)
	    {
	      buffer = blsuki_field_append (is_env_var, buffer, start, end);
	      if (buffer == NULL)
		return NULL;
	    }

	  is_env_var = true;
	  start = value + 1;
	}
      else if (is_env_var == true)
	{
	  if (grub_isalnum (*value) == 0 && *value != '_')
	    {
	      buffer = blsuki_field_append (is_env_var, buffer, start, end);
	      is_env_var = false;
	      start = value;
	      if (*start == ' ')
		start++;
	    }
	}

      end = value;
      value++;
    }

  if (start != end)
    {
      buffer = blsuki_field_append (is_env_var, buffer, start, end);
      if (buffer == NULL)
	return NULL;
    }

  return buffer;
}

/*
 * This function returns a string with the command to load a linux kernel with
 * kernel command-line options based on what was specified in the BLS config
 * file.
 */
static char *
bls_get_linux (grub_blsuki_entry_t *entry)
{
  char *linux_path;
  char *linux_cmd = NULL;
  char *options = NULL;
  char *tmp;
  grub_size_t size;

  linux_path = blsuki_get_val (entry, "linux", NULL);
  options = blsuki_expand_val (blsuki_get_val (entry, "options", NULL));

  if (grub_add (sizeof ("linux " GRUB_BOOT_DEVICE), grub_strlen (linux_path), &size))
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, "overflow detected while calculating linux buffer size");
      goto finish;
    }

  if (options != NULL)
    {
      if (grub_add (size, grub_strlen (options), &size) ||
	  grub_add (size, 1, &size))
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE, "overflow detected while calculating linux buffer size");
	  goto finish;
	}
    }

  linux_cmd = grub_malloc (size);
  if (linux_cmd == NULL)
    goto finish;

  tmp = linux_cmd;
  tmp = grub_stpcpy (tmp, "linux ");
  tmp = blsuki_update_boot_device (tmp);
  tmp = grub_stpcpy (tmp, linux_path);
  if (options != NULL)
    {
      tmp = grub_stpcpy (tmp, " ");
      tmp = grub_stpcpy (tmp, options);
    }

  tmp = grub_stpcpy (tmp, "\n");

 finish:
  grub_free (options);
  return linux_cmd;
}

/*
 * This function returns a string with the command to load all initrds for a
 * linux kernel image based on the list provided by the BLS config file.
 */
static char *
bls_get_initrd (grub_blsuki_entry_t *entry)
{
  char **initrd_list;
  char *initrd_cmd = NULL;
  char *tmp;
  grub_size_t size;
  int i;

  initrd_list = blsuki_make_list (entry, "initrd", NULL);
  if (initrd_list != NULL)
    {
      size = sizeof ("initrd");

      for (i = 0; initrd_list != NULL && initrd_list[i] != NULL; i++)
	{
	  if (grub_add (size, sizeof (" " GRUB_BOOT_DEVICE) - 1, &size) ||
	      grub_add (size, grub_strlen (initrd_list[i]), &size))
	    {
	      grub_error (GRUB_ERR_OUT_OF_RANGE, "overflow detected calculating initrd buffer size");
	      goto finish;
	    }
	}

      if (grub_add (size, 1, &size))
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE, "overflow detected calculating initrd buffer size");
	  goto finish;
	}

      initrd_cmd = grub_malloc (size);
      if (initrd_cmd == NULL)
	goto finish;

      tmp = grub_stpcpy (initrd_cmd, "initrd");
      for (i = 0; initrd_list != NULL && initrd_list[i] != NULL; i++)
	{
	  grub_dprintf ("blsuki", "adding initrd %s\n", initrd_list[i]);
	  tmp = grub_stpcpy (tmp, " ");
	  tmp = blsuki_update_boot_device (tmp);
	  tmp = grub_stpcpy (tmp, initrd_list[i]);
	}
      tmp = grub_stpcpy (tmp, "\n");
    }

 finish:
  grub_free (initrd_list);
  return initrd_cmd;
}

/*
 * This function returns a string with the command to load a device tree blob
 * from the BLS config file.
 */
static char *
bls_get_devicetree (grub_blsuki_entry_t *entry)
{
  char *dt_path;
  char *dt_cmd = NULL;
  char *tmp;
  grub_size_t size;

  dt_path = blsuki_expand_val (blsuki_get_val (entry, "devicetree", NULL));
  if (dt_path != NULL)
    {
      if (grub_add (sizeof ("devicetree " GRUB_BOOT_DEVICE), grub_strlen (dt_path), &size) ||
	  grub_add (size, 1, &size))
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE, "overflow detected calculating device tree buffer size");
	  return NULL;
	}

      dt_cmd = grub_malloc (size);
      if (dt_cmd == NULL)
	return NULL;

      tmp = dt_cmd;
      tmp = grub_stpcpy (dt_cmd, "devicetree ");
      tmp = blsuki_update_boot_device (tmp);
      tmp = grub_stpcpy (tmp, dt_path);
      tmp = grub_stpcpy (tmp, "\n");
    }

  return dt_cmd;
}

/*
 * This function puts together all of the commands generated from the contents
 * of the BLS config file and creates a new entry in the GRUB boot menu.
 */
static void
bls_create_entry (grub_blsuki_entry_t *entry)
{
  int argc = 0;
  const char **argv = NULL;
  char *title = NULL;
  char *linux_path = NULL;
  char *linux_cmd = NULL;
  char *initrd_cmd = NULL;
  char *dt_cmd = NULL;
  char *id = entry->filename;
  grub_size_t id_len;
  char *hotkey = NULL;
  char *users = NULL;
  char **classes = NULL;
  char **args = NULL;
  char *src = NULL;
  int i;
  grub_size_t size;
  bool blsuki_save_default;

  linux_path = blsuki_get_val (entry, "linux", NULL);
  if (linux_path == NULL)
    {
      grub_dprintf ("blsuki", "Skipping file %s with no 'linux' key.\n", entry->filename);
      goto finish;
    }

  id_len = grub_strlen (id);
  if (id_len >= BLS_EXT_LEN && grub_strcmp (id + id_len - BLS_EXT_LEN, ".conf") == 0)
    id[id_len - BLS_EXT_LEN] = '\0';

  title = blsuki_get_val (entry, "title", NULL);
  hotkey = blsuki_get_val (entry, "grub_hotkey", NULL);
  users = blsuki_expand_val (blsuki_get_val (entry, "grub_users", NULL));
  classes = blsuki_make_list (entry, "grub_class", NULL);
  args = blsuki_make_list (entry, "grub_arg", &argc);

  argc++;
  if (grub_mul (argc + 1, sizeof (char *), &size))
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("overflow detected creating argv list"));
      goto finish;
    }

  argv = grub_malloc (size);
  if (argv == NULL)
    goto finish;

  argv[0] = (title != NULL) ? title : linux_path;
  for (i = 1; i < argc; i++)
    argv[i] = args[i - 1];
  argv[argc] = NULL;

  linux_cmd = bls_get_linux (entry);
  if (linux_cmd == NULL)
    goto finish;

  initrd_cmd = bls_get_initrd (entry);
  if (grub_errno != GRUB_ERR_NONE)
    goto finish;

  dt_cmd = bls_get_devicetree (entry);
  if (grub_errno != GRUB_ERR_NONE)
    goto finish;

  blsuki_save_default = grub_env_get_bool ("blsuki_save_default", false);
  src = grub_xasprintf ("%s%s%s%s",
			blsuki_save_default ? "savedefault\n" : "",
			linux_cmd, initrd_cmd ? initrd_cmd : "",
			dt_cmd ? dt_cmd : "");

  grub_normal_add_menu_entry (argc, argv, classes, id, users, hotkey, NULL, src, 0, entry);

 finish:
  grub_free (linux_cmd);
  grub_free (dt_cmd);
  grub_free (initrd_cmd);
  grub_free (classes);
  grub_free (args);
  grub_free (argv);
  grub_free (src);
}

/*
 * This function fills a find_entry_info struct passed in by the info parameter.
 * If the dirname or devid parameters are set to NULL, the dirname and devid
 * fields in the info parameter will be set to default values. If info already
 * has a value in the dev fields, we can compare it to the value passed in by
 * the devid parameter or the default devid to see if we need to open a new
 * device.
 */
static grub_err_t
blsuki_set_find_entry_info (struct find_entry_info *info, const char *dirname, const char *devid)
{
  grub_device_t dev;
  grub_fs_t fs;

  if (info == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "info parameter is not set");

  if (devid == NULL)
    {
#ifdef GRUB_MACHINE_EMU
      devid = "host";
#else
      devid = grub_env_get ("root");
#endif
      if (devid == NULL)
	return grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("variable '%s' isn't set"), "root");
    }

  /* Check that we aren't closing and opening the same device. */
  if (info->dev != NULL && grub_strcmp (info->devid, devid) != 0)
    {
      grub_device_close (info->dev);
      info->dev = NULL;
    }
  /* If we are using the same device, then we can skip this step and only set the directory. */
  if (info->dev == NULL)
    {
      grub_dprintf ("blsuki", "opening %s\n", devid);
      dev = grub_device_open (devid);
      if (dev == NULL)
	return grub_errno;

      grub_dprintf ("blsuki", "probing fs\n");
      fs = grub_fs_probe (dev);
      if (fs == NULL)
	{
	  grub_device_close (dev);
	  return grub_errno;
	}

      info->devid = devid;
      info->dev = dev;
      info->fs = fs;
    }

  info->dirname = dirname;

  return GRUB_ERR_NONE;
}

/*
 * This function searches for BLS config files based on the data in the info
 * parameter. If the fallback option is enabled, the default location will be
 * checked for BLS config files if the first attempt fails.
 */
static grub_err_t
blsuki_find_entry (struct find_entry_info *info, bool enable_fallback)
{
  struct read_entry_info read_entry_info;
  char *default_dir = NULL;
  char *tmp;
  grub_size_t default_size;
  grub_fs_t dir_fs = NULL;
  grub_device_t dir_dev = NULL;
  bool fallback = false;
  int r;

  do
    {
      read_entry_info.file = NULL;
      read_entry_info.dirname = info->dirname;

      grub_dprintf ("blsuki", "scanning dir: %s\n", info->dirname);
      dir_dev = info->dev;
      dir_fs = info->fs;
      read_entry_info.devid = info->devid;

      r = dir_fs->fs_dir (dir_dev, read_entry_info.dirname, blsuki_read_entry,
			  &read_entry_info);
      if (r != 0)
	{
	  grub_dprintf ("blsuki", "blsuki_read_entry returned error\n");
	  grub_errno = GRUB_ERR_NONE;
	}

      /*
       * If we aren't able to find BLS entries in the directory given by info->dirname,
       * we can fallback to the default location "/boot/loader/entries/" and see if we
       * can find the files there.
       */
      if (entries == NULL && fallback == false && enable_fallback == true)
	{
	  default_size = sizeof (GRUB_BOOT_DEVICE) + sizeof (GRUB_BLS_CONFIG_PATH) - 1;
	  default_dir = grub_malloc (default_size);
	  if (default_dir == NULL)
	    return grub_errno;

	  tmp = blsuki_update_boot_device (default_dir);
	  tmp = grub_stpcpy (tmp, GRUB_BLS_CONFIG_PATH);

	  blsuki_set_find_entry_info (info, default_dir, NULL);
	  grub_dprintf ("blsuki", "Entries weren't found in %s, fallback to %s\n",
			read_entry_info.dirname, info->dirname);
	  fallback = true;
	}
      else
	fallback = false;
    }
  while (fallback == true);

  grub_free (default_dir);
  return GRUB_ERR_NONE;
}

static grub_err_t
blsuki_load_entries (char *path, bool enable_fallback)
{
  grub_size_t len;
  static grub_err_t r;
  const char *devid = NULL;
  char *dir = NULL;
  char *default_dir = NULL;
  char *tmp;
  grub_size_t dir_size;
  struct find_entry_info info = {
      .dev = NULL,
      .fs = NULL,
      .dirname = NULL,
  };
  struct read_entry_info rei = {
      .devid = NULL,
      .dirname = NULL,
  };

  if (path != NULL)
    {
      len = grub_strlen (path);
      if (len >= BLS_EXT_LEN && grub_strcmp (path + len - BLS_EXT_LEN, ".conf") == 0)
	{
	  rei.file = grub_file_open (path, GRUB_FILE_TYPE_CONFIG);
	  if (rei.file == NULL)
	    return grub_errno;

	  /* blsuki_read_entry() closes the file. */
	  return blsuki_read_entry (path, NULL, &rei);
	}
      else if (path[0] == '(')
	{
	  devid = path + 1;

	  dir = grub_strchr (path, ')');
	  if (dir == NULL)
	    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid file name `%s'"), path);

	  *dir = '\0';

	  /* Check if there is more than the devid in the path. */
	  if (dir + 1 < path + len)
	    dir = dir + 1;
	}
      else if (path[0] == '/')
	dir = path;
    }

  if (dir == NULL)
    {
      dir_size = sizeof (GRUB_BOOT_DEVICE) + sizeof (GRUB_BLS_CONFIG_PATH) - 2;
      default_dir = grub_malloc (dir_size);
      if (default_dir == NULL)
	return grub_errno;

      tmp = blsuki_update_boot_device (default_dir);
      tmp = grub_stpcpy (tmp, GRUB_BLS_CONFIG_PATH);
      dir = default_dir;
    }

  r = blsuki_set_find_entry_info (&info, dir, devid);
  if (r == GRUB_ERR_NONE)
    r = blsuki_find_entry (&info, enable_fallback);

  if (info.dev != NULL)
    grub_device_close (info.dev);

  grub_free (default_dir);
  return r;
}

static bool
blsuki_is_default_entry (const char *def_entry, grub_blsuki_entry_t *entry, int idx)
{
  const char *title;
  const char *def_entry_end;
  long def_idx;

  if (def_entry == NULL || *def_entry == '\0')
    return false;

  if (grub_strcmp (def_entry, entry->filename) == 0)
    return true;

  title = blsuki_get_val (entry, "title", NULL);

  if (title != NULL && grub_strcmp (def_entry, title) == 0)
    return true;

  def_idx = grub_strtol (def_entry, &def_entry_end, 0);
  if (*def_entry_end != '\0' || def_idx < 0 || def_idx > GRUB_INT_MAX)
    return false;

  if ((int) def_idx == idx)
    return true;

  return false;
}

/*
 * This function creates a GRUB boot menu entry for each BLS entry in the
 * entries list.
 */
static grub_err_t
blsuki_create_entries (bool show_default, bool show_non_default, char *entry_id)
{
  const char *def_entry = NULL;
  grub_blsuki_entry_t *entry = NULL;
  int idx = 0;

  def_entry = grub_env_get ("default");

  FOR_BLSUKI_ENTRIES(entry)
    {
      if (entry->visible == true)
	{
	  idx++;
	  continue;
	}
      if ((show_default == true && blsuki_is_default_entry (def_entry, entry, idx) == true) ||
	  (show_non_default == true && blsuki_is_default_entry (def_entry, entry, idx) == false) ||
	  (entry_id != NULL && grub_strcmp (entry_id, entry->filename) == 0))
	{
	  bls_create_entry (entry);
	  entry->visible = true;
	}

      idx++;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_blscfg (grub_extcmd_context_t ctxt, int argc __attribute__ ((unused)),
		 char **args __attribute__ ((unused)))
{
  grub_err_t err;
  struct grub_arg_list *state = ctxt->state;
  char *path = NULL;
  char *entry_id = NULL;
  bool enable_fallback = false;
  bool show_default = false;
  bool show_non_default = false;
  bool all = true;
  entries = NULL;

  if (state[0].set)
    path = state[0].arg;
  if (state[1].set)
    enable_fallback = true;
  if (state[2].set)
    {
      show_default = true;
      all = false;
    }
  if (state[3].set)
    {
      show_non_default = true;
      all = false;
    }
  if (state[4].set)
    {
      entry_id = state[4].arg;
      all = false;
    }
  if (all == true)
    {
      show_default = true;
      show_non_default = true;
    }

  err = blsuki_load_entries (path, enable_fallback);
  if (err != GRUB_ERR_NONE)
    return err;

  return blsuki_create_entries (show_default, show_non_default, entry_id);
}

static grub_extcmd_t bls_cmd;

GRUB_MOD_INIT(blsuki)
{
  bls_cmd = grub_register_extcmd ("blscfg", grub_cmd_blscfg, 0,
				  N_("[-p|--path] [-f|--enable-fallback] DIR [-d|--show-default] [-n|--show-non-default] [-e|--entry] FILE"),
				  N_("Import Boot Loader Specification snippets."),
				  bls_opt);
}

GRUB_MOD_FINI(blsuki)
{
  grub_unregister_extcmd (bls_cmd);
}
