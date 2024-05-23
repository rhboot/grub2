/* search.c - search devices based on a file or a filesystem label */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2007,2008,2009  Free Software Foundation, Inc.
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
#include <grub/device.h>
#include <grub/file.h>
#include <grub/env.h>
#include <grub/command.h>
#include <grub/search.h>
#include <grub/i18n.h>
#include <grub/disk.h>
#include <grub/partition.h>
#include <grub/efi/api.h>
#include <grub/time.h>

GRUB_MOD_LICENSE ("GPLv3+");

struct cache_entry
{
  struct cache_entry *next;
  char *key;
  char *value;
};

static struct cache_entry *cache;

/* Context for FUNC_NAME.  */
struct search_ctx
{
  const char *key;
  const char *var;
  enum search_flags flags;
  char **hints;
  unsigned nhints;
  int count;
  int is_cache;
};

static int
is_device_usb (const char *name)
{
  int ret = 0;

  grub_device_t dev = grub_device_open(name);

  if (dev)
    {
      struct grub_efidisk_data
      {
        grub_efi_handle_t handle;
        grub_efi_device_path_t *device_path;
        grub_efi_device_path_t *last_device_path;
        grub_efi_block_io_t *block_io;
        struct grub_efidisk_data *next;
      };

      if (dev->disk && dev->disk->data)
        {
        struct grub_efidisk_data *dp = dev->disk->data;

        if ( GRUB_EFI_DEVICE_PATH_TYPE (dp->last_device_path) == GRUB_EFI_MESSAGING_DEVICE_PATH_TYPE &&
          GRUB_EFI_DEVICE_PATH_SUBTYPE (dp->last_device_path) == GRUB_EFI_USB_DEVICE_PATH_SUBTYPE)
          {
            ret = 1;
          }
        }
      grub_device_close(dev);
    }

  return ret;
}

static int
get_device_uuid(const char *name, char** quid)
{
  int ret = 0;

  grub_device_t dev_part = grub_device_open(name);

  if (dev_part)
    {
      grub_fs_t fs;

      fs = grub_fs_probe (dev_part);

#ifdef DO_SEARCH_FS_UUID
#define read_fn fs_uuid
#else
#define read_fn fs_label
#endif
      if (fs && fs->read_fn)
        {
          fs->read_fn (dev_part, quid);

          if (grub_errno == GRUB_ERR_NONE && *quid)
            {
	      ret = 1;
            }

        }
        grub_device_close (dev_part);
    }

  return ret;
}
struct uuid_context {
  char* name;
  char* uuid;
};

static int
check_for_duplicate (const char *name, void *data)
{
  int ret = 0;
  struct uuid_context * uuid_ctx = (struct uuid_context *)data;
  char *quid = 0;

  get_device_uuid(name, &quid);

  if (quid == NULL)
    return 0;

  if (!grub_strcasecmp(quid, uuid_ctx->uuid) && grub_strcasecmp(name, uuid_ctx->name))
    {
      ret = 1;
    }

  grub_free(quid);

  return ret;
}

/* Helper for FUNC_NAME.  */
static int
iterate_device (const char *name, void *data)
{
  struct search_ctx *ctx = data;
  const char *root_dev;
  int found = 0;

  /* Skip floppy drives when requested.  */
  if (ctx->flags & SEARCH_FLAGS_NO_FLOPPY &&
      name[0] == 'f' && name[1] == 'd' && name[2] >= '0' && name[2] <= '9')
    return 0;

  /* Limit to EFI disks when requested.  */
  if (ctx->flags & SEARCH_FLAGS_EFIDISK_ONLY)
    {
      grub_device_t dev;
      dev = grub_device_open (name);
      if (! dev)
	{
	  grub_errno = GRUB_ERR_NONE;
	  return 0;
	}
      if (! dev->disk || dev->disk->dev->id != GRUB_DISK_DEVICE_EFIDISK_ID)
	{
	  grub_device_close (dev);
	  grub_errno = GRUB_ERR_NONE;
	  return 0;
	}
      grub_device_close (dev);
    }

  /* Skip it if it's not the root device when requested. */
  if (ctx->flags & SEARCH_FLAGS_ROOTDEV_ONLY)
    {
      const char *root_dev;
      root_dev = grub_env_get ("root");
      if (root_dev != NULL && *root_dev != '\0')
      {
        char *root_disk = grub_malloc (grub_strlen(root_dev) + 1);
        char *name_disk = grub_malloc (grub_strlen(name) + 1);
        char *rem_1 = grub_malloc(grub_strlen(root_dev) + 1);
        char *rem_2 = grub_malloc(grub_strlen(name) + 1);

	if (root_disk != NULL && name_disk != NULL && 
	    rem_1 != NULL && rem_2 != NULL)
  	  {
            /* get just the disk name; partitions will be different. */
            grub_str_sep (root_dev, root_disk, ',', rem_1);
            grub_str_sep (name, name_disk, ',', rem_2);
            if (root_disk != NULL && *root_disk != '\0' &&
    	        name_disk != NULL && *name_disk != '\0')
              {
                grub_device_t dev, dev_part;

                if (is_device_usb(name) && !is_device_usb(root_dev))
                  {
                    char *quid_name = NULL;
                    int longlist = 0;
                    struct uuid_context uuid_ctx;
                    int ret = 0;

                    get_device_uuid(name, &quid_name);
                    if (!grub_strcmp(quid_name, ctx->key))
                      {
                        uuid_ctx.name = name;
                        uuid_ctx.uuid = quid_name;

                        ret = grub_device_iterate (check_for_duplicate, &uuid_ctx);

                        if (ret)
                          {
                            grub_printf("Duplicated media UUID found, rebooting ...\n");
                            grub_sleep(10);
                            grub_reboot();
                          }
                      }

                    if (quid_name) grub_free (quid_name);

                  }
              }
	  }
        grub_free (root_disk);
        grub_free (name_disk);
        grub_free (rem_1);
        grub_free (rem_2);
      }
    }

#ifdef DO_SEARCH_FS_UUID
#define compare_fn grub_strcasecmp
#else
#define compare_fn grub_strcmp
#endif

#ifdef DO_SEARCH_FILE
    {
      char *buf;
      grub_file_t file;

      buf = grub_xasprintf ("(%s)%s", name, ctx->key);
      if (! buf)
	return 1;

      file = grub_file_open (buf, GRUB_FILE_TYPE_FS_SEARCH
			     | GRUB_FILE_TYPE_NO_DECOMPRESS);
      if (file)
	{
	  found = 1;
	  grub_file_close (file);
	}
      grub_free (buf);
    }
#else
    {
      /* SEARCH_FS_UUID or SEARCH_LABEL */
      grub_device_t dev;
      grub_fs_t fs;
      char *quid;

      dev = grub_device_open (name);
      if (dev)
	{
	  fs = grub_fs_probe (dev);

#ifdef DO_SEARCH_FS_UUID
#define read_fn fs_uuid
#else
#define read_fn fs_label
#endif

	  if (fs && fs->read_fn)
	    {
	      fs->read_fn (dev, &quid);

	      if (grub_errno == GRUB_ERR_NONE && quid)
		{
		  if (compare_fn (quid, ctx->key) == 0)
		    found = 1;

		  grub_free (quid);
		}
	    }

	  grub_device_close (dev);
	}
    }
#endif

  if (!ctx->is_cache && found && ctx->count == 0)
    {
      struct cache_entry *cache_ent;
      cache_ent = grub_malloc (sizeof (*cache_ent));
      if (cache_ent)
	{
	  cache_ent->key = grub_strdup (ctx->key);
	  cache_ent->value = grub_strdup (name);
	  if (cache_ent->value && cache_ent->key)
	    {
	      cache_ent->next = cache;
	      cache = cache_ent;
	    }
	  else
	    {
	      grub_free (cache_ent->value);
	      grub_free (cache_ent->key);
	      grub_free (cache_ent);
	      grub_errno = GRUB_ERR_NONE;
	    }
	}
      else
	grub_errno = GRUB_ERR_NONE;
    }

  if (found)
    {
      ctx->count++;
      if (ctx->var)
	grub_env_set (ctx->var, name);
      else
	grub_printf (" %s", name);
    }

  grub_errno = GRUB_ERR_NONE;
  return (found && ctx->var);
}

/* Helper for FUNC_NAME.  */
static int
part_hook (grub_disk_t disk, const grub_partition_t partition, void *data)
{
  struct search_ctx *ctx = data;
  char *partition_name, *devname;
  int ret;

  partition_name = grub_partition_get_name (partition);
  if (! partition_name)
    return 1;

  devname = grub_xasprintf ("%s,%s", disk->name, partition_name);
  grub_free (partition_name);
  if (!devname)
    return 1;
  ret = iterate_device (devname, ctx);
  grub_free (devname);    

  return ret;
}

/* Helper for FUNC_NAME.  */
static void
try (struct search_ctx *ctx)    
{
  unsigned i;
  struct cache_entry **prev;
  struct cache_entry *cache_ent;

  for (prev = &cache, cache_ent = *prev; cache_ent;
       prev = &cache_ent->next, cache_ent = *prev)
    if (compare_fn (cache_ent->key, ctx->key) == 0)
      break;
  if (cache_ent)
    {
      ctx->is_cache = 1;
      if (iterate_device (cache_ent->value, ctx))
	{
	  ctx->is_cache = 0;
	  return;
	}
      ctx->is_cache = 0;
      /* Cache entry was outdated. Remove it.  */
      if (!ctx->count)
	{
	  *prev = cache_ent->next;
	  grub_free (cache_ent->key);
	  grub_free (cache_ent->value);
	  grub_free (cache_ent);
	}
    }

  for (i = 0; i < ctx->nhints; i++)
    {
      char *end;
      if (!ctx->hints[i][0])
	continue;
      end = ctx->hints[i] + grub_strlen (ctx->hints[i]) - 1;
      if (*end == ',')
	*end = 0;
      if (iterate_device (ctx->hints[i], ctx))
	{
	  if (!*end)
	    *end = ',';
	  return;
	}
      if (!*end)
	{
	  grub_device_t dev;
	  int ret;
	  dev = grub_device_open (ctx->hints[i]);
	  if (!dev)
	    {
	      if (!*end)
		*end = ',';
	      continue;
	    }
	  if (!dev->disk)
	    {
	      grub_device_close (dev);
	      if (!*end)
		*end = ',';
	      continue;
	    }
	  ret = grub_partition_iterate (dev->disk, part_hook, ctx);
	  if (!*end)
	    *end = ',';
	  grub_device_close (dev);
	  if (ret)
	    return;
	}
    }
  grub_device_iterate (iterate_device, ctx);
}

void
FUNC_NAME (const char *key, const char *var, enum search_flags flags,
	   char **hints, unsigned nhints)
{
  struct search_ctx ctx = {
    .key = key,
    .var = var,
    .flags = flags,
    .hints = hints,
    .nhints = nhints,
    .count = 0,
    .is_cache = 0
  };
  grub_fs_autoload_hook_t saved_autoload;

  /* First try without autoloading if we're setting variable. */
  if (var)
    {
      saved_autoload = grub_fs_autoload_hook;
      grub_fs_autoload_hook = 0;
      try (&ctx);

      /* Restore autoload hook.  */
      grub_fs_autoload_hook = saved_autoload;

      /* Retry with autoload if nothing found.  */
      if (grub_errno == GRUB_ERR_NONE && ctx.count == 0)
	try (&ctx);
    }
  else
    try (&ctx);

  if (grub_errno == GRUB_ERR_NONE && ctx.count == 0)
    grub_error (GRUB_ERR_FILE_NOT_FOUND, "no such device: %s", key);
}

static grub_err_t
grub_cmd_do_search (grub_command_t cmd __attribute__ ((unused)), int argc,
		    char **args)
{
  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("one argument expected"));

  FUNC_NAME (args[0], argc == 1 ? 0 : args[1], 0, (args + 2),
	     argc > 2 ? argc - 2 : 0);

  return grub_errno;
}

static grub_command_t cmd;

#ifdef DO_SEARCH_FILE
GRUB_MOD_INIT(search_fs_file)
#elif defined (DO_SEARCH_FS_UUID)
GRUB_MOD_INIT(search_fs_uuid)
#else
GRUB_MOD_INIT(search_label)
#endif
{
  cmd =
    grub_register_command (COMMAND_NAME, grub_cmd_do_search,
			   N_("NAME [VARIABLE] [HINTS]"),
			   HELP_MESSAGE);
}

#ifdef DO_SEARCH_FILE
GRUB_MOD_FINI(search_fs_file)
#elif defined (DO_SEARCH_FS_UUID)
GRUB_MOD_FINI(search_fs_uuid)
#else
GRUB_MOD_FINI(search_label)
#endif
{
  grub_unregister_command (cmd);
}
