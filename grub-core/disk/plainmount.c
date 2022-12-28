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

/* plaimount.c - Open device encrypted in plain mode. */

#include <grub/cryptodisk.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/extcmd.h>
#include <grub/partition.h>
#include <grub/file.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define PLAINMOUNT_DEFAULT_SECTOR_SIZE 512
#define PLAINMOUNT_DEFAULT_UUID        "109fea84-a6b7-34a8-4bd1-1c506305a400"


enum PLAINMOUNT_OPTION
  {
    OPTION_HASH,
    OPTION_CIPHER,
    OPTION_KEY_SIZE,
    OPTION_SECTOR_SIZE,
    OPTION_PASSWORD,
    OPTION_KEYFILE,
    OPTION_KEYFILE_OFFSET,
    OPTION_UUID
  };

static const struct grub_arg_option options[] =
  {
    /* TRANSLATORS: It's still restricted to this module only.  */
    {"hash", 'h', 0, N_("Password hash"), 0, ARG_TYPE_STRING},
    {"cipher", 'c', 0, N_("Password cipher"), 0, ARG_TYPE_STRING},
    {"key-size", 's', 0, N_("Key size (in bits)"), 0, ARG_TYPE_INT},
    {"sector-size", 'S', 0, N_("Device sector size"), 0, ARG_TYPE_INT},
    {"password", 'p', 0, N_("Password (key)"), 0, ARG_TYPE_STRING},
    {"keyfile", 'd', 0, N_("Keyfile path"), 0, ARG_TYPE_STRING},
    {"keyfile-offset", 'O', 0, N_("Keyfile offset"), 0, ARG_TYPE_INT},
    {"uuid", 'u', 0, N_("Set device UUID"), 0, ARG_TYPE_STRING},
    {0, 0, 0, 0, 0, 0}
  };

/* Cryptodisk setkey() function wrapper */
static grub_err_t
plainmount_setkey (grub_cryptodisk_t dev, grub_uint8_t *key,
		   grub_size_t size)
{
  gcry_err_code_t code = grub_cryptodisk_setkey (dev, key, size);
  if (code != GPG_ERR_NO_ERROR)
    {
      grub_dprintf ("plainmount", "failed to set cipher key with code: %d\n", code);
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("cannot set specified key"));
    }
  return GRUB_ERR_NONE;
}

/* Configure cryptodisk uuid */
static void plainmount_set_uuid (grub_cryptodisk_t dev, const char *user_uuid)
{
  grub_size_t pos = 0;

  /* Size of user_uuid is checked in main func */
  if (user_uuid != NULL)
      grub_strcpy (dev->uuid, user_uuid);
  else
    {
      /*
       * Set default UUID. Last digits start from 1 and are incremented for
       * each new plainmount device by snprintf().
       */
      grub_snprintf (dev->uuid, sizeof (dev->uuid) - 1, "%36lx", dev->id + 1);
      while (dev->uuid[++pos] == ' ');
      grub_memcpy (dev->uuid, PLAINMOUNT_DEFAULT_UUID, pos);
    }
  COMPILE_TIME_ASSERT (sizeof (dev->uuid) >= sizeof (PLAINMOUNT_DEFAULT_UUID));
}

/* Configure cryptodevice sector size (-S option) */
static grub_err_t
plainmount_configure_sectors (grub_cryptodisk_t dev, grub_disk_t disk,
			      grub_size_t sector_size)
{
  dev->total_sectors = grub_disk_native_sectors (disk);
  if (dev->total_sectors == GRUB_DISK_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("cannot determine disk %s size"),
		       disk->name);

  /* Convert size to sectors */
  dev->log_sector_size = grub_log2ull (sector_size);
  dev->total_sectors = grub_convert_sector (dev->total_sectors,
					    GRUB_DISK_SECTOR_BITS,
					    dev->log_sector_size);
  if (dev->total_sectors == 0)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("cannot set specified sector size on disk %s"),
		       disk->name);

  grub_dprintf ("plainmount", "log_sector_size=%d, total_sectors=%"
		PRIuGRUB_UINT64_T"\n", dev->log_sector_size, dev->total_sectors);
  return GRUB_ERR_NONE;
}

/* Hashes a password into a key and stores it with the cipher. */
static grub_err_t
plainmount_configure_password (grub_cryptodisk_t dev, const char *hash,
			       grub_uint8_t *key_data, grub_size_t key_size,
			       grub_size_t password_size)
{
  grub_uint8_t *derived_hash, *dh;
  char *p;
  unsigned int round, i, len, size;
  grub_size_t alloc_size;
  grub_err_t err = GRUB_ERR_NONE;

  /* Support none (plain) hash */
  if (grub_strcmp (hash, "plain") == 0)
    {
      dev->hash = NULL;
      return err;
    }

  /* Hash argument was checked at main func */
  dev->hash = grub_crypto_lookup_md_by_name (hash);
  len = dev->hash->mdlen;

  alloc_size = grub_max (password_size, key_size);
  /*
   * Allocate buffer for the password and for an added prefix character
   * for each hash round ('alloc_size' may not be a multiple of 'len').
   */
  p = grub_zalloc (alloc_size + (alloc_size / len) + 1);
  derived_hash = grub_zalloc (GRUB_CRYPTODISK_MAX_KEYLEN * 2);
  if (p == NULL || derived_hash == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
      goto fail;
    }
  dh = derived_hash;

  /*
   * Hash password. Adapted from cryptsetup.
   * https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/lib/crypt_plain.c
   */
  for (round = 0, size = alloc_size; size; round++, dh += len, size -= len)
    {
      for (i = 0; i < round; i++)
	p[i] = 'A';

      grub_memcpy (p + i, (char*) key_data, password_size);

      if (len > size)
	len = size;

      grub_crypto_hash (dev->hash, dh, p, password_size + round);
    }
  grub_memcpy (key_data, derived_hash, key_size);

 fail:
  grub_free (p);
  grub_free (derived_hash);
  return err;
}

/* Read key material from keyfile */
static grub_err_t
plainmount_configure_keyfile (char *keyfile, grub_uint8_t *key_data,
			      grub_size_t key_size, grub_size_t keyfile_offset)
{
  grub_file_t g_keyfile = grub_file_open (keyfile, GRUB_FILE_TYPE_NONE);
  if (g_keyfile == NULL)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("cannot open keyfile %s"),
		       keyfile);

  if (grub_file_seek (g_keyfile, keyfile_offset) == (grub_off_t) - 1)
    return grub_error (GRUB_ERR_FILE_READ_ERROR,
		       N_("cannot seek keyfile at offset %"PRIuGRUB_SIZE),
		       keyfile_offset);

  if (key_size > (g_keyfile->size - keyfile_offset))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Specified key size (%"
		       PRIuGRUB_SIZE") is too small for keyfile size (%"
		       PRIuGRUB_UINT64_T") and offset (%"PRIuGRUB_SIZE")"),
		       key_size, g_keyfile->size, keyfile_offset);

  if (grub_file_read (g_keyfile, key_data, key_size) != (grub_ssize_t) key_size)
    return grub_error (GRUB_ERR_FILE_READ_ERROR, N_("error reading key file"));
  return GRUB_ERR_NONE;
}

/* Plainmount command entry point */
static grub_err_t
grub_cmd_plainmount (grub_extcmd_context_t ctxt, int argc, char **args)
{
  struct grub_arg_list *state = ctxt->state;
  grub_cryptodisk_t dev = NULL;
  grub_disk_t disk = NULL;
  const gcry_md_spec_t *gcry_hash;
  char *diskname, *disklast = NULL, *cipher, *mode, *hash, *keyfile, *uuid;
  grub_size_t len, key_size, sector_size, keyfile_offset = 0, password_size = 0;
  grub_err_t err;
  const char *p;
  grub_uint8_t *key_data;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("device name required"));

  /* Check whether required arguments are specified */
  if (!state[OPTION_CIPHER].set || !state[OPTION_KEY_SIZE].set)
      return grub_error (GRUB_ERR_BAD_ARGUMENT, "cipher and key size must be set");
  if (!state[OPTION_HASH].set && !state[OPTION_KEYFILE].set)
      return grub_error (GRUB_ERR_BAD_ARGUMENT, "hash algorithm must be set");

  /* Check hash */
  if (!state[OPTION_KEYFILE].set)
  {
    gcry_hash = grub_crypto_lookup_md_by_name (state[OPTION_HASH].arg);
    if (!gcry_hash)
      return grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("couldn't load hash %s"),
			 state[OPTION_HASH].arg);

    if (gcry_hash->mdlen > GRUB_CRYPTODISK_MAX_KEYLEN)
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
			 N_("hash length %"PRIuGRUB_SIZE" exceeds maximum %d bits"),
			 gcry_hash->mdlen * GRUB_CHAR_BIT,
			 GRUB_CRYPTODISK_MAX_KEYLEN * GRUB_CHAR_BIT);
   }

  /* Check cipher mode */
  if (!grub_strchr (state[OPTION_CIPHER].arg,'-'))
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("invalid cipher mode, must be of format cipher-mode"));

  /* Check password size */
  if (state[OPTION_PASSWORD].set && grub_strlen (state[OPTION_PASSWORD].arg) >
		                                 GRUB_CRYPTODISK_MAX_PASSPHRASE)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("password exceeds maximium size"));

  /* Check uuid length */
  if (state[OPTION_UUID].set && grub_strlen (state[OPTION_UUID].arg) >
				GRUB_CRYPTODISK_MAX_UUID_LENGTH - 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("specified UUID exceeds maximum size"));
  if (state[OPTION_UUID].set && grub_strlen (state[OPTION_UUID].arg) == 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("specified UUID too short"));

  /* Parse plainmount arguments */
  grub_errno = GRUB_ERR_NONE;
  keyfile_offset = state[OPTION_KEYFILE_OFFSET].set ?
		   grub_strtoull (state[OPTION_KEYFILE_OFFSET].arg, &p, 0) : 0;
  if (state[OPTION_KEYFILE_OFFSET].set &&
     (state[OPTION_KEYFILE_OFFSET].arg[0] == '\0' || *p != '\0' ||
      grub_errno != GRUB_ERR_NONE))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized keyfile offset"));

  sector_size = state[OPTION_SECTOR_SIZE].set ?
		grub_strtoull (state[OPTION_SECTOR_SIZE].arg, &p, 0) :
		PLAINMOUNT_DEFAULT_SECTOR_SIZE;
  if (state[OPTION_SECTOR_SIZE].set && (state[OPTION_SECTOR_SIZE].arg[0] == '\0' ||
					*p != '\0' || grub_errno != GRUB_ERR_NONE))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized sector size"));

  /* Check key size */
  key_size = grub_strtoull (state[OPTION_KEY_SIZE].arg, &p, 0);
  if (state[OPTION_KEY_SIZE].arg[0] == '\0' || *p != '\0' ||
      grub_errno != GRUB_ERR_NONE)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized key size"));
  if ((key_size % GRUB_CHAR_BIT) != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("key size is not multiple of %d bits"), GRUB_CHAR_BIT);
  key_size = key_size / GRUB_CHAR_BIT;
  if (key_size > GRUB_CRYPTODISK_MAX_KEYLEN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("key size %"PRIuGRUB_SIZE" exceeds maximum %d bits"),
		       key_size * GRUB_CHAR_BIT,
		       GRUB_CRYPTODISK_MAX_KEYLEN * GRUB_CHAR_BIT);

  /* Check disk sector size */
  if (sector_size < GRUB_DISK_SECTOR_SIZE)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("sector size -S must be at least %d"),
		       GRUB_DISK_SECTOR_SIZE);
  if ((sector_size & (sector_size - 1)) != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("sector size -S %"PRIuGRUB_SIZE" is not power of 2"),
		       sector_size);

  /* Allocate all stuff here */
  hash =  state[OPTION_HASH].set ? grub_strdup (state[OPTION_HASH].arg) : NULL;
  cipher = grub_strdup (state[OPTION_CIPHER].arg);
  keyfile = state[OPTION_KEYFILE].set ?
	    grub_strdup (state[OPTION_KEYFILE].arg) : NULL;
  dev = grub_zalloc (sizeof *dev);
  key_data = grub_zalloc (GRUB_CRYPTODISK_MAX_PASSPHRASE);
  uuid = state[OPTION_UUID].set ? grub_strdup (state[OPTION_UUID].arg) : NULL;
  if ((state[OPTION_HASH].set && hash == NULL) || cipher == NULL || dev == NULL ||
      (state[OPTION_KEYFILE].set && keyfile == NULL) || key_data == NULL ||
      (state[OPTION_UUID].set && uuid == NULL))
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
      goto fail;
    }

  /* Copy user password from -p option */
  if (state[OPTION_PASSWORD].set)
    {
      /*
       * Password from the '-p' option is limited to C-string.
       * Arbitrary data keys are supported via keyfiles.
       */
      password_size = grub_strlen (state[OPTION_PASSWORD].arg);
      grub_strcpy ((char*) key_data, state[OPTION_PASSWORD].arg);
    }

  /* Set cipher mode (tested above) */
  mode = grub_strchr (cipher,'-');
  *mode++ = '\0';

  /* Check cipher */
  err = grub_cryptodisk_setcipher (dev, cipher, mode);
  if (err != GRUB_ERR_NONE)
    {
      if (err == GRUB_ERR_FILE_NOT_FOUND)
        err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid cipher %s"), cipher);
      else if (err == GRUB_ERR_BAD_ARGUMENT)
        err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid mode %s"), mode);
      else
        err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid cipher %s or mode %s"),
			  cipher, mode);
      goto fail;
    }

  /* Open SOURCE disk */
  diskname = args[0];
  len = grub_strlen (diskname);
  if (len && diskname[0] == '(' && diskname[len - 1] == ')')
    {
      disklast = &diskname[len - 1];
      *disklast = '\0';
      diskname++;
    }
  disk = grub_disk_open (diskname);
  if (disk == NULL)
    {
      if (disklast)
        *disklast = ')';
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("cannot open disk %s"), diskname);
      goto fail;
    }

  /* Get password from console */
  if (!state[OPTION_KEYFILE].set && key_data[0] == '\0')
  {
    char *part = grub_partition_get_name (disk->partition);
    grub_printf_ (N_("Enter passphrase for %s%s%s: "), disk->name,
		  disk->partition != NULL ? "," : "",
		  part != NULL ? part : N_("UNKNOWN"));
    grub_free (part);

    if (!grub_password_get ((char*) key_data, GRUB_CRYPTODISK_MAX_PASSPHRASE - 1))
      {
        err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("error reading password"));
        goto fail;
      }
    /*
     * Password from interactive console is limited to C-string.
     * Arbitrary data keys are supported via keyfiles.
     */
    password_size = grub_strlen ((char*) key_data);
  }

  /* Warn if hash and keyfile are both provided */
  if (state[OPTION_KEYFILE].set && state[OPTION_HASH].arg)
    grub_printf_ (N_("warning: hash is ignored if keyfile is specified\n"));

  /* Warn if -p option is specified with keyfile */
  if (state[OPTION_PASSWORD].set && state[OPTION_KEYFILE].set)
    grub_printf_ (N_("warning: password specified with -p option "
		     "is ignored if keyfile is provided\n"));

  /* Warn of -O is provided without keyfile */
  if (state[OPTION_KEYFILE_OFFSET].set && !state[OPTION_KEYFILE].set)
    grub_printf_ (N_("warning: keyfile offset option -O "
		     "specified without keyfile option -d\n"));

  grub_dprintf ("plainmount", "parameters: cipher=%s, hash=%s, key_size=%"
		 PRIuGRUB_SIZE ", keyfile=%s, keyfile offset=%" PRIuGRUB_SIZE "\n",
		cipher, hash, key_size, keyfile, keyfile_offset);

  err = plainmount_configure_sectors (dev, disk, sector_size);
  if (err != GRUB_ERR_NONE)
    goto fail;

  /* Configure keyfile or password */
  if (state[OPTION_KEYFILE].set)
    err = plainmount_configure_keyfile (keyfile, key_data, key_size, keyfile_offset);
  else
    err = plainmount_configure_password (dev, hash, key_data, key_size, password_size);
  if (err != GRUB_ERR_NONE)
    goto fail;

  err = plainmount_setkey (dev, key_data, key_size);
  if (err != GRUB_ERR_NONE)
    goto fail;

  err = grub_cryptodisk_insert (dev, diskname, disk);
  if (err != GRUB_ERR_NONE)
    goto fail;

  dev->modname = "plainmount";
  dev->source_disk = disk;
  plainmount_set_uuid (dev, uuid);

 fail:
  grub_free (hash);
  grub_free (cipher);
  grub_free (keyfile);
  grub_free (key_data);
  grub_free (uuid);
  if (err != GRUB_ERR_NONE && disk != NULL)
    grub_disk_close (disk);
  if (err != GRUB_ERR_NONE)
    grub_free (dev);
  return err;
}

static grub_extcmd_t cmd;
GRUB_MOD_INIT (plainmount)
{
  cmd = grub_register_extcmd ("plainmount", grub_cmd_plainmount, 0,
			      N_("-c cipher -s key-size [-h hash] [-S sector-size]"
			      " [-o offset] [-p password] [-u uuid] "
			      " [[-d keyfile] [-O keyfile offset]] <SOURCE>"),
			      N_("Open partition encrypted in plain mode."),
			      options);
}

GRUB_MOD_FINI (plainmount)
{
  grub_unregister_extcmd (cmd);
}
