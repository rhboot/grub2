/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024  Free Software Foundation, Inc.
 *  Copyright (C) 2024 IBM Corporation
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

#include <grub/mm.h>
#include <grub/powerpc/ieee1275/ieee1275.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/lockdown.h>
#include <grub/powerpc/ieee1275/platform_keystore.h>

#define PKS_CONSUMER_FW 1
#define SB_VERSION_KEY_NAME ((grub_uint8_t *) "SB_VERSION")
#define SB_VERSION_KEY_LEN 10
#define DB 1
#define DBX 2
#define PKS_OBJECT_NOT_FOUND ((grub_err_t) - 7)

/* Platform Keystore */
static grub_size_t pks_max_object_size;
grub_uint8_t grub_pks_use_keystore = 0;
grub_pks_t grub_pks_keystore = { .db = NULL,
                                 .dbx = NULL,
                                 .db_entries = 0,
                                 .dbx_entries = 0,
                                 .use_static_keys = false };

/* Convert the esl data into the ESL */
static grub_esl_t *
convert_to_esl (const grub_uint8_t *esl_data, const grub_size_t esl_data_size)
{
  grub_esl_t *esl = NULL;

  if (esl_data_size < sizeof (grub_esl_t) || esl_data == NULL)
    return esl;

  esl = (grub_esl_t *) esl_data;

  return esl;
}

/*
 * Import the GUID, esd, and its size into the pks sd buffer and
 * pks sd entries from the EFI signature list.
 */
static grub_err_t
esd_from_esl (const grub_uint8_t *esl_data, grub_size_t esl_size,
              const grub_size_t signature_size, const grub_uuid_t *guid,
              grub_pks_sd_t **pks_sd, grub_size_t *pks_sd_entries)
{
  grub_esd_t *esd = NULL;
  grub_pks_sd_t *signature = *pks_sd;
  grub_size_t entries = *pks_sd_entries;
  grub_size_t data_size = 0, offset = 0;

  /* reads the esd from esl */
  while (esl_size > 0)
    {
      esd = (grub_esd_t *) (esl_data + offset);
      data_size = signature_size - sizeof (grub_esd_t);

      signature = grub_realloc (signature, (entries + 1) * sizeof (grub_pks_sd_t));
      if (signature == NULL)
        return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

      signature[entries].data = grub_malloc (data_size * sizeof (grub_uint8_t));
      if (signature[entries].data == NULL)
        {
          /*
           * allocated memory will be freed by
           * grub_free_platform_keystore
           */
          *pks_sd = signature;
          *pks_sd_entries = entries + 1;
          return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
        }

      grub_memcpy (signature[entries].data, esd->signaturedata, data_size);
      signature[entries].data_size = data_size;
      signature[entries].guid = *guid;
      entries++;
      esl_size -= signature_size;
      offset += signature_size;
    }

  *pks_sd = signature;
  *pks_sd_entries = entries;

  return GRUB_ERR_NONE;
}

/*
 * Extract the esd after removing the esl header from esl.
 */
static grub_err_t
esl_to_esd (const grub_uint8_t *esl_data, grub_size_t *next_esl,
            grub_pks_sd_t **pks_sd, grub_size_t *pks_sd_entries)
{
  grub_uuid_t guid = { 0 };
  grub_esl_t *esl = NULL;
  grub_size_t offset = 0, esl_size = 0,
              signature_size = 0, signature_header_size = 0;

  esl = convert_to_esl (esl_data, *next_esl);
  if (esl == NULL)
    return grub_error (GRUB_ERR_BUG, "invalid ESL");

  esl_size = grub_le_to_cpu32 (esl->signaturelistsize);
  signature_header_size = grub_le_to_cpu32 (esl->signatureheadersize);
  signature_size = grub_le_to_cpu32 (esl->signaturesize);
  guid = esl->signaturetype;

  if (esl_size < sizeof (grub_esl_t) || esl_size > *next_esl)
    return grub_error (GRUB_ERR_BUG, "invalid ESL size (%u)\n", esl_size);

  *next_esl = esl_size;
  offset = sizeof (grub_esl_t) + signature_header_size;
  esl_size = esl_size - offset;

  return esd_from_esl (esl_data + offset, esl_size, signature_size, &guid,
                       pks_sd, pks_sd_entries);
}

/*
 * Import the EFI signature data and the number of esd from the esl
 * into the pks sd buffer and pks sd entries.
 */
static grub_err_t
pks_sd_from_esl (const grub_uint8_t *esl_data, grub_size_t esl_size,
                 grub_pks_sd_t **pks_sd, grub_size_t *pks_sd_entries)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_size_t next_esl = esl_size;

  do
    {
      rc = esl_to_esd (esl_data, &next_esl, pks_sd, pks_sd_entries);
      if (rc != GRUB_ERR_NONE)
        break;

      esl_data += next_esl;
      esl_size -= next_esl;
      next_esl = esl_size;
    }
  while (esl_size > 0);

  return rc;
}

/*
 * Read the secure boot version from PKS as an object.
 * caller must free result
 */
static grub_err_t
read_sbversion_from_pks (grub_uint8_t **out, grub_size_t *outlen, grub_size_t *policy)
{
  *out = grub_malloc (pks_max_object_size);
  if (*out == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  return grub_ieee1275_pks_read_object (PKS_CONSUMER_FW, SB_VERSION_KEY_NAME,
                                        SB_VERSION_KEY_LEN, *out, pks_max_object_size,
                                        outlen, policy);
}

/*
 * reads the secure boot variable from PKS.
 * caller must free result
 */
static grub_err_t
read_sbvar_from_pks (const grub_uint8_t sbvarflags, const grub_uint8_t sbvartype,
                     grub_uint8_t **out, grub_size_t *outlen)
{
  *out = grub_malloc (pks_max_object_size);
  if (*out == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  return grub_ieee1275_pks_read_sbvar (sbvarflags, sbvartype, *out,
                                       pks_max_object_size, outlen);
}

/* Test the availability of PKS support. */
static grub_err_t
is_support_pks (void)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_ieee1275_cell_t missing = 0;

  rc = grub_ieee1275_test ("pks-max-object-size", &missing);
  if (rc != GRUB_ERR_NONE || (int) missing == -1)
    rc = grub_error (GRUB_ERR_BAD_FIRMWARE, "Firmware doesn't have PKS support!\n");
  else
    {
      rc = grub_ieee1275_pks_max_object_size (&pks_max_object_size);
      if (rc != GRUB_ERR_NONE)
        rc = grub_error (GRUB_ERR_BAD_NUMBER, "PKS support is there but it has zero objects!\n");
    }

  return rc;
}

/*
 * Retrieve the secure boot variable from PKS, unpacks it, read the esd
 * from ESL, and store the information in the pks sd buffer.
 */
static grub_err_t
read_secure_boot_variables (const grub_uint8_t sbvarflags, const grub_uint8_t sbvartype,
                            grub_pks_sd_t **pks_sd, grub_size_t *pks_sd_entries)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_uint8_t *esl_data = NULL;
  grub_size_t esl_data_size = 0;

  rc = read_sbvar_from_pks (sbvarflags, sbvartype, &esl_data, &esl_data_size);
  /*
   * at this point we have SB_VERSION, so any error is worth
   * at least some user-visible info
   */
  if (rc != GRUB_ERR_NONE)
    rc = grub_error (rc, "secure boot variable %s reading (%d)",
                     (sbvartype == DB ? "db" : "dbx"), rc);
  else if (esl_data_size != 0)
    rc = pks_sd_from_esl ((const grub_uint8_t *) esl_data, esl_data_size,
                          pks_sd, pks_sd_entries);
  grub_free (esl_data);

  return rc;
}

/* reads secure boot version (SB_VERSION) and it supports following
 * SB_VERSION
 * 1 - PKS
 * 0 - static key (embeded key)
 */
static grub_err_t
get_secure_boot_version (void)
{
  grub_err_t rc = GRUB_ERR_NONE;
  grub_uint8_t *data = NULL;
  grub_size_t len = 0, policy = 0;

  rc = read_sbversion_from_pks (&data, &len, &policy);
  if (rc != GRUB_ERR_NONE)
    rc = grub_error (GRUB_ERR_READ_ERROR, "SB version read failed! (%d)\n", rc);
  else if (len != 1 || (*data >= 2))
    rc = grub_error (GRUB_ERR_BAD_NUMBER, "found unexpected SB version! (%d)\n", *data);

  if (rc != GRUB_ERR_NONE)
    {
      grub_printf ("Switch to Static Key!\n");
      if (grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
        grub_fatal ("Secure Boot locked down");
    }
  else
    grub_pks_use_keystore = *data;

  grub_free (data);

  return rc;
}

/* Free allocated memory */
void
grub_pks_free_keystore (void)
{
  grub_size_t i = 0;

  for (i = 0; i < grub_pks_keystore.db_entries; i++)
    grub_free (grub_pks_keystore.db[i].data);

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    grub_free (grub_pks_keystore.dbx[i].data);

  grub_free (grub_pks_keystore.db);
  grub_free (grub_pks_keystore.dbx);
  grub_memset (&grub_pks_keystore, 0, sizeof (grub_pks_t));
}

/* Initialization of the Platform Keystore */
grub_err_t
grub_pks_keystore_init (void)
{
  grub_err_t rc = GRUB_ERR_NONE;

  grub_dprintf ("ieee1275", "trying to load Platform Keystore\n");

  rc = is_support_pks ();
  if (rc != GRUB_ERR_NONE)
    {
      grub_printf ("Switch to Static Key!\n");
      return rc;
    }

  /* SB_VERSION */
  rc = get_secure_boot_version ();
  if (rc != GRUB_ERR_NONE)
    return rc;

  if (grub_pks_use_keystore)
    {
      grub_memset (&grub_pks_keystore, 0, sizeof (grub_pks_t));
      /* DB */
      rc = read_secure_boot_variables (0, DB, &grub_pks_keystore.db, &grub_pks_keystore.db_entries);
      if (rc == PKS_OBJECT_NOT_FOUND)
        {
          rc = GRUB_ERR_NONE;
          /*
           * DB variable won't be available by default in PKS.
           * So, it will load the Default Keys from ELF Note
           */
          grub_pks_keystore.use_static_keys = true;
        }

      if (rc == GRUB_ERR_NONE)
        {
          /* DBX */
          rc = read_secure_boot_variables (0, DBX, &grub_pks_keystore.dbx, &grub_pks_keystore.dbx_entries);
          if (rc == PKS_OBJECT_NOT_FOUND)
            {
              grub_dprintf ("ieee1275", "dbx is not found in PKS\n");
              rc = GRUB_ERR_NONE;
            }
        }

    }

  if (rc != GRUB_ERR_NONE)
    grub_pks_free_keystore ();

  return rc;
}
