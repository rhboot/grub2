/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022  Free Software Foundation, Inc.
 *  Copyright (C) 2022  IBM Corporation
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
 *
 *  IBM vTPM support code.
 */

#include <grub/err.h>
#include <grub/types.h>
#include <grub/tpm.h>
#include <grub/ieee1275/ieee1275.h>
#include <grub/mm.h>
#include <grub/misc.h>

static grub_ieee1275_ihandle_t tpm_ihandle;
static grub_uint8_t tpm_version;

#define IEEE1275_IHANDLE_INVALID ((grub_ieee1275_ihandle_t) 0)

static void
tpm_get_tpm_version (void)
{
  grub_ieee1275_phandle_t vtpm;
  char buffer[20];

  if (!grub_ieee1275_finddevice ("/vdevice/vtpm", &vtpm) &&
      !grub_ieee1275_get_property (vtpm, "compatible", buffer,
				   sizeof (buffer), NULL) &&
      !grub_strcmp (buffer, "IBM,vtpm20"))
    tpm_version = 2;
}

static grub_err_t
tpm_init (void)
{
  static int init_success = 0;

  if (!init_success)
    {
      if (grub_ieee1275_open ("/vdevice/vtpm", &tpm_ihandle) < 0)
	{
	  tpm_ihandle = IEEE1275_IHANDLE_INVALID;
	  return GRUB_ERR_UNKNOWN_DEVICE;
	}

      init_success = 1;

      tpm_get_tpm_version ();
    }

  return GRUB_ERR_NONE;
}

static int
ibmvtpm_2hash_ext_log (grub_uint8_t pcrindex,
		       grub_uint32_t eventtype,
		       const char *description,
		       grub_size_t description_size,
		       void *buf, grub_size_t size)
{
  struct tpm_2hash_ext_log
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t method;
    grub_ieee1275_cell_t ihandle;
    grub_ieee1275_cell_t size;
    grub_ieee1275_cell_t buf;
    grub_ieee1275_cell_t description_size;
    grub_ieee1275_cell_t description;
    grub_ieee1275_cell_t eventtype;
    grub_ieee1275_cell_t pcrindex;
    grub_ieee1275_cell_t catch_result;
    grub_ieee1275_cell_t rc;
  };
  struct tpm_2hash_ext_log args;

  INIT_IEEE1275_COMMON (&args.common, "call-method", 8, 2);
  args.method = (grub_ieee1275_cell_t) "2hash-ext-log";
  args.ihandle = tpm_ihandle;
  args.pcrindex = pcrindex;
  args.eventtype = eventtype;
  args.description = (grub_ieee1275_cell_t) description;
  args.description_size = description_size;
  args.buf = (grub_ieee1275_cell_t) buf;
  args.size = (grub_ieee1275_cell_t) size;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  /*
   * catch_result is set if firmware does not support 2hash-ext-log
   * rc is GRUB_IEEE1275_CELL_FALSE (0) on failure
   */
  if ((args.catch_result) || args.rc == GRUB_IEEE1275_CELL_FALSE)
    return -1;

  return 0;
}

static grub_err_t
tpm2_log_event (unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		const char *description)
{
  static int error_displayed = 0;
  int rc;

  rc = ibmvtpm_2hash_ext_log (pcr, EV_IPL,
			      description, grub_strlen(description) + 1,
			      buf, size);
  if (rc && !error_displayed)
    {
      error_displayed++;
      return grub_error (GRUB_ERR_BAD_DEVICE,
			 "2HASH-EXT-LOG failed: Firmware is likely too old.\n");
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm_measure (unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		  const char *description)
{
  grub_dprintf ("tpm", "log_event, pcr = %d, size = 0x%" PRIxGRUB_SIZE ", %s\n",
		pcr, size, description);

  if (tpm_version == 2)
    return tpm2_log_event (buf, size, pcr, description);

  return GRUB_ERR_NONE;
}

int
grub_tpm_present (void)
{
  /*
   * Call tpm_init() "late" rather than from GRUB_MOD_INIT() so that device nodes
   * can be found.
   */
  return tpm_init() == GRUB_ERR_NONE;
}
