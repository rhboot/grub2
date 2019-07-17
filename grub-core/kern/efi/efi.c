/* efi.c - generic EFI support */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/console_control.h>
#include <grub/efi/pe32.h>
#include <grub/time.h>
#include <grub/term.h>
#include <grub/kernel.h>
#include <grub/mm.h>
#include <grub/loader.h>

/* The handle of GRUB itself. Filled in by the startup code.  */
grub_efi_handle_t grub_efi_image_handle;

/* The pointer to a system table. Filled in by the startup code.  */
grub_efi_system_table_t *grub_efi_system_table;

static grub_efi_guid_t console_control_guid = GRUB_EFI_CONSOLE_CONTROL_GUID;
static grub_efi_guid_t loaded_image_guid = GRUB_EFI_LOADED_IMAGE_GUID;
static grub_efi_guid_t device_path_guid = GRUB_EFI_DEVICE_PATH_GUID;

void *
grub_efi_locate_protocol (grub_efi_guid_t *protocol, void *registration)
{
  void *interface;
  grub_efi_status_t status;

  status = efi_call_3 (grub_efi_system_table->boot_services->locate_protocol,
                       protocol, registration, &interface);
  if (status != GRUB_EFI_SUCCESS)
    return 0;

  return interface;
}

/* Return the array of handles which meet the requirement. If successful,
   the number of handles is stored in NUM_HANDLES. The array is allocated
   from the heap.  */
grub_efi_handle_t *
grub_efi_locate_handle (grub_efi_locate_search_type_t search_type,
			grub_efi_guid_t *protocol,
			void *search_key,
			grub_efi_uintn_t *num_handles)
{
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;
  grub_efi_handle_t *buffer;
  grub_efi_uintn_t buffer_size = 8 * sizeof (grub_efi_handle_t);

  buffer = grub_malloc (buffer_size);
  if (! buffer)
    return 0;

  b = grub_efi_system_table->boot_services;
  status = efi_call_5 (b->locate_handle, search_type, protocol, search_key,
			     &buffer_size, buffer);
  if (status == GRUB_EFI_BUFFER_TOO_SMALL)
    {
      grub_free (buffer);
      buffer = grub_malloc (buffer_size);
      if (! buffer)
	return 0;

      status = efi_call_5 (b->locate_handle, search_type, protocol, search_key,
				 &buffer_size, buffer);
    }

  if (status != GRUB_EFI_SUCCESS)
    {
      grub_free (buffer);
      return 0;
    }

  *num_handles = buffer_size / sizeof (grub_efi_handle_t);
  return buffer;
}

void *
grub_efi_open_protocol (grub_efi_handle_t handle,
			grub_efi_guid_t *protocol,
			grub_efi_uint32_t attributes)
{
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;
  void *interface;

  b = grub_efi_system_table->boot_services;
  status = efi_call_6 (b->open_protocol, handle,
		       protocol,
		       &interface,
		       grub_efi_image_handle,
		       0,
		       attributes);
  if (status != GRUB_EFI_SUCCESS)
    return 0;

  return interface;
}

int
grub_efi_set_text_mode (int on)
{
  grub_efi_console_control_protocol_t *c;
  grub_efi_screen_mode_t mode, new_mode;

  c = grub_efi_locate_protocol (&console_control_guid, 0);
  if (! c)
    /* No console control protocol instance available, assume it is
       already in text mode. */
    return 1;

  if (efi_call_4 (c->get_mode, c, &mode, 0, 0) != GRUB_EFI_SUCCESS)
    return 0;

  new_mode = on ? GRUB_EFI_SCREEN_TEXT : GRUB_EFI_SCREEN_GRAPHICS;
  if (mode != new_mode)
    if (efi_call_2 (c->set_mode, c, new_mode) != GRUB_EFI_SUCCESS)
      return 0;

  return 1;
}

void
grub_efi_stall (grub_efi_uintn_t microseconds)
{
  efi_call_1 (grub_efi_system_table->boot_services->stall, microseconds);
}

grub_efi_loaded_image_t *
grub_efi_get_loaded_image (grub_efi_handle_t image_handle)
{
  return grub_efi_open_protocol (image_handle,
				 &loaded_image_guid,
				 GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
}

void
grub_reboot (void)
{
  grub_machine_fini (GRUB_LOADER_FLAG_NORETURN |
		     GRUB_LOADER_FLAG_EFI_KEEP_ALLOCATED_MEMORY);
  efi_call_4 (grub_efi_system_table->runtime_services->reset_system,
              GRUB_EFI_RESET_COLD, GRUB_EFI_SUCCESS, 0, NULL);
  for (;;) ;
}

void
grub_exit (void)
{
  grub_machine_fini (GRUB_LOADER_FLAG_NORETURN);
  efi_call_4 (grub_efi_system_table->boot_services->exit,
              grub_efi_image_handle, GRUB_EFI_SUCCESS, 0, 0);
  for (;;) ;
}

grub_err_t
grub_efi_set_virtual_address_map (grub_efi_uintn_t memory_map_size,
				  grub_efi_uintn_t descriptor_size,
				  grub_efi_uint32_t descriptor_version,
				  grub_efi_memory_descriptor_t *virtual_map)
{
  grub_efi_runtime_services_t *r;
  grub_efi_status_t status;

  r = grub_efi_system_table->runtime_services;
  status = efi_call_4 (r->set_virtual_address_map, memory_map_size,
		       descriptor_size, descriptor_version, virtual_map);

  if (status == GRUB_EFI_SUCCESS)
    return GRUB_ERR_NONE;

  return grub_error (GRUB_ERR_IO, "set_virtual_address_map failed");
}

grub_err_t
grub_efi_set_variable(const char *var, const grub_efi_guid_t *guid,
		      void *data, grub_size_t datasize)
{
  grub_efi_status_t status;
  grub_efi_runtime_services_t *r;
  grub_efi_char16_t *var16;
  grub_size_t len, len16;

  len = grub_strlen (var);
  len16 = len * GRUB_MAX_UTF16_PER_UTF8;
  var16 = grub_calloc (len16 + 1, sizeof (var16[0]));
  if (!var16)
    return grub_errno;
  len16 = grub_utf8_to_utf16 (var16, len16, (grub_uint8_t *) var, len, NULL);
  var16[len16] = 0;

  r = grub_efi_system_table->runtime_services;

  status = efi_call_5 (r->set_variable, var16, guid, 
		       (GRUB_EFI_VARIABLE_NON_VOLATILE
			| GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS
			| GRUB_EFI_VARIABLE_RUNTIME_ACCESS),
		       datasize, data);
  grub_free (var16);
  if (status == GRUB_EFI_SUCCESS)
    return GRUB_ERR_NONE;

  return grub_error (GRUB_ERR_IO, "could not set EFI variable `%s'", var);
}

void *
grub_efi_get_variable (const char *var, const grub_efi_guid_t *guid,
		       grub_size_t *datasize_out)
{
  grub_efi_status_t status;
  grub_efi_uintn_t datasize = 0;
  grub_efi_runtime_services_t *r;
  grub_efi_char16_t *var16;
  void *data;
  grub_size_t len, len16;

  *datasize_out = 0;

  len = grub_strlen (var);
  len16 = len * GRUB_MAX_UTF16_PER_UTF8;
  var16 = grub_calloc (len16 + 1, sizeof (var16[0]));
  if (!var16)
    return NULL;
  len16 = grub_utf8_to_utf16 (var16, len16, (grub_uint8_t *) var, len, NULL);
  var16[len16] = 0;

  r = grub_efi_system_table->runtime_services;

  status = efi_call_5 (r->get_variable, var16, guid, NULL, &datasize, NULL);

  if (status != GRUB_EFI_BUFFER_TOO_SMALL || !datasize)
    {
      grub_free (var16);
      return NULL;
    }

  data = grub_malloc (datasize);
  if (!data)
    {
      grub_free (var16);
      return NULL;
    }

  status = efi_call_5 (r->get_variable, var16, guid, NULL, &datasize, data);
  grub_free (var16);

  if (status == GRUB_EFI_SUCCESS)
    {
      *datasize_out = datasize;
      return data;
    }

  grub_free (data);
  return NULL;
}

#pragma GCC diagnostic ignored "-Wcast-align"

/* Search the mods section from the PE32/PE32+ image. This code uses
   a PE32 header, but should work with PE32+ as well.  */
grub_addr_t
grub_efi_modules_addr (void)
{
  grub_efi_loaded_image_t *image;
  struct grub_pe32_header *header;
  struct grub_pe32_coff_header *coff_header;
  struct grub_pe32_section_table *sections;
  struct grub_pe32_section_table *section;
  struct grub_module_info *info;
  grub_uint16_t i;

  image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (! image)
    return 0;

  header = image->image_base;
  coff_header = &(header->coff_header);
  sections
    = (struct grub_pe32_section_table *) ((char *) coff_header
					  + sizeof (*coff_header)
					  + coff_header->optional_header_size);

  for (i = 0, section = sections;
       i < coff_header->num_sections;
       i++, section++)
    {
      if (grub_strcmp (section->name, "mods") == 0)
	break;
    }

  if (i == coff_header->num_sections)
    {
      grub_dprintf("sections", "section %d is last section; invalid.\n", i);
      return 0;
    }

  info = (struct grub_module_info *) ((char *) image->image_base
				      + section->virtual_address);
  if (section->name[0] != '.' && info->magic != GRUB_MODULE_MAGIC)
    {
      grub_dprintf("sections",
		   "section %d has bad magic %08x, should be %08x\n",
		   i, info->magic, GRUB_MODULE_MAGIC);
      return 0;
    }

  grub_dprintf("sections", "returning section info for section %d: \"%s\"\n",
	       i, section->name);
  return (grub_addr_t) info;
}

#pragma GCC diagnostic error "-Wcast-align"

char *
grub_efi_get_filename (grub_efi_device_path_t *dp0)
{
  char *name = 0, *p, *pi;
  grub_size_t filesize = 0;
  grub_efi_device_path_t *dp;

  if (!dp0)
    return NULL;

  dp = dp0;

  while (dp)
    {
      grub_efi_uint8_t type = GRUB_EFI_DEVICE_PATH_TYPE (dp);
      grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);

      if (type == GRUB_EFI_END_DEVICE_PATH_TYPE)
	break;
      if (type == GRUB_EFI_MEDIA_DEVICE_PATH_TYPE
	       && subtype == GRUB_EFI_FILE_PATH_DEVICE_PATH_SUBTYPE)
	{
	  grub_efi_uint16_t len = GRUB_EFI_DEVICE_PATH_LENGTH (dp);

	  if (len < 4)
	    {
	      grub_error (GRUB_ERR_OUT_OF_RANGE,
			  "malformed EFI Device Path node has length=%d", len);
	      return NULL;
	    }
	  len = (len - 4) / sizeof (grub_efi_char16_t);
	  filesize += GRUB_MAX_UTF8_PER_UTF16 * len + 2;
	}

      dp = GRUB_EFI_NEXT_DEVICE_PATH (dp);
    }

  if (!filesize)
    return NULL;

  dp = dp0;

  p = name = grub_malloc (filesize);
  if (!name)
    return NULL;

  while (dp)
    {
      grub_efi_uint8_t type = GRUB_EFI_DEVICE_PATH_TYPE (dp);
      grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);

      if (type == GRUB_EFI_END_DEVICE_PATH_TYPE)
	break;
      else if (type == GRUB_EFI_MEDIA_DEVICE_PATH_TYPE
	       && subtype == GRUB_EFI_FILE_PATH_DEVICE_PATH_SUBTYPE)
	{
	  grub_efi_file_path_device_path_t *fp;
	  grub_efi_uint16_t len;
	  grub_efi_char16_t *dup_name;

	  *p++ = '/';

	  len = GRUB_EFI_DEVICE_PATH_LENGTH (dp);
	  if (len < 4)
	    {
	      grub_error (GRUB_ERR_OUT_OF_RANGE,
			  "malformed EFI Device Path node has length=%d", len);
	      return NULL;
	    }

	  len = (len - 4) / sizeof (grub_efi_char16_t);
	  fp = (grub_efi_file_path_device_path_t *) dp;
	  /* According to EFI spec Path Name is NULL terminated */
	  while (len > 0 && fp->path_name[len - 1] == 0)
	    len--;

	  dup_name = grub_calloc (len, sizeof (*dup_name));
	  if (!dup_name)
	    {
	      grub_free (name);
	      return NULL;
	    }
	  p = (char *) grub_utf16_to_utf8 ((unsigned char *) p,
					    grub_memcpy (dup_name, fp->path_name, len * sizeof (*dup_name)),
					    len);
	  grub_free (dup_name);
	}

      dp = GRUB_EFI_NEXT_DEVICE_PATH (dp);
    }

  *p = '\0';

  for (pi = name, p = name; *pi;)
    {
      /* EFI breaks paths with backslashes.  */
      if (*pi == '\\' || *pi == '/')
	{
	  *p++ = '/';
	  while (*pi == '\\' || *pi == '/')
	    pi++;
	  continue;
	}
      *p++ = *pi++;
    }
  *p = '\0';

  return name;
}

grub_efi_device_path_t *
grub_efi_get_device_path (grub_efi_handle_t handle)
{
  return grub_efi_open_protocol (handle, &device_path_guid,
				 GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
}

/* Return the device path node right before the end node.  */
grub_efi_device_path_t *
grub_efi_find_last_device_path (const grub_efi_device_path_t *dp)
{
  grub_efi_device_path_t *next, *p;

  if (GRUB_EFI_END_ENTIRE_DEVICE_PATH (dp))
    return 0;

  for (p = (grub_efi_device_path_t *) dp, next = GRUB_EFI_NEXT_DEVICE_PATH (p);
       ! GRUB_EFI_END_ENTIRE_DEVICE_PATH (next);
       p = next, next = GRUB_EFI_NEXT_DEVICE_PATH (next))
    ;

  return p;
}

/* Duplicate a device path.  */
grub_efi_device_path_t *
grub_efi_duplicate_device_path (const grub_efi_device_path_t *dp)
{
  grub_efi_device_path_t *p;
  grub_size_t total_size = 0;

  for (p = (grub_efi_device_path_t *) dp;
       ;
       p = GRUB_EFI_NEXT_DEVICE_PATH (p))
    {
      grub_size_t len = GRUB_EFI_DEVICE_PATH_LENGTH (p);

      /*
       * In the event that we find a node that's completely garbage, for
       * example if we get to 0x7f 0x01 0x02 0x00 ... (EndInstance with a size
       * of 2), GRUB_EFI_END_ENTIRE_DEVICE_PATH() will be true and
       * GRUB_EFI_NEXT_DEVICE_PATH() will return NULL, so we won't continue,
       * and neither should our consumers, but there won't be any error raised
       * even though the device path is junk.
       *
       * This keeps us from passing junk down back to our caller.
       */
      if (len < 4)
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE,
		      "malformed EFI Device Path node has length=%d", len);
	  return NULL;
	}

      total_size += len;
      if (GRUB_EFI_END_ENTIRE_DEVICE_PATH (p))
	break;
    }

  p = grub_malloc (total_size);
  if (! p)
    return 0;

  grub_memcpy (p, dp, total_size);
  return p;
}

grub_ssize_t
grub_efi_fmt_guid (char *str, grub_size_t len, grub_efi_guid_t *guid)
{
  return grub_snprintf (str, len,
			"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			(unsigned) guid->data1,
			(unsigned) guid->data2,
			(unsigned) guid->data3,
			(unsigned) guid->data4[0],
			(unsigned) guid->data4[1],
			(unsigned) guid->data4[2],
			(unsigned) guid->data4[3],
			(unsigned) guid->data4[4],
			(unsigned) guid->data4[5],
			(unsigned) guid->data4[6],
			(unsigned) guid->data4[7]);
}

static inline void
prep_str(char *instr, grub_size_t inlen, grub_size_t offset,
	 char **outstr, grub_size_t *outlen)
{
  grub_ssize_t tmplen;

  if (instr)
    *outstr = instr + offset;
  else
    *outstr = instr;

  /*
   * There is no possible way these limits are meaningfully correct, but this
   * will keep us from also having an arithmetic overflow that causes us to
   * pass a negative length around.
   */
  if (inlen > GRUB_SSIZE_MAX)
    tmplen = GRUB_SSIZE_MAX;
  else
    tmplen = inlen;

  if (offset > GRUB_SSIZE_MAX)
    offset = GRUB_SSIZE_MAX;

  tmplen -= offset;
  if (tmplen < 0)
    tmplen = 0;

  *outlen = tmplen;
}

static grub_ssize_t
fmt_unknown_device_path(char *instr, grub_size_t inlen, const char *typename,
			grub_efi_device_path_t *dp)
{
  grub_uint32_t data_len = GRUB_EFI_DEVICE_PATH_LENGTH (dp) - sizeof (*dp);
  grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);
  grub_efi_uint8_t type = GRUB_EFI_DEVICE_PATH_TYPE (dp);
  grub_ssize_t ret = 0, strsz;
  grub_uint8_t *data = (grub_uint8_t *)dp + sizeof (*dp);
  char *str;
  grub_size_t len;

  prep_str (instr, inlen, ret, &str, &len);
  ret = grub_snprintf(str, len, "/Unknown%s(0x%02hhx,0x%02hhx,0x%04hx",
		      typename, type, subtype, data_len);
  if (ret < 0)
    return ret;

  if (data_len > 0)
    {
      prep_str (instr, inlen, ret, &str, &len);
      strsz = grub_snprintf (str, len, ",");
      if (strsz < 0)
	return strsz;
      ret += strsz;
    }

  for (grub_size_t i = 0; i < data_len; i++)
    {
      prep_str (instr, inlen, ret, &str, &len);
      strsz = grub_snprintf (str, len, "%02hhx", data[i]);
      if (strsz < 0)
       return strsz;
      ret += strsz;
    }

  prep_str (instr, inlen, ret, &str, &len);
  strsz = grub_snprintf (str, len, ")");
  if (strsz < 0)
    return strsz;
  ret += strsz;

  return ret;
}

static grub_ssize_t
fmt_vendor_device_path (char *instr, grub_size_t inlen, const char *type,
                       grub_efi_vendor_device_path_t *vendor)
{
  grub_uint32_t vendor_data_len = vendor->header.length - sizeof (*vendor);
  grub_ssize_t ret = 0, strsz;
  char *str;
  grub_size_t len;

  prep_str (instr, inlen, ret, &str, &len);
  ret = grub_snprintf (str, len, "/%sVendor(%pG", type, &vendor->vendor_guid);
  if (ret < 0)
    return ret;

  if (vendor->header.length > sizeof (*vendor))
    {
      grub_uint32_t i;

      prep_str (instr, inlen, ret, &str, &len);
      strsz = grub_snprintf (str, len, ",");
      if (strsz < 0)
	return strsz;
      ret += strsz;

      for (i = 0; i < vendor_data_len; i++)
	{
	  prep_str (instr, inlen, ret, &str, &len);
	  strsz = grub_snprintf (str, len, "%02hhx",
				 vendor->vendor_defined_data[i]);
	  if (strsz < 0)
	    return strsz;
	  ret += strsz;
	}
    }

  prep_str (instr, inlen, ret, &str, &len);
  strsz = grub_snprintf (str, len, ")");
  if (strsz < 0)
    return strsz;
  ret += strsz;

  return ret;
}

static grub_ssize_t
fmt_end_device_path (char *str, grub_size_t len,
		     grub_efi_device_path_t *dp, int *stop)
{
  grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);
  grub_ssize_t ret;

  switch (subtype)
    {
    case GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE:
      grub_dprintf ("efidp", "end entire device path\n");
      ret = 0;
      *stop = 1;
      break;
    case GRUB_EFI_END_THIS_DEVICE_PATH_SUBTYPE:
      grub_dprintf ("efidp", "end this device path\n");
      ret = grub_snprintf (str, len, ",");
      *stop = 0;
      break;
    default:
      ret = fmt_unknown_device_path (str, len, "End", dp);
      *stop = 1;
      break;
    }

  return ret;
}

static grub_ssize_t
fmt_hw_device_path (char *str, grub_size_t len,
		    grub_efi_device_path_t *dp)
{
  grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);
  grub_ssize_t ret;

  switch (subtype)
    {
    case GRUB_EFI_PCI_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_pci_device_path_t *pci;

	grub_dprintf ("efidp", "pci device path\n");
	pci = (grub_efi_pci_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/PCI(%x,%x)",
			     (unsigned) pci->function, (unsigned) pci->device);
      }
      break;
    case GRUB_EFI_PCCARD_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_pccard_device_path_t *pccard;

	grub_dprintf ("efidp", "pccard device path\n");
	pccard = (grub_efi_pccard_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/PCCARD(%x)",
			     (unsigned) pccard->function);
      }
      break;
    case GRUB_EFI_MEMORY_MAPPED_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_memory_mapped_device_path_t *mmapped;

	grub_dprintf ("efidp", "memory mapped device path\n");
	mmapped = (grub_efi_memory_mapped_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/MMap(%x,%llx,%llx)",
			     (unsigned) mmapped->memory_type,
			     (unsigned long long) mmapped->start_address,
			     (unsigned long long) mmapped->end_address);
      }
      break;
    case GRUB_EFI_VENDOR_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_vendor_device_path_t *vendor;

	grub_dprintf ("efidp", "vendor hw device path\n");
	vendor = (grub_efi_vendor_device_path_t *) dp;
	ret = fmt_vendor_device_path (str, len, "Hardware", vendor);
      }
      break;
    case GRUB_EFI_CONTROLLER_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_controller_device_path_t *controller;

	grub_dprintf ("efidp", "controller device path\n");
	controller = (grub_efi_controller_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/Ctrl(%x)",
			     (unsigned) controller->controller_number);
      }
      break;
    default:
      grub_dprintf ("efidp", "unknown hw device path\n");
      ret = fmt_unknown_device_path (str, len, "HW", dp);
      break;
    }

  return ret;
}

static grub_ssize_t
fmt_expanded_acpi_device_path (char *instr, grub_size_t inlen,
			       grub_efi_expanded_acpi_device_path_t *eacpi)
{
  grub_efi_device_path_t *dp;
  grub_ssize_t sz, ret = 0;
  char *str;
  grub_size_t len;

  dp = (grub_efi_device_path_t *) eacpi;

  prep_str (instr, inlen, ret, &str, &len);
  sz = grub_snprintf (str, len, "/ACPI(");
  if (sz < 0)
    return sz;
  ret = sz;

  prep_str (instr, inlen, ret, &str, &len);
  if (GRUB_EFI_EXPANDED_ACPI_HIDSTR (dp)[0] == '\0')
    sz = grub_snprintf (str, len, "%x,", (unsigned) eacpi->hid);
  else
    sz = grub_snprintf (str, len, "%s,", GRUB_EFI_EXPANDED_ACPI_HIDSTR (dp));
  if (sz < 0)
    return sz;
  ret += sz;

  prep_str (instr, inlen, ret, &str, &len);
  if (GRUB_EFI_EXPANDED_ACPI_UIDSTR (dp)[0] == '\0')
    sz = grub_snprintf (str, len, "%x,", (unsigned) eacpi->uid);
  else
    sz = grub_snprintf (str, len, "%s,", GRUB_EFI_EXPANDED_ACPI_UIDSTR (dp));
  if (sz < 0)
    return sz;
  ret += sz;

  prep_str (instr, inlen, ret, &str, &len);
  if (GRUB_EFI_EXPANDED_ACPI_CIDSTR (dp)[0] == '\0')
    sz = grub_snprintf (str, len, "%x)", (unsigned) eacpi->cid);
  else
    sz = grub_snprintf (str, len, "%s)", GRUB_EFI_EXPANDED_ACPI_CIDSTR (dp));
  if (sz < 0)
    return sz;
  ret += sz;

  return ret;
}

static grub_ssize_t
fmt_acpi_device_path (char *str, grub_size_t len,
		      grub_efi_device_path_t *dp)
{
  grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);
  grub_ssize_t ret;

  switch (subtype)
    {
    case GRUB_EFI_ACPI_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_acpi_device_path_t *acpi;

	grub_dprintf ("efidp", "acpi device path\n");
	acpi = (grub_efi_acpi_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/ACPI(%x,%x)",
			     (unsigned) acpi->hid, (unsigned) acpi->uid);
      }
      break;
    case GRUB_EFI_EXPANDED_ACPI_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_expanded_acpi_device_path_t *eacpi;

	grub_dprintf ("efidp", "eacpi device path\n");
	eacpi = (grub_efi_expanded_acpi_device_path_t *) dp;
	ret = fmt_expanded_acpi_device_path(str, len, eacpi);
      }
      break;
    default:
      ret = fmt_unknown_device_path (str, len, "ACPI", dp);
      break;
    }

  return ret;
}

static grub_ssize_t
fmt_ipv4_device_path (char *instr, grub_size_t inlen,
		      grub_efi_ipv4_device_path_t *ipv4)
{
  grub_efi_device_path_t *dp;
  grub_ssize_t sz, ret = 0;
  char *str;
  grub_size_t len;

  dp = (grub_efi_device_path_t *) ipv4;

  prep_str (instr, inlen, ret, &str, &len);
  sz = grub_snprintf (str, len, "/IPv4(%u.%u.%u.%u,%u.%u.%u.%u,%u,%u,%x,%x",
		      (unsigned) ipv4->local_ip_address[0],
		      (unsigned) ipv4->local_ip_address[1],
		      (unsigned) ipv4->local_ip_address[2],
		      (unsigned) ipv4->local_ip_address[3],
		      (unsigned) ipv4->remote_ip_address[0],
		      (unsigned) ipv4->remote_ip_address[1],
		      (unsigned) ipv4->remote_ip_address[2],
		      (unsigned) ipv4->remote_ip_address[3],
		      (unsigned) ipv4->local_port,
		      (unsigned) ipv4->remote_port,
		      (unsigned) ipv4->protocol,
		      (unsigned) ipv4->static_ip_address);
  if (sz < 0)
    return sz;
  ret = sz;

  if (GRUB_EFI_DEVICE_PATH_LENGTH (dp) == sizeof (*ipv4))
    {
      prep_str (instr, inlen, ret, &str, &len);
      sz = grub_snprintf (str, len, ",%u.%u.%u.%u,%u.%u.%u.%u",
			  (unsigned) ipv4->gateway_ip_address[0],
			  (unsigned) ipv4->gateway_ip_address[1],
			  (unsigned) ipv4->gateway_ip_address[2],
			  (unsigned) ipv4->gateway_ip_address[3],
			  (unsigned) ipv4->subnet_mask[0],
			  (unsigned) ipv4->subnet_mask[1],
			  (unsigned) ipv4->subnet_mask[2],
			  (unsigned) ipv4->subnet_mask[3]);
      if (sz < 0)
	return sz;
      ret += sz;
    }

  prep_str (instr, inlen, ret, &str, &len);
  sz = grub_snprintf (str, len, ")");
  if (sz < 0)
    return sz;
  ret += sz;

  return ret;
}

static grub_ssize_t
fmt_ipv6_device_path (char *instr, grub_size_t inlen,
		      grub_efi_ipv6_device_path_t *ipv6)
{
  grub_efi_device_path_t *dp;
  grub_ssize_t sz, ret = 0;
  char *str;
  grub_size_t len;

  dp = (grub_efi_device_path_t *) ipv6;

  prep_str (instr, inlen, ret, &str, &len);
  sz = grub_snprintf (str, len,
		      "/IPv6(%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x,%u,%u,%x,%x",
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[0]),
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[1]),
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[2]),
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[3]),
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[4]),
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[5]),
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[6]),
		      (unsigned) grub_be_to_cpu16 (ipv6->local_ip_address[7]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[0]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[1]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[2]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[3]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[4]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[5]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[6]),
		      (unsigned) grub_be_to_cpu16 (ipv6->remote_ip_address[7]),
		      (unsigned) ipv6->local_port,
		      (unsigned) ipv6->remote_port,
		      (unsigned) ipv6->protocol,
		      (unsigned) ipv6->static_ip_address);
  if (sz < 0)
    return sz;
  ret = sz;

  if (GRUB_EFI_DEVICE_PATH_LENGTH (dp) == sizeof (*ipv6))
    {
      prep_str (instr, inlen, ret, &str, &len);
      sz = grub_snprintf (str, len,
			  ",%u,%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			  (unsigned) ipv6->prefix_length,
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[0]),
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[1]),
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[2]),
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[3]),
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[4]),
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[5]),
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[6]),
			  (unsigned) grub_be_to_cpu16 (ipv6->gateway_ip_address[7]));
      if (sz < 0)
	return sz;
      ret += sz;
    }

  sz = grub_snprintf (str + ret, len - ret, ")");
  if (sz < 0)
    return sz;
  ret += sz;

  return ret;
}

static grub_ssize_t
fmt_dns_device_path (char *str, grub_size_t len,
		     grub_efi_dns_device_path_t *dns)
{
  grub_ssize_t ret;
  if (dns->is_ipv6)
    {
      ret = grub_snprintf (str, len,
			   "/DNS(%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x)",
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[0]) >> 16),
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[0])),
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[1]) >> 16),
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[1])),
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[2]) >> 16),
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[2])),
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[3]) >> 16),
			   (grub_uint16_t)(grub_be_to_cpu32(dns->dns_server_ip[0].addr[3])));
    }
  else
    {
      ret = grub_snprintf (str, len, "/DNS(%d.%d.%d.%d)",
			   dns->dns_server_ip[0].v4.addr[0],
			   dns->dns_server_ip[0].v4.addr[1],
			   dns->dns_server_ip[0].v4.addr[2],
			   dns->dns_server_ip[0].v4.addr[3]);
    }

  return ret;
}

static grub_ssize_t
fmt_msg_device_path (char *str, grub_size_t len,
		     grub_efi_device_path_t *dp)
{
  grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);
  grub_ssize_t ret;

  switch (subtype)
    {
    case GRUB_EFI_ATAPI_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_atapi_device_path_t *atapi;

	grub_dprintf ("efidp", "atapi device path\n");
	atapi = (grub_efi_atapi_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/ATAPI(%x,%x,%x)",
			     (unsigned) atapi->primary_secondary,
			     (unsigned) atapi->slave_master,
			     (unsigned) atapi->lun);
      }
      break;

    case GRUB_EFI_SCSI_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_scsi_device_path_t *scsi;

	grub_dprintf ("efidp", "scsi device path\n");
	scsi = (grub_efi_scsi_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/SCSI(%x,%x)",
			     (unsigned) scsi->pun, (unsigned) scsi->lun);
      }
      break;

    case GRUB_EFI_FIBRE_CHANNEL_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_fibre_channel_device_path_t *fc;

	grub_dprintf ("efidp", "fc device path\n");
	fc = (grub_efi_fibre_channel_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/FibreChannel(%llx,%llx)",
			     (unsigned long long) fc->wwn,
			     (unsigned long long) fc->lun);
      }
      break;

    case GRUB_EFI_1394_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_1394_device_path_t *firewire;

	grub_dprintf ("efidp", "1394 device path\n");
	firewire = (grub_efi_1394_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/1394(%llx)",
			     (unsigned long long) firewire->guid);
      }
      break;

    case GRUB_EFI_USB_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_usb_device_path_t *usb;

	grub_dprintf ("efidp", "usb device path\n");
	usb = (grub_efi_usb_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/USB(%x,%x)",
			     (unsigned) usb->parent_port_number,
			     (unsigned) usb->usb_interface);
      }
      break;

    case GRUB_EFI_USB_CLASS_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_usb_class_device_path_t *usb_class;

	grub_dprintf ("efidp", "usb_class device path\n");
	usb_class = (grub_efi_usb_class_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/USBClass(%x,%x,%x,%x,%x)",
			     (unsigned) usb_class->vendor_id,
			     (unsigned) usb_class->product_id,
			     (unsigned) usb_class->device_class,
			     (unsigned) usb_class->device_subclass,
			     (unsigned) usb_class->device_protocol);
      }
      break;

    case GRUB_EFI_I2O_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_i2o_device_path_t *i2o;

	grub_dprintf ("efidp", "i2o device path\n");
	i2o = (grub_efi_i2o_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/I2O(%x)", (unsigned) i2o->tid);
      }
      break;

    case GRUB_EFI_MAC_ADDRESS_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_mac_address_device_path_t *mac;

	grub_dprintf ("efidp", "mac device path\n");
	mac = (grub_efi_mac_address_device_path_t *) dp;
	ret = grub_snprintf (str, len,
			     "/MacAddr(%02x:%02x:%02x:%02x:%02x:%02x,%x)",
			     (unsigned) mac->mac_address[0],
			     (unsigned) mac->mac_address[1],
			     (unsigned) mac->mac_address[2],
			     (unsigned) mac->mac_address[3],
			     (unsigned) mac->mac_address[4],
			     (unsigned) mac->mac_address[5],
			     (unsigned) mac->if_type);
      }
      break;

    case GRUB_EFI_IPV4_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_ipv4_device_path_t *ipv4;

	grub_dprintf ("efidp", "ipv4 device path\n");
	ipv4 = (grub_efi_ipv4_device_path_t *) dp;
	ret = fmt_ipv4_device_path(str, len, ipv4);
      }
      break;

    case GRUB_EFI_IPV6_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_ipv6_device_path_t *ipv6;

	grub_dprintf ("efidp", "ipv6 device path\n");
	ipv6 = (grub_efi_ipv6_device_path_t *) dp;
	ret = fmt_ipv6_device_path(str, len, ipv6);
      }
      break;

    case GRUB_EFI_INFINIBAND_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_infiniband_device_path_t *ib;

	grub_dprintf ("efidp", "ib device path\n");
	ib = (grub_efi_infiniband_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/InfiniBand(%x,%llx,%llx,%llx)",
			     (unsigned) ib->port_gid[0], /* XXX */
			     (unsigned long long) ib->remote_id,
			     (unsigned long long) ib->target_port_id,
			     (unsigned long long) ib->device_id);
      }
      break;

    case GRUB_EFI_UART_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_uart_device_path_t *uart;

	grub_dprintf ("efidp", "uart device path\n");
	uart = (grub_efi_uart_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/UART(%llu,%u,%x,%x)",
			     (unsigned long long) uart->baud_rate,
			     uart->data_bits, uart->parity, uart->stop_bits);
      }
      break;

    case GRUB_EFI_SATA_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_sata_device_path_t *sata;

	grub_dprintf ("efidp", "sata device path\n");
	sata = (grub_efi_sata_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/Sata(%x,%x,%x)",
			     sata->hba_port, sata->multiplier_port,
			     sata->lun);
      }
      break;

    case GRUB_EFI_VENDOR_MESSAGING_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_vendor_device_path_t *vendor;

	grub_dprintf ("efidp", "vendor device path\n");
	vendor = (grub_efi_vendor_device_path_t *) dp;
	ret = fmt_vendor_device_path (str, len, "Messaging", vendor);
      }
      break;

    case GRUB_EFI_URI_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_uri_device_path_t *uri;

	grub_dprintf ("efidp", "uri device path\n");
	uri = (grub_efi_uri_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/URI(%s)", uri->uri);
      }
      break;

    case GRUB_EFI_SD_DEVICE_PATH_SUBTYPE:
    case GRUB_EFI_EMMC_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_sd_device_path_t *sd;

	grub_dprintf ("efidp", "sd/emmc device path\n");
	sd = (grub_efi_sd_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/%s(%d)",
		  subtype == GRUB_EFI_SD_DEVICE_PATH_SUBTYPE ? "SD" : "eMMC",
		  sd->slot);
      }
      break;

    case GRUB_EFI_DNS_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_dns_device_path_t *dns;

	grub_dprintf ("efidp", "dns device path\n");
	dns = (grub_efi_dns_device_path_t *) dp;
	ret = fmt_dns_device_path(str, len, dns);
      }
      break;

    default:
      grub_dprintf ("efidp", "unknown device path\n");
      ret = fmt_unknown_device_path (str, len, "Messaging", dp);
      break;
    }

  return ret;
}

static grub_ssize_t
fmt_file_device_path (char *str, grub_size_t len,
		      grub_efi_device_path_t *dp)
{
  grub_efi_file_path_device_path_t *fp;
  grub_uint8_t *buf, *end;
  grub_efi_uint16_t dpsz = GRUB_EFI_DEVICE_PATH_LENGTH (dp);
  grub_ssize_t ret = 0;

  fp = (grub_efi_file_path_device_path_t *) dp;
  buf = grub_malloc ((dpsz - 4) * 2 + 1);
  if (!buf)
    {
      ret = -1;
      return ret;
    }

  end = grub_utf16_to_utf8 (buf, fp->path_name,
			    (dpsz - 4) / sizeof (grub_efi_char16_t));
  *end = '\0';
  ret = grub_snprintf (str, len, "/File(%s)", buf);
  grub_free (buf);
  return ret;
}

static grub_ssize_t
fmt_media_device_path (char *str, grub_size_t len,
		       grub_efi_device_path_t *dp)
{
  grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);
  grub_ssize_t ret;

  switch (subtype)
    {
    case GRUB_EFI_HARD_DRIVE_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_hard_drive_device_path_t *hd;

	grub_dprintf ("efidp", "hd device path\n");
	hd = (grub_efi_hard_drive_device_path_t *) dp;
	ret = grub_snprintf (str, len,
			     "/HD(%u,%llx,%llx,%02x%02x%02x%02x%02x%02x%02x%02x,%x,%x)",
			     hd->partition_number,
			     (unsigned long long) hd->partition_start,
			     (unsigned long long) hd->partition_size,
			     (unsigned) hd->partition_signature[0],
			     (unsigned) hd->partition_signature[1],
			     (unsigned) hd->partition_signature[2],
			     (unsigned) hd->partition_signature[3],
			     (unsigned) hd->partition_signature[4],
			     (unsigned) hd->partition_signature[5],
			     (unsigned) hd->partition_signature[6],
			     (unsigned) hd->partition_signature[7],
			     (unsigned) hd->partmap_type,
			     (unsigned) hd->signature_type);
      }
      break;

    case GRUB_EFI_CDROM_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_cdrom_device_path_t *cd;

	grub_dprintf ("efidp", "cdrom device path\n");
	cd  = (grub_efi_cdrom_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/CD(%u,%llx,%llx)",
			     cd->boot_entry,
			     (unsigned long long) cd->partition_start,
			     (unsigned long long) cd->partition_size);
      }
      break;

    case GRUB_EFI_VENDOR_MEDIA_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_vendor_device_path_t *vendor;

	grub_dprintf ("efidp", "vendor media device path\n");
	vendor = (grub_efi_vendor_device_path_t *) dp;
	ret = fmt_vendor_device_path (str, len, "Media", vendor);
      }
      break;

    case GRUB_EFI_FILE_PATH_DEVICE_PATH_SUBTYPE:
      {
	grub_dprintf ("efidp", "file device path\n");

	ret = fmt_file_device_path (str, len, dp);
      }
      break;

    case GRUB_EFI_PROTOCOL_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_protocol_device_path_t *proto;

	grub_dprintf ("efidp", "protocol device path\n");
	proto = (grub_efi_protocol_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/Protocol(%pG)", &proto->guid);
      }
      break;
    default:
      grub_dprintf ("efidp", "unknown media device path\n");
      ret = fmt_unknown_device_path (str, len, "Media", dp);
      break;
    }

  return ret;
}

static grub_ssize_t
fmt_bios_device_path (char *str, grub_size_t len,
		      grub_efi_device_path_t *dp)
{
  grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);
  grub_ssize_t ret;

  switch (subtype)
    {
    case GRUB_EFI_BIOS_DEVICE_PATH_SUBTYPE:
      {
	grub_efi_bios_device_path_t *bios;

	grub_dprintf ("efidp", "bios device path\n");
	bios = (grub_efi_bios_device_path_t *) dp;
	ret = grub_snprintf (str, len, "/BIOS(%x,%x,%s)",
			     (unsigned) bios->device_type,
			     (unsigned) bios->status_flags,
			     (char *) (dp + 1));
      }
      break;
    default:
      grub_dprintf ("efidp", "unknown bios device path\n");
      ret = fmt_unknown_device_path (str, len, "BIOS", dp);
      break;
    }

  return ret;
}

/* Format the chain of Device Path nodes. This is mainly for debugging. */
grub_ssize_t
grub_efi_fmt_device_path (char *str, grub_size_t len,
			  grub_efi_device_path_t *dp)
{
  grub_ssize_t ret = 0, strsz;
  int stop = 0;

  while (!stop)
    {
      grub_efi_uint8_t type = GRUB_EFI_DEVICE_PATH_TYPE (dp);

      switch (type)
	{
	case GRUB_EFI_END_DEVICE_PATH_TYPE:
	  grub_dprintf ("efidp", "end device path\n");
	  strsz = fmt_end_device_path (str, len, dp, &stop);
	  break;

	case GRUB_EFI_HARDWARE_DEVICE_PATH_TYPE:
	  grub_dprintf ("efidp", "hw device path\n");
	  strsz = fmt_hw_device_path (str, len, dp);
	  break;

	case GRUB_EFI_ACPI_DEVICE_PATH_TYPE:
	  grub_dprintf ("efidp", "acpi device path\n");
	  strsz = fmt_acpi_device_path (str, len, dp);
	  break;

	case GRUB_EFI_MESSAGING_DEVICE_PATH_TYPE:
	  grub_dprintf ("efidp", "msg device path\n");
	  strsz = fmt_msg_device_path (str, len, dp);
	  break;

	case GRUB_EFI_MEDIA_DEVICE_PATH_TYPE:
	  grub_dprintf ("efidp", "media device path\n");
	  strsz = fmt_media_device_path (str, len, dp);
	  break;

	case GRUB_EFI_BIOS_DEVICE_PATH_TYPE:
	  grub_dprintf ("efidp", "bios device path\n");
	  strsz = fmt_bios_device_path (str, len, dp);
	  break;

	default:
	  grub_dprintf ("efidp", "unknown device path\n");
	  strsz = fmt_unknown_device_path (str, len, "Type", dp);
	  break;
	}

      if (strsz < 0)
	return strsz;

      dp = GRUB_EFI_NEXT_DEVICE_PATH (dp);
      ret += strsz;
      if (str)
	{
	  str += strsz;
	  if (len)
	    len -= strsz;
	}
    }

  return ret;
}

/* Compare device paths.  */
int
grub_efi_compare_device_paths (const grub_efi_device_path_t *dp1,
			       const grub_efi_device_path_t *dp2)
{
  if (! dp1 || ! dp2)
    /* Return non-zero.  */
    return 1;

  if (dp1 == dp2)
    return 0;

  while (GRUB_EFI_DEVICE_PATH_VALID (dp1) && GRUB_EFI_DEVICE_PATH_VALID (dp2))
    {
      grub_efi_uint8_t type1, type2;
      grub_efi_uint8_t subtype1, subtype2;
      grub_efi_uint16_t len1, len2;
      int ret;

      type1 = GRUB_EFI_DEVICE_PATH_TYPE (dp1);
      type2 = GRUB_EFI_DEVICE_PATH_TYPE (dp2);

      if (type1 != type2)
	return (int) type2 - (int) type1;

      subtype1 = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp1);
      subtype2 = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp2);

      if (subtype1 != subtype2)
	return (int) subtype1 - (int) subtype2;

      len1 = GRUB_EFI_DEVICE_PATH_LENGTH (dp1);
      len2 = GRUB_EFI_DEVICE_PATH_LENGTH (dp2);

      if (len1 != len2)
	return (int) len1 - (int) len2;

      ret = grub_memcmp (dp1, dp2, len1);
      if (ret != 0)
	return ret;

      if (GRUB_EFI_END_ENTIRE_DEVICE_PATH (dp1))
	break;

      dp1 = (grub_efi_device_path_t *) ((char *) dp1 + len1);
      dp2 = (grub_efi_device_path_t *) ((char *) dp2 + len2);
    }

  /*
   * There's no "right" answer here, but we probably don't want to call a valid
   * dp and an invalid dp equal, so pick one way or the other.
   */
  if (GRUB_EFI_DEVICE_PATH_VALID (dp1) && !GRUB_EFI_DEVICE_PATH_VALID (dp2))
    return 1;
  else if (!GRUB_EFI_DEVICE_PATH_VALID (dp1) && GRUB_EFI_DEVICE_PATH_VALID (dp2))
    return -1;

  return 0;
}

static struct {
    const grub_efi_status_t status;
    const char * const desc;
} grub_efi_error_code_table[] = {
	{  GRUB_EFI_SUCCESS,                "Success"},
	{  GRUB_EFI_LOAD_ERROR,             "Load Error"},
	{  GRUB_EFI_INVALID_PARAMETER,      "Invalid Parameter"},
	{  GRUB_EFI_UNSUPPORTED,            "Unsupported"},
	{  GRUB_EFI_BAD_BUFFER_SIZE,        "Bad Buffer Size"},
	{  GRUB_EFI_BUFFER_TOO_SMALL,       "Buffer Too Small"},
	{  GRUB_EFI_NOT_READY,              "Not Ready"},
	{  GRUB_EFI_DEVICE_ERROR,           "Device Error"},
	{  GRUB_EFI_WRITE_PROTECTED,        "Write Protected"},
	{  GRUB_EFI_OUT_OF_RESOURCES,       "Out of Resources"},
	{  GRUB_EFI_VOLUME_CORRUPTED,       "Volume Corrupt"},
	{  GRUB_EFI_VOLUME_FULL,            "Volume Full"},
	{  GRUB_EFI_NO_MEDIA,               "No Media"},
	{  GRUB_EFI_MEDIA_CHANGED,          "Media changed"},
	{  GRUB_EFI_NOT_FOUND,              "Not Found"},
	{  GRUB_EFI_ACCESS_DENIED,          "Access Denied"},
	{  GRUB_EFI_NO_RESPONSE,            "No Response"},
	{  GRUB_EFI_NO_MAPPING,             "No mapping"},
	{  GRUB_EFI_TIMEOUT,                "Time out"},
	{  GRUB_EFI_NOT_STARTED,            "Not started"},
	{  GRUB_EFI_ALREADY_STARTED,        "Already started"},
	{  GRUB_EFI_ABORTED,                "Aborted"},
	{  GRUB_EFI_ICMP_ERROR,             "ICMP Error"},
	{  GRUB_EFI_TFTP_ERROR,             "TFTP Error"},
	{  GRUB_EFI_PROTOCOL_ERROR,         "Protocol Error"},
	{  GRUB_EFI_INCOMPATIBLE_VERSION,   "Incompatible Version"},
	{  GRUB_EFI_SECURITY_VIOLATION,     "Security Policy Violation"},
	{  GRUB_EFI_CRC_ERROR,              "CRC Error"},
	{  GRUB_EFI_END_OF_MEDIA,           "End of Media"},
	{  GRUB_EFI_END_OF_FILE,            "End of File"},
	{  GRUB_EFI_INVALID_LANGUAGE,       "Invalid Languages"},
	{  GRUB_EFI_COMPROMISED_DATA,       "Compromised Data"},

	// warnings
	{  GRUB_EFI_WARN_UNKNOWN_GLYPH,     "Warning Unknown Glyph"},
	{  GRUB_EFI_WARN_DELETE_FAILURE,    "Warning Delete Failure"},
	{  GRUB_EFI_WARN_WRITE_FAILURE,     "Warning Write Failure"},
	{  GRUB_EFI_WARN_BUFFER_TOO_SMALL,  "Warning Buffer Too Small"},
	{  0, NULL}
};

static const char * const unknown_error = "Unknown Error";

const char *
grub_real_efi_status_to_str (grub_efi_status_t status)
{
  int i;

  for (i = 0; grub_efi_error_code_table[i].desc != NULL; i++)
    if (grub_efi_error_code_table[i].status == status)
      return (char *)grub_efi_error_code_table[i].desc;

  return unknown_error;
}
