/* chainloader.c - boot another boot loader */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2004,2006,2007,2008  Free Software Foundation, Inc.
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

/* TODO: support load options.  */

#include <grub/loader.h>
#include <grub/file.h>
#include <grub/err.h>
#include <grub/device.h>
#include <grub/disk.h>
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/disk.h>
#include <grub/efi/pe32.h>
#include <grub/efi/linux.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/net.h>
#if defined (__i386__) || defined (__x86_64__)
#include <grub/macho.h>
#include <grub/i386/macho.h>
#endif

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;

static grub_efi_physical_address_t address;
static grub_efi_uintn_t pages;
static grub_ssize_t fsize;
static grub_efi_device_path_t *file_path;
static grub_efi_handle_t image_handle;
static grub_efi_char16_t *cmdline;
static grub_ssize_t cmdline_len;
static grub_efi_handle_t dev_handle;

static grub_efi_status_t (*entry_point) (grub_efi_handle_t image_handle, grub_efi_system_table_t *system_table);

static grub_err_t
grub_chainloader_unload (void)
{
  grub_efi_boot_services_t *b;

  b = grub_efi_system_table->boot_services;
  efi_call_1 (b->unload_image, image_handle);
  efi_call_2 (b->free_pages, address, pages);

  grub_free (file_path);
  grub_free (cmdline);
  cmdline = 0;
  file_path = 0;
  dev_handle = 0;

  grub_dl_unref (my_mod);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_chainloader_boot (void)
{
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;
  grub_efi_uintn_t exit_data_size;
  grub_efi_char16_t *exit_data = NULL;

  b = grub_efi_system_table->boot_services;
  status = efi_call_3 (b->start_image, image_handle, &exit_data_size, &exit_data);
  if (status != GRUB_EFI_SUCCESS)
    {
      if (exit_data)
	{
	  char *buf;

	  buf = grub_malloc (exit_data_size * 4 + 1);
	  if (buf)
	    {
	      *grub_utf16_to_utf8 ((grub_uint8_t *) buf,
				   exit_data, exit_data_size) = 0;

	      grub_error (GRUB_ERR_BAD_OS, buf);
	      grub_free (buf);
	    }
	}
      else
	grub_error (GRUB_ERR_BAD_OS, "unknown error");
    }

  if (exit_data)
    efi_call_1 (b->free_pool, exit_data);

  grub_loader_unset ();

  return grub_errno;
}

static void
copy_file_path (grub_efi_file_path_device_path_t *fp,
		const char *str, grub_efi_uint16_t len)
{
  grub_efi_char16_t *p;
  grub_efi_uint16_t size;

  fp->header.type = GRUB_EFI_MEDIA_DEVICE_PATH_TYPE;
  fp->header.subtype = GRUB_EFI_FILE_PATH_DEVICE_PATH_SUBTYPE;

  size = grub_utf8_to_utf16 (fp->path_name, len * GRUB_MAX_UTF16_PER_UTF8,
			     (const grub_uint8_t *) str, len, 0);
  for (p = fp->path_name; p < fp->path_name + size; p++)
    if (*p == '/')
      *p = '\\';

  /* File Path is NULL terminated */
  fp->path_name[size++] = '\0';
  fp->header.length = size * sizeof (grub_efi_char16_t) + sizeof (*fp);
}

static grub_efi_device_path_t *
make_file_path (grub_efi_device_path_t *dp, const char *filename)
{
  char *dir_start;
  char *dir_end;
  grub_size_t size;
  grub_efi_device_path_t *d;

  dir_start = grub_strchr (filename, ')');
  if (! dir_start)
    dir_start = (char *) filename;
  else
    dir_start++;

  dir_end = grub_strrchr (dir_start, '/');
  if (! dir_end)
    {
      grub_error (GRUB_ERR_BAD_FILENAME, "invalid EFI file path");
      return 0;
    }

  size = 0;
  d = dp;
  while (1)
    {
      size += GRUB_EFI_DEVICE_PATH_LENGTH (d);
      if ((GRUB_EFI_END_ENTIRE_DEVICE_PATH (d)))
	break;
      d = GRUB_EFI_NEXT_DEVICE_PATH (d);
    }

  /* File Path is NULL terminated. Allocate space for 2 extra characters */
  /* FIXME why we split path in two components? */
  file_path = grub_malloc (size
			   + ((grub_strlen (dir_start) + 2)
			      * GRUB_MAX_UTF16_PER_UTF8
			      * sizeof (grub_efi_char16_t))
			   + sizeof (grub_efi_file_path_device_path_t) * 2);
  if (! file_path)
    return 0;

  grub_memcpy (file_path, dp, size);

  /* Fill the file path for the directory.  */
  d = (grub_efi_device_path_t *) ((char *) file_path
				  + ((char *) d - (char *) dp));
  copy_file_path ((grub_efi_file_path_device_path_t *) d,
		  dir_start, dir_end - dir_start);

  /* Fill the file path for the file.  */
  d = GRUB_EFI_NEXT_DEVICE_PATH (d);
  copy_file_path ((grub_efi_file_path_device_path_t *) d,
		  dir_end + 1, grub_strlen (dir_end + 1));

  /* Fill the end of device path nodes.  */
  d = GRUB_EFI_NEXT_DEVICE_PATH (d);
  d->type = GRUB_EFI_END_DEVICE_PATH_TYPE;
  d->subtype = GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
  d->length = sizeof (*d);

  return file_path;
}

#define SHIM_LOCK_GUID \
  { 0x605dab50, 0xe046, 0x4300, { 0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23 } }

typedef union
{
  struct grub_pe32_header_32 pe32;
  struct grub_pe32_header_64 pe32plus;
} grub_pe_header_t;

struct pe_coff_loader_image_context
{
  grub_efi_uint64_t image_address;
  grub_efi_uint64_t image_size;
  grub_efi_uint64_t entry_point;
  grub_efi_uintn_t size_of_headers;
  grub_efi_uint16_t image_type;
  grub_efi_uint16_t number_of_sections;
  grub_efi_uint32_t section_alignment;
  struct grub_pe32_section_table *first_section;
  struct grub_pe32_data_directory *reloc_dir;
  struct grub_pe32_data_directory *sec_dir;
  grub_efi_uint64_t number_of_rva_and_sizes;
  grub_pe_header_t *pe_hdr;
};

typedef struct pe_coff_loader_image_context pe_coff_loader_image_context_t;

struct grub_efi_shim_lock
{
  grub_efi_status_t (*verify)(void *buffer,
                              grub_efi_uint32_t size);
  grub_efi_status_t (*hash)(void *data,
                            grub_efi_int32_t datasize,
                            pe_coff_loader_image_context_t *context,
                            grub_efi_uint8_t *sha256hash,
                            grub_efi_uint8_t *sha1hash);
  grub_efi_status_t (*context)(void *data,
                               grub_efi_uint32_t size,
                               pe_coff_loader_image_context_t *context);
};

typedef struct grub_efi_shim_lock grub_efi_shim_lock_t;

static grub_efi_boolean_t
read_header (void *data, grub_efi_uint32_t size,
	     pe_coff_loader_image_context_t *context)
{
  grub_efi_guid_t guid = SHIM_LOCK_GUID;
  grub_efi_shim_lock_t *shim_lock;
  grub_efi_status_t status;

  shim_lock = grub_efi_locate_protocol (&guid, NULL);
  if (!shim_lock)
    {
      grub_dprintf ("chain", "no shim lock protocol");
      return 0;
    }

  status = shim_lock->context (data, size, context);

  if (status == GRUB_EFI_SUCCESS)
    {
      grub_dprintf ("chain", "context success\n");
      return 1;
    }

  switch (status)
    {
      case GRUB_EFI_UNSUPPORTED:
      grub_error (GRUB_ERR_BAD_ARGUMENT, "context error unsupported");
      break;
      case GRUB_EFI_INVALID_PARAMETER:
      grub_error (GRUB_ERR_BAD_ARGUMENT, "context error invalid parameter");
      break;
      default:
      grub_error (GRUB_ERR_BAD_ARGUMENT, "context error code");
      break;
    }

  return -1;
}

static void*
image_address (void *image, grub_efi_uint64_t sz, grub_efi_uint64_t adr)
{
  if (adr > sz)
    return NULL;

  return ((grub_uint8_t*)image + adr);
}

static int
image_is_64_bit (grub_pe_header_t *pe_hdr)
{
  /* .Magic is the same offset in all cases */
  if (pe_hdr->pe32plus.optional_header.magic == GRUB_PE32_PE64_MAGIC)
    return 1;
  return 0;
}

static const grub_uint16_t machine_type __attribute__((__unused__)) =
#if defined(__x86_64__)
  GRUB_PE32_MACHINE_X86_64;
#elif defined(__aarch64__)
  GRUB_PE32_MACHINE_ARM64;
#elif defined(__arm__)
  GRUB_PE32_MACHINE_ARMTHUMB_MIXED;
#elif defined(__i386__) || defined(__i486__) || defined(__i686__)
  GRUB_PE32_MACHINE_I386;
#elif defined(__ia64__)
  GRUB_PE32_MACHINE_IA64;
#else
#error this architecture is not supported by grub2
#endif

static grub_efi_status_t
relocate_coff (pe_coff_loader_image_context_t *context,
	       struct grub_pe32_section_table *section,
	       void *orig, void *data)
{
  struct grub_pe32_data_directory *reloc_base, *reloc_base_end;
  grub_efi_uint64_t adjust;
  struct grub_pe32_fixup_block *reloc, *reloc_end;
  char *fixup, *fixup_base, *fixup_data = NULL;
  grub_efi_uint16_t *fixup_16;
  grub_efi_uint32_t *fixup_32;
  grub_efi_uint64_t *fixup_64;
  grub_efi_uint64_t size = context->image_size;
  void *image_end = (char *)orig + size;
  int n = 0;

  if (image_is_64_bit (context->pe_hdr))
    context->pe_hdr->pe32plus.optional_header.image_base =
      (grub_uint64_t)(unsigned long)data;
  else
    context->pe_hdr->pe32.optional_header.image_base =
      (grub_uint32_t)(unsigned long)data;

  /* Alright, so here's how this works:
   *
   * context->reloc_dir gives us two things:
   * - the VA the table of base relocation blocks are (maybe) to be
   *   mapped at (reloc_dir->rva)
   * - the virtual size (reloc_dir->size)
   *
   * The .reloc section (section here) gives us some other things:
   * - the name! kind of. (section->name)
   * - the virtual size (section->virtual_size), which should be the same
   *   as RelocDir->Size
   * - the virtual address (section->virtual_address)
   * - the file section size (section->raw_data_size), which is
   *   a multiple of optional_header->file_alignment.  Only useful for image
   *   validation, not really useful for iteration bounds.
   * - the file address (section->raw_data_offset)
   * - a bunch of stuff we don't use that's 0 in our binaries usually
   * - Flags (section->characteristics)
   *
   * and then the thing that's actually at the file address is an array
   * of struct grub_pe32_fixup_block structs with some values packed behind
   * them.  The block_size field of this structure includes the
   * structure itself, and adding it to that structure's address will
   * yield the next entry in the array.
   */

  reloc_base = image_address (orig, size, section->raw_data_offset);
  reloc_base_end = image_address (orig, size, section->raw_data_offset
				  + section->virtual_size);

  grub_dprintf ("chain", "relocate_coff(): reloc_base %p reloc_base_end %p\n",
		reloc_base, reloc_base_end);

  if (!reloc_base && !reloc_base_end)
    return GRUB_EFI_SUCCESS;

  if (!reloc_base || !reloc_base_end)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, "Reloc table overflows binary");
      return GRUB_EFI_UNSUPPORTED;
    }

  adjust = (grub_uint64_t)(grub_efi_uintn_t)data - context->image_address;
  if (adjust == 0)
    return GRUB_EFI_SUCCESS;

  while (reloc_base < reloc_base_end)
    {
      grub_uint16_t *entry;
      reloc = (struct grub_pe32_fixup_block *)((char*)reloc_base);

      if ((reloc_base->size == 0) ||
	  (reloc_base->size > context->reloc_dir->size))
	{
	  grub_error (GRUB_ERR_BAD_ARGUMENT,
		      "Reloc %d block size %d is invalid\n", n,
		      reloc_base->size);
	  return GRUB_EFI_UNSUPPORTED;
	}

      entry = &reloc->entries[0];
      reloc_end = (struct grub_pe32_fixup_block *)
	((char *)reloc_base + reloc_base->size);

      if ((void *)reloc_end < orig || (void *)reloc_end > image_end)
        {
          grub_error (GRUB_ERR_BAD_ARGUMENT, "Reloc entry %d overflows binary",
		      n);
          return GRUB_EFI_UNSUPPORTED;
        }

      fixup_base = image_address(data, size, reloc_base->rva);

      if (!fixup_base)
        {
          grub_error (GRUB_ERR_BAD_ARGUMENT, "Reloc %d Invalid fixupbase", n);
          return GRUB_EFI_UNSUPPORTED;
        }

      while ((void *)entry < (void *)reloc_end)
        {
          fixup = fixup_base + (*entry & 0xFFF);
          switch ((*entry) >> 12)
            {
              case GRUB_PE32_REL_BASED_ABSOLUTE:
                break;
              case GRUB_PE32_REL_BASED_HIGH:
                fixup_16 = (grub_uint16_t *)fixup;
                *fixup_16 = (grub_uint16_t)
		  (*fixup_16 + ((grub_uint16_t)((grub_uint32_t)adjust >> 16)));
                if (fixup_data != NULL)
                  {
                    *(grub_uint16_t *) fixup_data = *fixup_16;
                    fixup_data = fixup_data + sizeof (grub_uint16_t);
                  }
                break;
              case GRUB_PE32_REL_BASED_LOW:
                fixup_16 = (grub_uint16_t *)fixup;
                *fixup_16 = (grub_uint16_t) (*fixup_16 + (grub_uint16_t)adjust);
                if (fixup_data != NULL)
                  {
                    *(grub_uint16_t *) fixup_data = *fixup_16;
                    fixup_data = fixup_data + sizeof (grub_uint16_t);
                  }
                break;
              case GRUB_PE32_REL_BASED_HIGHLOW:
                fixup_32 = (grub_uint32_t *)fixup;
                *fixup_32 = *fixup_32 + (grub_uint32_t)adjust;
                if (fixup_data != NULL)
                  {
                    fixup_data = (char *)ALIGN_UP ((grub_addr_t)fixup_data, sizeof (grub_uint32_t));
                    *(grub_uint32_t *) fixup_data = *fixup_32;
                    fixup_data += sizeof (grub_uint32_t);
                  }
                break;
              case GRUB_PE32_REL_BASED_DIR64:
                fixup_64 = (grub_uint64_t *)fixup;
                *fixup_64 = *fixup_64 + (grub_uint64_t)adjust;
                if (fixup_data != NULL)
                  {
                    fixup_data = (char *)ALIGN_UP ((grub_addr_t)fixup_data, sizeof (grub_uint64_t));
                    *(grub_uint64_t *) fixup_data = *fixup_64;
                    fixup_data += sizeof (grub_uint64_t);
                  }
                break;
              default:
                grub_error (GRUB_ERR_BAD_ARGUMENT,
			    "Reloc %d unknown relocation type %d",
			    n, (*entry) >> 12);
                return GRUB_EFI_UNSUPPORTED;
            }
          entry += 1;
        }
      reloc_base = (struct grub_pe32_data_directory *)reloc_end;
      n++;
    }

  return GRUB_EFI_SUCCESS;
}

static grub_efi_device_path_t *
grub_efi_get_media_file_path (grub_efi_device_path_t *dp)
{
  while (1)
    {
      grub_efi_uint8_t type = GRUB_EFI_DEVICE_PATH_TYPE (dp);
      grub_efi_uint8_t subtype = GRUB_EFI_DEVICE_PATH_SUBTYPE (dp);

      if (type == GRUB_EFI_END_DEVICE_PATH_TYPE)
        break;
      else if (type == GRUB_EFI_MEDIA_DEVICE_PATH_TYPE
            && subtype == GRUB_EFI_FILE_PATH_DEVICE_PATH_SUBTYPE)
      return dp;

      dp = GRUB_EFI_NEXT_DEVICE_PATH (dp);
    }

    return NULL;
}

static grub_efi_boolean_t
handle_image (void *data, grub_efi_uint32_t datasize)
{
  grub_efi_boot_services_t *b;
  grub_efi_loaded_image_t *li, li_bak;
  grub_efi_status_t efi_status;
  char *buffer = NULL;
  char *buffer_aligned = NULL;
  grub_efi_uint32_t i;
  struct grub_pe32_section_table *section;
  char *base, *end;
  pe_coff_loader_image_context_t context;
  grub_uint32_t section_alignment;
  grub_uint32_t buffer_size;
  int found_entry_point = 0;
  int rc;

  b = grub_efi_system_table->boot_services;

  rc = read_header (data, datasize, &context);
  if (rc < 0)
    {
      grub_dprintf ("chain", "Failed to read header\n");
      goto error_exit;
    }
  else if (rc == 0)
    {
      grub_dprintf ("chain", "Secure Boot is not enabled\n");
      return 0;
    }
  else
    {
      grub_dprintf ("chain", "Header read without error\n");
    }

  /*
   * The spec says, uselessly, of SectionAlignment:
   * =====
   * The alignment (in bytes) of sections when they are loaded into
   * memory. It must be greater than or equal to FileAlignment. The
   * default is the page size for the architecture.
   * =====
   * Which doesn't tell you whose responsibility it is to enforce the
   * "default", or when.  It implies that the value in the field must
   * be > FileAlignment (also poorly defined), but it appears visual
   * studio will happily write 512 for FileAlignment (its default) and
   * 0 for SectionAlignment, intending to imply PAGE_SIZE.
   *
   * We only support one page size, so if it's zero, nerf it to 4096.
   */
  section_alignment = context.section_alignment;
  if (section_alignment == 0)
    section_alignment = 4096;

  buffer_size = context.image_size + section_alignment;
  grub_dprintf ("chain", "image size is %08"PRIxGRUB_UINT64_T", datasize is %08x\n",
	       context.image_size, datasize);

  efi_status = efi_call_3 (b->allocate_pool, GRUB_EFI_LOADER_DATA,
			   buffer_size, &buffer);

  if (efi_status != GRUB_EFI_SUCCESS)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto error_exit;
    }

  buffer_aligned = (char *)ALIGN_UP ((grub_addr_t)buffer, section_alignment);
  if (!buffer_aligned)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto error_exit;
    }

  grub_memcpy (buffer_aligned, data, context.size_of_headers);

  entry_point = image_address (buffer_aligned, context.image_size,
			       context.entry_point);

  grub_dprintf ("chain", "entry_point: %p\n", entry_point);
  if (!entry_point)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid entry point");
      goto error_exit;
    }

  char *reloc_base, *reloc_base_end;
  grub_dprintf ("chain", "reloc_dir: %p reloc_size: 0x%08x\n",
		(void *)(unsigned long)context.reloc_dir->rva,
		context.reloc_dir->size);
  reloc_base = image_address (buffer_aligned, context.image_size,
			      context.reloc_dir->rva);
  /* RelocBaseEnd here is the address of the last byte of the table */
  reloc_base_end = image_address (buffer_aligned, context.image_size,
				  context.reloc_dir->rva
				  + context.reloc_dir->size - 1);
  grub_dprintf ("chain", "reloc_base: %p reloc_base_end: %p\n",
		reloc_base, reloc_base_end);

  struct grub_pe32_section_table *reloc_section = NULL, fake_reloc_section;

  section = context.first_section;
  for (i = 0; i < context.number_of_sections; i++, section++)
    {
      char name[9];

      base = image_address (buffer_aligned, context.image_size,
			    section->virtual_address);
      end = image_address (buffer_aligned, context.image_size,
			   section->virtual_address + section->virtual_size -1);

      grub_strncpy(name, section->name, 9);
      name[8] = '\0';
      grub_dprintf ("chain", "Section %d \"%s\" at %p..%p\n", i,
		   name, base, end);

      if (end < base)
	{
	  grub_dprintf ("chain", " base is %p but end is %p... bad.\n",
		       base, end);
	  grub_error (GRUB_ERR_BAD_ARGUMENT,
		      "Image has invalid negative size");
	  goto error_exit;
	}

      if (section->virtual_address <= context.entry_point &&
	  (section->virtual_address + section->raw_data_size - 1)
	  > context.entry_point)
	{
	  found_entry_point++;
	  grub_dprintf ("chain", " section contains entry point\n");
	}

      /* We do want to process .reloc, but it's often marked
       * discardable, so we don't want to memcpy it. */
      if (grub_memcmp (section->name, ".reloc\0\0", 8) == 0)
	{
	  if (reloc_section)
	    {
	      grub_error (GRUB_ERR_BAD_ARGUMENT,
			  "Image has multiple relocation sections");
	      goto error_exit;
	    }

	  /* If it has nonzero sizes, and our bounds check
	   * made sense, and the VA and size match RelocDir's
	   * versions, then we believe in this section table. */
	  if (section->raw_data_size && section->virtual_size &&
	      base && end && reloc_base == base)
	    {
	      if (reloc_base_end == end)
		{
		  grub_dprintf ("chain", " section is relocation section\n");
		  reloc_section = section;
		}
	      else if (reloc_base_end && reloc_base_end < end)
	        {
		  /* Bogus virtual size in the reloc section -- RelocDir
		   * reported a smaller Base Relocation Directory. Decrease
		   * the section's virtual size so that it equal RelocDir's
		   * idea, but only for the purposes of relocate_coff(). */
		  grub_dprintf ("chain",
				" section is (overlong) relocation section\n");
		  grub_memcpy (&fake_reloc_section, section, sizeof *section);
		  fake_reloc_section.virtual_size -= (end - reloc_base_end);
		  reloc_section = &fake_reloc_section;
		}
	    }

	  if (!reloc_section)
	    {
	      grub_dprintf ("chain", " section is not reloc section?\n");
	      grub_dprintf ("chain", " rds: 0x%08x, vs: %08x\n",
			    section->raw_data_size, section->virtual_size);
	      grub_dprintf ("chain", " base: %p end: %p\n", base, end);
	      grub_dprintf ("chain", " reloc_base: %p reloc_base_end: %p\n",
			    reloc_base, reloc_base_end);
	    }
	}

      grub_dprintf ("chain", " Section characteristics are %08x\n",
		   section->characteristics);
      grub_dprintf ("chain", " Section virtual size: %08x\n",
		   section->virtual_size);
      grub_dprintf ("chain", " Section raw_data size: %08x\n",
		   section->raw_data_size);
      if (section->characteristics & GRUB_PE32_SCN_MEM_DISCARDABLE)
	{
	  grub_dprintf ("chain", " Discarding section\n");
	  continue;
	}

      if (!base || !end)
        {
	  grub_dprintf ("chain", " section is invalid\n");
          grub_error (GRUB_ERR_BAD_ARGUMENT, "Invalid section size");
          goto error_exit;
        }

      if (section->characteristics & GRUB_PE32_SCN_CNT_UNINITIALIZED_DATA)
	{
	  if (section->raw_data_size != 0)
	    grub_dprintf ("chain", " UNINITIALIZED_DATA section has data?\n");
	}
      else if (section->virtual_address < context.size_of_headers ||
	       section->raw_data_offset < context.size_of_headers)
	{
	  grub_error (GRUB_ERR_BAD_ARGUMENT,
		      "Section %d is inside image headers", i);
	  goto error_exit;
	}

      if (section->raw_data_size > 0)
	{
	  grub_dprintf ("chain", " copying 0x%08x bytes to %p\n",
			section->raw_data_size, base);
	  grub_memcpy (base,
		       (grub_efi_uint8_t*)data + section->raw_data_offset,
		       section->raw_data_size);
	}

      if (section->raw_data_size < section->virtual_size)
	{
	  grub_dprintf ("chain", " padding with 0x%08x bytes at %p\n",
			section->virtual_size - section->raw_data_size,
			base + section->raw_data_size);
	  grub_memset (base + section->raw_data_size, 0,
		       section->virtual_size - section->raw_data_size);
	}

      grub_dprintf ("chain", " finished section %s\n", name);
    }

  /* 5 == EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC */
  if (context.number_of_rva_and_sizes <= 5)
    {
      grub_dprintf ("chain", "image has no relocation entry\n");
      goto error_exit;
    }

  if (context.reloc_dir->size && reloc_section)
    {
      /* run the relocation fixups */
      efi_status = relocate_coff (&context, reloc_section, data,
				  buffer_aligned);

      if (efi_status != GRUB_EFI_SUCCESS)
	{
	  grub_error (GRUB_ERR_BAD_ARGUMENT, "relocation failed");
	  goto error_exit;
	}
    }

  if (!found_entry_point)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, "entry point is not within sections");
      goto error_exit;
    }
  if (found_entry_point > 1)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, "%d sections contain entry point",
		  found_entry_point);
      goto error_exit;
    }

  li = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (!li)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, "no loaded image available");
      goto error_exit;
    }

  grub_memcpy (&li_bak, li, sizeof (grub_efi_loaded_image_t));
  li->image_base = buffer_aligned;
  li->image_size = context.image_size;
  li->load_options = cmdline;
  li->load_options_size = cmdline_len;
  li->file_path = grub_efi_get_media_file_path (file_path);
  li->device_handle = dev_handle;
  if (!li->file_path)
    {
      grub_error (GRUB_ERR_UNKNOWN_DEVICE, "no matching file path found");
      goto error_exit;
    }

  grub_dprintf ("chain", "booting via entry point\n");
  efi_status = efi_call_2 (entry_point, grub_efi_image_handle,
			   grub_efi_system_table);

  grub_dprintf ("chain", "entry_point returned %ld\n", efi_status);
  grub_memcpy (li, &li_bak, sizeof (grub_efi_loaded_image_t));
  efi_status = efi_call_1 (b->free_pool, buffer);

  return 1;

error_exit:
  grub_dprintf ("chain", "error_exit: grub_errno: %d\n", grub_errno);
  if (buffer)
      efi_call_1 (b->free_pool, buffer);

  return 0;
}

static grub_err_t
grub_secureboot_chainloader_unload (void)
{
  grub_efi_boot_services_t *b;

  b = grub_efi_system_table->boot_services;
  efi_call_2 (b->free_pages, address, pages);
  grub_free (file_path);
  grub_free (cmdline);
  cmdline = 0;
  file_path = 0;
  dev_handle = 0;

  grub_dl_unref (my_mod);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_load_and_start_image(void *boot_image)
{
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;
  grub_efi_loaded_image_t *loaded_image;

  b = grub_efi_system_table->boot_services;

  status = efi_call_6 (b->load_image, 0, grub_efi_image_handle, file_path,
		       boot_image, fsize, &image_handle);
  if (status != GRUB_EFI_SUCCESS)
    {
      if (status == GRUB_EFI_OUT_OF_RESOURCES)
	grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of resources");
      else
	grub_error (GRUB_ERR_BAD_OS, "cannot load image");
      return -1;
    }

  /* LoadImage does not set a device handler when the image is
     loaded from memory, so it is necessary to set it explicitly here.
     This is a mess.  */
  loaded_image = grub_efi_get_loaded_image (image_handle);
  if (! loaded_image)
    {
      grub_error (GRUB_ERR_BAD_OS, "no loaded image available");
      return -1;
    }
  loaded_image->device_handle = dev_handle;

  if (cmdline)
    {
      loaded_image->load_options = cmdline;
      loaded_image->load_options_size = cmdline_len;
    }

  return 0;
}

static grub_err_t
grub_secureboot_chainloader_boot (void)
{
  int rc;
  rc = handle_image ((void *)(unsigned long)address, fsize);
  if (rc == 0)
    {
      grub_load_and_start_image((void *)(unsigned long)address);
    }

  grub_loader_unset ();
  return grub_errno;
}

static grub_err_t
grub_cmd_chainloader (grub_command_t cmd __attribute__ ((unused)),
		      int argc, char *argv[])
{
  grub_file_t file = 0;
  grub_efi_status_t status;
  grub_efi_boot_services_t *b;
  grub_device_t dev = 0;
  grub_efi_device_path_t *dp = 0;
  char *filename;
  void *boot_image = 0;
  int rc;

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
  filename = argv[0];

  grub_dl_ref (my_mod);

  /* Initialize some global variables.  */
  address = 0;
  image_handle = 0;
  file_path = 0;
  dev_handle = 0;

  b = grub_efi_system_table->boot_services;

  if (argc > 1)
    {
      int i;
      grub_efi_char16_t *p16;

      for (i = 1, cmdline_len = 0; i < argc; i++)
        cmdline_len += grub_strlen (argv[i]) + 1;

      cmdline_len *= sizeof (grub_efi_char16_t);
      cmdline = p16 = grub_malloc (cmdline_len);
      if (! cmdline)
        goto fail;

      for (i = 1; i < argc; i++)
        {
          char *p8;

          p8 = argv[i];
          while (*p8)
            *(p16++) = *(p8++);

          *(p16++) = ' ';
        }
      *(--p16) = 0;
    }

  file = grub_file_open (filename);
  if (! file)
    goto fail;

  /* Get the device path from filename. */
  char *devname = grub_file_get_device_name (filename);
  dev = grub_device_open (devname);
  if (devname)
    grub_free (devname);
  if (! dev)
    goto fail;

  if (dev->disk)
    dev_handle = grub_efidisk_get_device_handle (dev->disk);
  else if (dev->net && dev->net->server)
    {
      grub_net_network_level_address_t addr;
      struct grub_net_network_level_interface *inf;
      grub_net_network_level_address_t gateway;
      grub_err_t err;

      err = grub_net_resolve_address (dev->net->server, &addr);
      if (err)
	goto fail;

      err = grub_net_route_address (addr, &gateway, &inf);
      if (err)
	goto fail;

      dev_handle = grub_efinet_get_device_handle (inf->card);
    }

  if (dev_handle)
    dp = grub_efi_get_device_path (dev_handle);

  if (! dp)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "not a valid root device");
      goto fail;
    }

  file_path = make_file_path (dp, filename);
  if (! file_path)
    goto fail;

  fsize = grub_file_size (file);
  if (!fsize)
    {
      grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		  filename);
      goto fail;
    }
  pages = (((grub_efi_uintn_t) fsize + ((1 << 12) - 1)) >> 12);

  status = efi_call_4 (b->allocate_pages, GRUB_EFI_ALLOCATE_ANY_PAGES,
			      GRUB_EFI_LOADER_CODE,
			      pages, &address);
  if (status != GRUB_EFI_SUCCESS)
    {
      grub_dprintf ("chain", "Failed to allocate %u pages\n",
		    (unsigned int) pages);
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }

  boot_image = (void *) ((grub_addr_t) address);
  if (grub_file_read (file, boot_image, fsize) != fsize)
    {
      if (grub_errno == GRUB_ERR_NONE)
	grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		    filename);

      goto fail;
    }

#if defined (__i386__) || defined (__x86_64__)
  if (fsize >= (grub_ssize_t) sizeof (struct grub_macho_fat_header))
    {
      struct grub_macho_fat_header *head = boot_image;
      if (head->magic
	  == grub_cpu_to_le32_compile_time (GRUB_MACHO_FAT_EFI_MAGIC))
	{
	  grub_uint32_t i;
	  struct grub_macho_fat_arch *archs
	    = (struct grub_macho_fat_arch *) (head + 1);

	  if (grub_efi_secure_boot())
	    {
	      grub_error (GRUB_ERR_BAD_OS,
			  "MACHO binaries are forbidden with Secure Boot");
	      goto fail;
	    }

	  for (i = 0; i < grub_cpu_to_le32 (head->nfat_arch); i++)
	    {
	      if (GRUB_MACHO_CPUTYPE_IS_HOST_CURRENT (archs[i].cputype))
		break;
	    }
	  if (i == grub_cpu_to_le32 (head->nfat_arch))
	    {
	      grub_error (GRUB_ERR_BAD_OS, "no compatible arch found");
	      goto fail;
	    }
	  if (grub_cpu_to_le32 (archs[i].offset)
	      > ~grub_cpu_to_le32 (archs[i].size)
	      || grub_cpu_to_le32 (archs[i].offset)
	      + grub_cpu_to_le32 (archs[i].size)
	      > (grub_size_t) fsize)
	    {
	      grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
			  filename);
	      goto fail;
	    }
	  boot_image = (char *) boot_image + grub_cpu_to_le32 (archs[i].offset);
	  fsize = grub_cpu_to_le32 (archs[i].size);
	}
    }
#endif

  rc = grub_linuxefi_secure_validate((void *)(unsigned long)address, fsize);
  grub_dprintf ("chain", "linuxefi_secure_validate: %d\n", rc);
  if (rc > 0)
    {
      grub_file_close (file);
      grub_device_close (dev);
      grub_loader_set (grub_secureboot_chainloader_boot,
		       grub_secureboot_chainloader_unload, 0);
      return 0;
    }
  else if (rc == 0)
    {
      grub_load_and_start_image(boot_image);
      grub_file_close (file);
      grub_device_close (dev);
      grub_loader_set (grub_chainloader_boot, grub_chainloader_unload, 0);

      return 0;
    }

fail:
  if (dev)
    grub_device_close (dev);

  if (file)
    grub_file_close (file);

  grub_free (file_path);

  if (address)
    efi_call_2 (b->free_pages, address, pages);

  if (cmdline)
    grub_free (cmdline);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_command_t cmd;

GRUB_MOD_INIT(chainloader)
{
  cmd = grub_register_command ("chainloader", grub_cmd_chainloader,
			       0, N_("Load another boot loader."));
  my_mod = mod;
}

GRUB_MOD_FINI(chainloader)
{
  grub_unregister_command (cmd);
}
