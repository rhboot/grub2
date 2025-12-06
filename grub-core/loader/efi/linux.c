/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013  Free Software Foundation, Inc.
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

#include <grub/charset.h>
#include <grub/command.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/fdt.h>
#include <grub/linux.h>
#include <grub/loader.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/efi/efi.h>
#include <grub/efi/fdtload.h>
#include <grub/efi/memory.h>
#include <grub/efi/pe32.h>
#include <grub/efi/linux.h>
#include <grub/efi/sb.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>
#include <grub/safemath.h>
#include <grub/verify.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;
static int loaded;

static void *kernel_addr;
static grub_uint64_t kernel_size;

static char *linux_args;
static grub_uint32_t cmdline_size;

static grub_addr_t initrd_start;
static grub_addr_t initrd_end;

static struct grub_linux_initrd_context initrd_ctx = {0, 0, 0};
static grub_efi_handle_t initrd_lf2_handle = NULL;
static bool initrd_use_loadfile2 = false;

static grub_guid_t load_file2_guid = GRUB_EFI_LOAD_FILE2_PROTOCOL_GUID;
static grub_guid_t device_path_guid = GRUB_EFI_DEVICE_PATH_GUID;

static initrd_media_device_path_t initrd_lf2_device_path = {
  {
    {
      GRUB_EFI_MEDIA_DEVICE_PATH_TYPE,
      GRUB_EFI_VENDOR_MEDIA_DEVICE_PATH_SUBTYPE,
      sizeof(grub_efi_vendor_media_device_path_t),
    },
    LINUX_EFI_INITRD_MEDIA_GUID
  }, {
    GRUB_EFI_END_DEVICE_PATH_TYPE,
    GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE,
    sizeof(grub_efi_device_path_t)
  }
};

extern grub_err_t
grub_cmd_linux_x86_legacy (grub_command_t cmd, int argc, char *argv[]);

extern grub_err_t
grub_cmd_initrd_x86_legacy (grub_command_t cmd, int argc, char *argv[]);

static grub_efi_status_t __grub_efi_api
grub_efi_initrd_load_file2 (grub_efi_load_file2_t *this,
                            grub_efi_device_path_t *device_path,
                            grub_efi_boolean_t boot_policy,
                            grub_efi_uintn_t *buffer_size,
                            void *buffer);

static grub_efi_load_file2_t initrd_lf2 = {
  grub_efi_initrd_load_file2
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

grub_err_t
grub_efi_check_nx_image_support (grub_addr_t k_add,
				 grub_size_t k_size,
				 int *nx_supported)
{
  struct grub_dos_header *doshdr;
  grub_size_t sz = sizeof (*doshdr);

  struct grub_pe32_header_32 *pe32;
  struct grub_pe32_header_64 *pe64;

  int image_is_compatible = 0;
  int is_64_bit;

  if (k_size < sz)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

  doshdr = (void *)k_add;

  if ((doshdr->magic & 0xffff) != GRUB_DOS_MAGIC)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel DOS magic is invalid"));

  sz = doshdr->lfanew + sizeof (*pe32);
  if (k_size < sz)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

  pe32 = (struct grub_pe32_header_32 *)(k_add + doshdr->lfanew);
  pe64 = (struct grub_pe32_header_64 *)pe32;

  if (grub_memcmp (pe32->signature, GRUB_PE32_SIGNATURE,
		   GRUB_PE32_SIGNATURE_SIZE) != 0)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel PE magic is invalid"));

  switch (pe32->coff_header.machine)
    {
    case GRUB_PE32_MACHINE_ARMTHUMB_MIXED:
    case GRUB_PE32_MACHINE_I386:
    case GRUB_PE32_MACHINE_RISCV32:
      is_64_bit = 0;
      break;
    case GRUB_PE32_MACHINE_ARM64:
    case GRUB_PE32_MACHINE_IA64:
    case GRUB_PE32_MACHINE_RISCV64:
    case GRUB_PE32_MACHINE_X86_64:
      is_64_bit = 1;
      break;
    default:
      return grub_error (GRUB_ERR_BAD_OS, N_("PE machine type 0x%04hx unknown"),
			 pe32->coff_header.machine);
    }

  if (is_64_bit)
    {
      sz = doshdr->lfanew + sizeof (*pe64);
      if (k_size < sz)
	return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

      if (pe64->optional_header.dll_characteristics & GRUB_PE32_NX_COMPAT)
	image_is_compatible = 1;
    }
  else
    {
      if (pe32->optional_header.dll_characteristics & GRUB_PE32_NX_COMPAT)
	image_is_compatible = 1;
    }

  *nx_supported = image_is_compatible;
  return GRUB_ERR_NONE;
}

grub_err_t
grub_efi_check_nx_required (int *nx_required)
{
  grub_efi_status_t status;
  grub_guid_t guid = GRUB_EFI_SHIM_LOCK_GUID;
  grub_size_t mok_policy_sz = 0;
  char *mok_policy = NULL;
  grub_uint32_t mok_policy_attrs = 0;

  status = grub_efi_get_variable_with_attributes ("MokPolicy", &guid,
						  &mok_policy_sz,
						  (void **)&mok_policy,
						  &mok_policy_attrs);
  if (status == GRUB_EFI_NOT_FOUND ||
      mok_policy_sz == 0 ||
      mok_policy == NULL)
    {
      *nx_required = 0;
      return GRUB_ERR_NONE;
    }

  *nx_required = 0;
  if (mok_policy_sz < 1 ||
      mok_policy_attrs != (GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS |
			   GRUB_EFI_VARIABLE_RUNTIME_ACCESS) ||
      (mok_policy[mok_policy_sz-1] & GRUB_MOK_POLICY_NX_REQUIRED))
    *nx_required = 1;

  return GRUB_ERR_NONE;
}

typedef void (*handover_func) (void *, grub_efi_system_table_t *, void *);

grub_err_t
grub_efi_mem_set_att(grub_addr_t k_address, grub_size_t k_size,
                     grub_size_t k_start, int nx_supported)
{
  grub_addr_t k_start_address = k_address + k_start;

  grub_uint64_t default_set_attrs = GRUB_MEM_ATTR_R | GRUB_MEM_ATTR_W | GRUB_MEM_ATTR_X;
  grub_uint64_t default_clear_attrs = 0;
  grub_uint64_t stack_set_attrs = default_set_attrs;
  grub_uint64_t stack_clear_attrs = default_clear_attrs;
  grub_uint64_t kernel_set_attrs = default_set_attrs;
  grub_uint64_t kernel_clear_attrs = default_clear_attrs;
  grub_uint64_t attrs;

  struct grub_msdos_image_header *header;
  struct grub_pe_image_header *pe_image_header;
  struct grub_pe32_coff_header *coff_header;
  struct grub_pe32_section_table *section, *sections;
  grub_uint16_t i;
  grub_size_t sz;

  header = (struct grub_msdos_image_header *)k_address;

  if (grub_add ((grub_addr_t) header, header->pe_image_header_offset, &sz))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("Error on PE image header address calculation"));

  pe_image_header = (struct grub_pe_image_header *) (sz);

  if (pe_image_header > (k_address + k_size))
    return grub_error (GRUB_ERR_BAD_OS, N_("PE image header address is invalid"));

  if (grub_memcmp (pe_image_header->signature, GRUB_PE32_SIGNATURE,
                   GRUB_PE32_SIGNATURE_SIZE) != 0)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel PE magic is invalid"));

  coff_header = &(pe_image_header->coff_header);
  grub_dprintf ("nx", "coff_header 0x%"PRIxGRUB_ADDR" machine %08x\n", (grub_addr_t)coff_header, coff_header->machine);

  if (grub_add ((grub_addr_t) coff_header, sizeof (*coff_header), &sz) ||
      grub_add (sz, coff_header->optional_header_size, &sz))
    return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("Error on PE sections calculation"));

  sections = (struct grub_pe32_section_table *) (sz);

  if (sections > (k_address + k_size))
    return grub_error (GRUB_ERR_BAD_OS, N_("Section address is invalid"));

  /* Parse the PE, remove W for code section, remove X for data sections, RO for the rest */
  for (i = 0, section = sections; i < coff_header->num_sections; i++, section++)
    {
      kernel_set_attrs = default_set_attrs;
      kernel_clear_attrs = default_clear_attrs;

      if (nx_supported)
        {
          if (section->characteristics & GRUB_PE32_SCN_MEM_EXECUTE)
            {
              /* RX section */
              kernel_set_attrs &= ~GRUB_MEM_ATTR_W;
              kernel_clear_attrs |= GRUB_MEM_ATTR_W;
            }
          else if (section->characteristics & GRUB_PE32_SCN_MEM_WRITE)
            {
              /* RW section */
              kernel_set_attrs &= ~GRUB_MEM_ATTR_X;
              kernel_clear_attrs |= GRUB_MEM_ATTR_X;
            }
          else
            {
              /* RO section */
              kernel_set_attrs &= ~GRUB_MEM_ATTR_W & ~GRUB_MEM_ATTR_X;
              kernel_clear_attrs |= GRUB_MEM_ATTR_X | GRUB_MEM_ATTR_W ;
            }
        }

      /* Make sure we are inside range */
      if (grub_add ((grub_addr_t) k_address, section->raw_data_offset, &sz))
        return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("Error on PE Executable section calculation"));

      grub_update_mem_attrs (sz, section->raw_data_size, kernel_set_attrs, kernel_clear_attrs);

      grub_get_mem_attrs (sz, 4096, &attrs);
      grub_dprintf ("nx", "permissions for section %s 0x%"PRIxGRUB_ADDR" are %s%s%s\n",
		    section->name,
		    (grub_addr_t)sz,
		    (attrs & GRUB_MEM_ATTR_R) ? "r" : "-",
		    (attrs & GRUB_MEM_ATTR_W) ? "w" : "-",
		    (attrs & GRUB_MEM_ATTR_X) ? "x" : "-");
    }

  if (grub_stack_addr != (grub_addr_t)-1ll)
    {
      if (nx_supported)
        {
          stack_set_attrs &= ~GRUB_MEM_ATTR_X;
          stack_clear_attrs |= GRUB_MEM_ATTR_X;
        }

      grub_dprintf ("nx", "Setting attributes for stack at 0x%"PRIxGRUB_ADDR"-0x%"PRIxGRUB_ADDR" to rw%c\n",
                    grub_stack_addr, grub_stack_addr + grub_stack_size - 1,
                    (stack_set_attrs & GRUB_MEM_ATTR_X) ? 'x' : '-');

      grub_update_mem_attrs (grub_stack_addr, grub_stack_size,
                             stack_set_attrs, stack_clear_attrs);

      grub_get_mem_attrs (grub_stack_addr, 4096, &attrs);
      grub_dprintf ("nx", "permissions for 0x%"PRIxGRUB_ADDR" are %s%s%s\n",
                    grub_stack_addr,
                    (attrs & GRUB_MEM_ATTR_R) ? "r" : "-",
                    (attrs & GRUB_MEM_ATTR_W) ? "w" : "-",
                    (attrs & GRUB_MEM_ATTR_X) ? "x" : "-");
    }

  return GRUB_ERR_NONE;
}


grub_err_t
grub_efi_linux_boot (grub_addr_t k_address, grub_size_t k_size, grub_size_t k_start,
		     grub_off_t h_offset, void *k_params,
		     int nx_supported)
{
  grub_addr_t k_start_address = k_address + k_start;
  grub_efi_loaded_image_t *loaded_image = NULL;
  handover_func hf;
  int offset = 0;
  int nx_required = 0;
 
#ifdef __x86_64__
  offset = 512;
#endif

  /*
   * Since the EFI loader is not calling the LoadImage() and StartImage()
   * services for loading the kernel and booting respectively, it has to
   * set the Loaded Image base address.
   */
  loaded_image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (loaded_image)
    loaded_image->image_base = (void *)k_address;
  else
    grub_dprintf ("linux", "Loaded Image base address could not be set\n");

  grub_dprintf ("linux", "kernel_address: %p handover_offset: %p params: %p\n",
		(void *)k_address, (void *)h_offset, k_params);

  grub_efi_check_nx_required(&nx_required);

  if (nx_required && !nx_supported)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel does not support NX loading required by policy"));

  grub_efi_mem_set_att (k_address, k_size, k_start, nx_supported);

#if defined(__i386__) || defined(__x86_64__)
  asm volatile ("cli");
#endif

  hf = (handover_func)((char *)k_start_address + h_offset + offset);
  hf (grub_efi_image_handle, grub_efi_system_table, k_params);

  return GRUB_ERR_BUG;
}

#pragma GCC diagnostic pop

grub_err_t
grub_arch_efi_linux_load_image_header (grub_file_t file,
                                      struct linux_arch_kernel_header * lh)
{
  grub_file_seek (file, 0);
  if (grub_file_read (file, lh, sizeof (*lh)) < (grub_ssize_t) sizeof (*lh))
    return grub_error(GRUB_ERR_FILE_READ_ERROR, "failed to read Linux image header");

  if ((lh->code0 & 0xffff) != GRUB_DOS_MAGIC)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       N_("plain image kernel not supported - rebuild with CONFIG_(U)EFI_STUB enabled"));

  grub_dprintf ("linux", "UEFI stub kernel:\n");
  grub_dprintf ("linux", "PE/COFF header @ %08x\n", lh->hdr_offset);

  /*
   * The PE/COFF spec permits the COFF header to appear anywhere in the file, so
   * we need to double check whether it was where we expected it, and if not, we
   * must load it from the correct offset into the pe_image_header field of
   * struct linux_arch_kernel_header.
   */
  if ((grub_uint8_t *) lh + lh->hdr_offset != (grub_uint8_t *) &lh->pe_image_header)
    {
      if (grub_file_seek (file, lh->hdr_offset) == (grub_off_t) -1
          || grub_file_read (file, &lh->pe_image_header,
                             sizeof (struct grub_pe_image_header))
             != sizeof (struct grub_pe_image_header))
        return grub_error (GRUB_ERR_FILE_READ_ERROR, "failed to read COFF image header");
    }

  if (lh->pe_image_header.optional_header.magic != GRUB_PE32_NATIVE_MAGIC)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "non-native image not supported");

  /*
   * Linux kernels built for any architecture are guaranteed to support the
   * LoadFile2 based initrd loading protocol if the image version is >= 1.
   */
  if (lh->pe_image_header.optional_header.major_image_version >= 1)
    initrd_use_loadfile2 = true;
  else
    initrd_use_loadfile2 = false;

  grub_dprintf ("linux", "LoadFile2 initrd loading %sabled\n",
                initrd_use_loadfile2 ? "en" : "dis");

  return GRUB_ERR_NONE;
}

#if !defined(__i386__) && !defined(__x86_64__)
static grub_err_t
finalize_params_linux (void)
{
  grub_err_t err = GRUB_ERR_NONE;
  int node, retval;
  void *fdt;

  /* Set initrd info */
  if (initrd_start && initrd_end > initrd_start)
    {
      fdt = grub_fdt_load (GRUB_EFI_LINUX_FDT_EXTRA_SPACE);

      if (!fdt)
        {
          err = grub_error(GRUB_ERR_BAD_OS, "failed to load FDT");
          goto failure;
        }


      node = grub_fdt_find_subnode (fdt, 0, "chosen");
      if (node < 0)
       node = grub_fdt_add_subnode (fdt, 0, "chosen");

      if (node < 1)
        {
          err = grub_error(grub_errno, "failed to load chosen fdt node.");
          goto failure;
        }

      grub_dprintf ("linux", "Initrd @ %p-%p\n",
		    (void *) initrd_start, (void *) initrd_end);

      retval = grub_fdt_set_prop64 (fdt, node, "linux,initrd-start",
				    initrd_start);
      if (retval)
	{
	  err = grub_error(retval, "Failed to set linux,initrd-start property");
	  goto failure;
	}

      retval = grub_fdt_set_prop64 (fdt, node, "linux,initrd-end",
				    initrd_end);
      if (retval)
	{
	  err = grub_error(retval, "Failed to set linux,initrd-end property");
	  goto failure;
	}
    }

  retval = grub_fdt_install();
  if (retval != GRUB_ERR_NONE)
    {
      err = grub_error(retval, "Failed to install fdt");
      goto failure;
    }

  return GRUB_ERR_NONE;

failure:
  grub_fdt_unload();
  return err;
}
#endif

grub_err_t
grub_arch_efi_linux_boot_image (grub_addr_t addr, grub_size_t size, char *args)
{
  grub_efi_memory_mapped_device_path_t *mempath;
  grub_efi_handle_t image_handle;
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;
  grub_efi_loaded_image_t *loaded_image;
  int len;

  mempath = grub_malloc (2 * sizeof (grub_efi_memory_mapped_device_path_t));
  if (!mempath)
    return grub_errno;

  mempath[0].header.type = GRUB_EFI_HARDWARE_DEVICE_PATH_TYPE;
  mempath[0].header.subtype = GRUB_EFI_MEMORY_MAPPED_DEVICE_PATH_SUBTYPE;
  mempath[0].header.length = grub_cpu_to_le16_compile_time (sizeof (*mempath));
  mempath[0].memory_type = GRUB_EFI_LOADER_DATA;
  mempath[0].start_address = addr;
  mempath[0].end_address = addr + size;

  mempath[1].header.type = GRUB_EFI_END_DEVICE_PATH_TYPE;
  mempath[1].header.subtype = GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
  mempath[1].header.length = sizeof (grub_efi_device_path_t);

  b = grub_efi_system_table->boot_services;
  status = b->load_image (0, grub_efi_image_handle,
			  (grub_efi_device_path_t *) mempath,
			  (void *) addr, size, &image_handle);
  grub_free (mempath);
  if (status != GRUB_EFI_SUCCESS)
    return grub_error (GRUB_ERR_BAD_OS, "cannot load image");

  grub_dprintf ("linux", "linux command line: '%s'\n", args);

  /* Convert command line to UCS-2 */
  loaded_image = grub_efi_get_loaded_image (image_handle);
  if (loaded_image == NULL)
    {
      grub_error (GRUB_ERR_BAD_FIRMWARE, "missing loaded_image proto");
      goto unload;
    }
  loaded_image->load_options_size = len =
    (grub_strlen (args) + 1) * sizeof (grub_efi_char16_t);
  loaded_image->load_options =
    grub_efi_allocate_any_pages (GRUB_EFI_BYTES_TO_PAGES (loaded_image->load_options_size));
  if (!loaded_image->load_options)
      goto unload;

  loaded_image->load_options_size =
    2 * grub_utf8_to_utf16 (loaded_image->load_options, len,
			    (grub_uint8_t *) args, len, NULL);

  grub_dprintf ("linux", "starting image %p\n", image_handle);
  status = b->start_image (image_handle, 0, NULL);

  /* When successful, not reached */
  grub_error (GRUB_ERR_BAD_OS, "start_image() returned 0x%" PRIxGRUB_EFI_UINTN_T, status);
  grub_efi_free_pages ((grub_addr_t) loaded_image->load_options,
		       GRUB_EFI_BYTES_TO_PAGES (loaded_image->load_options_size));
unload:
  b->unload_image (image_handle);

  return grub_errno;
}

static grub_err_t
grub_linux_boot (void)
{
#if !defined(__i386__) && !defined(__x86_64__)
  if (finalize_params_linux () != GRUB_ERR_NONE)
    return grub_errno;
#endif

  return grub_arch_efi_linux_boot_image ((grub_addr_t) kernel_addr,
					 kernel_size, linux_args);
}

static grub_err_t
grub_linux_unload (void)
{
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;

  grub_dl_unref (my_mod);
  loaded = 0;
  if (initrd_start)
    grub_efi_free_pages ((grub_efi_physical_address_t) initrd_start,
			 GRUB_EFI_BYTES_TO_PAGES (initrd_end - initrd_start));
  initrd_start = initrd_end = 0;
  grub_free (linux_args);
  if (kernel_addr)
    grub_efi_free_pages ((grub_addr_t) kernel_addr,
			 GRUB_EFI_BYTES_TO_PAGES (kernel_size));
#if !defined(__i386__) && !defined(__x86_64__)
  grub_fdt_unload ();
#endif

  if (initrd_lf2_handle != NULL)
    {
      b->uninstall_multiple_protocol_interfaces (initrd_lf2_handle,
                                                 &load_file2_guid,
                                                 &initrd_lf2,
                                                 &device_path_guid,
                                                 &initrd_lf2_device_path,
                                                 NULL);
      initrd_lf2_handle = NULL;
      initrd_use_loadfile2 = false;
    }
  return GRUB_ERR_NONE;
}

#if !defined(__i386__) && !defined(__x86_64__)
/*
 * As per linux/Documentation/arm/Booting
 * ARM initrd needs to be covered by kernel linear mapping,
 * so place it in the first 512MB of DRAM.
 *
 * As per linux/Documentation/arm64/booting.txt
 * ARM64 initrd needs to be contained entirely within a 1GB aligned window
 * of up to 32GB of size that covers the kernel image as well.
 * Since the EFI stub loader will attempt to load the kernel near start of
 * RAM, place the buffer in the first 32GB of RAM.
 */
#ifdef __arm__
#define INITRD_MAX_ADDRESS_OFFSET (512U * 1024 * 1024)
#else /* __aarch64__ */
#define INITRD_MAX_ADDRESS_OFFSET (32ULL * 1024 * 1024 * 1024)
#endif

/*
 * This function returns a pointer to a legally allocated initrd buffer,
 * or NULL if unsuccessful
 */
static void *
allocate_initrd_mem (int initrd_pages)
{
  grub_addr_t max_addr = 0;
  grub_err_t err;
  void *ret;

  err = grub_efi_get_ram_base (&max_addr);
  if (err != GRUB_ERR_NONE)
    {
      grub_error (err, "grub_efi_get_ram_base() failed");
      return NULL;
    }

  grub_dprintf ("linux", "max_addr: 0x%016lx, INITRD_MAX_ADDRESS_OFFSET: 0x%016llx\n",
		max_addr, INITRD_MAX_ADDRESS_OFFSET);

  max_addr += INITRD_MAX_ADDRESS_OFFSET - 1;
  grub_dprintf ("linux", "calling grub_efi_allocate_pages_real (0x%016lx, 0x%08x, EFI_ALLOCATE_MAX_ADDRESS, EFI_LOADER_DATA)", max_addr, initrd_pages);

  ret = grub_efi_allocate_pages_real (max_addr, initrd_pages,
				      GRUB_EFI_ALLOCATE_MAX_ADDRESS,
				      GRUB_EFI_LOADER_DATA);
  grub_dprintf ("linux", "got 0x%016llx\n", (unsigned long long)ret);
  return ret;
}
#endif

static grub_efi_status_t __grub_efi_api
grub_efi_initrd_load_file2 (grub_efi_load_file2_t *this,
                            grub_efi_device_path_t *device_path,
                            grub_efi_boolean_t boot_policy,
                            grub_efi_uintn_t *buffer_size,
                            void *buffer)
{
  grub_efi_status_t status = GRUB_EFI_SUCCESS;
  grub_efi_uintn_t initrd_size;

  if (this != &initrd_lf2 || buffer_size == NULL)
    return GRUB_EFI_INVALID_PARAMETER;

  if (device_path->type != GRUB_EFI_END_DEVICE_PATH_TYPE ||
      device_path->subtype != GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE)
    return GRUB_EFI_NOT_FOUND;

  if (boot_policy)
    return GRUB_EFI_UNSUPPORTED;

  initrd_size = grub_get_initrd_size (&initrd_ctx);
  if (buffer == NULL || *buffer_size < initrd_size)
    {
      *buffer_size = initrd_size;
      return GRUB_EFI_BUFFER_TOO_SMALL;
    }

  grub_dprintf ("linux", "Providing initrd via EFI_LOAD_FILE2_PROTOCOL\n");

  if (grub_initrd_load (&initrd_ctx, buffer))
    status = GRUB_EFI_DEVICE_ERROR;

  grub_initrd_close (&initrd_ctx);
  return status;
}

static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)),
		 int argc, char *argv[])
{
  int __attribute__ ((unused)) initrd_size, initrd_pages;
  void *__attribute__ ((unused)) initrd_mem = NULL;
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
  grub_efi_status_t status;

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

#if defined(__i386__) || defined(__x86_64__)
  if (!initrd_use_loadfile2)
    return grub_cmd_initrd_x86_legacy (cmd, argc, argv);
#endif

  if (!loaded)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT,
		  N_("you need to load the kernel first"));
      goto fail;
    }

  if (grub_initrd_init (argc, argv, &initrd_ctx))
    goto fail;

  if (initrd_use_loadfile2)
    {
      if (initrd_lf2_handle == NULL)
        {
          status = b->install_multiple_protocol_interfaces (&initrd_lf2_handle,
                                                            &load_file2_guid,
                                                            &initrd_lf2,
                                                            &device_path_guid,
                                                            &initrd_lf2_device_path,
                                                            NULL);
          if (status == GRUB_EFI_OUT_OF_RESOURCES)
            {
              grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
              goto fail;
            }
          else if (status != GRUB_EFI_SUCCESS)
            {
              grub_error (GRUB_ERR_BAD_ARGUMENT, N_("failed to install protocols"));
              goto fail;
            }
        }
      grub_dprintf ("linux", "Using LoadFile2 initrd loading protocol\n");
      return GRUB_ERR_NONE;
    }

#if !defined(__i386__) && !defined(__x86_64__)
  initrd_size = grub_get_initrd_size (&initrd_ctx);
  grub_dprintf ("linux", "Loading initrd\n");

  initrd_pages = (GRUB_EFI_BYTES_TO_PAGES (initrd_size));
  initrd_mem = allocate_initrd_mem (initrd_pages);

  if (!initrd_mem)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }

  if (grub_initrd_load (&initrd_ctx, initrd_mem))
    {
      grub_efi_free_pages ((grub_addr_t) initrd_mem, initrd_pages);
      goto fail;
    }

  initrd_start = (grub_addr_t) initrd_mem;
  initrd_end = initrd_start + initrd_size;
  grub_dprintf ("linux", "[addr=%p, size=0x%x]\n",
		(void *) initrd_start, initrd_size);
#endif

 fail:
  grub_initrd_close (&initrd_ctx);

  return grub_errno;
}

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_file_t file = 0;
  struct linux_arch_kernel_header lh;
  grub_err_t err;

  grub_dl_ref (my_mod);

  if (grub_is_shim_lock_enabled () == true)
    {
#if defined(__i386__) || defined(__x86_64__)
      grub_dprintf ("linux", "shim_lock enabled, falling back to legacy Linux kernel loader\n");

      err = grub_cmd_linux_x86_legacy (cmd, argc, argv);

      if (err == GRUB_ERR_NONE)
	return GRUB_ERR_NONE;
      else
	goto fail;
#else
      grub_dprintf ("linux", "shim_lock enabled, trying Linux kernel EFI stub loader\n");
#endif
    }

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  file = grub_file_open (argv[0], GRUB_FILE_TYPE_LINUX_KERNEL);
  if (!file)
    goto fail;

  kernel_size = grub_file_size (file);

  if (grub_arch_efi_linux_load_image_header (file, &lh) != GRUB_ERR_NONE)
#if !defined(__i386__) && !defined(__x86_64__)
    goto fail;
#else
    goto fallback;

  if (!initrd_use_loadfile2)
    {
      /*
       * This is a EFI stub image but it is too old to implement the LoadFile2
       * based initrd loading scheme, and Linux/x86 does not support the DT
       * based method either. So fall back to the x86-specific loader that
       * enters Linux in EFI mode but without going through its EFI stub.
       */
fallback:
      grub_file_close (file);
      return grub_cmd_linux_x86_legacy (cmd, argc, argv);
    }
#endif

  grub_loader_unset();

  grub_dprintf ("linux", "kernel file size: %lld\n", (long long) kernel_size);
  kernel_addr = grub_efi_allocate_any_pages (GRUB_EFI_BYTES_TO_PAGES (kernel_size));
  grub_dprintf ("linux", "kernel numpages: %lld\n",
		(long long) GRUB_EFI_BYTES_TO_PAGES (kernel_size));
  if (!kernel_addr)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }

  grub_file_seek (file, 0);
  if (grub_file_read (file, kernel_addr, kernel_size)
      < (grub_int64_t) kernel_size)
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"), argv[0]);
      goto fail;
    }

  grub_dprintf ("linux", "kernel @ %p\n", kernel_addr);

  cmdline_size = grub_loader_cmdline_size (argc, argv) + sizeof (LINUX_IMAGE);
  linux_args = grub_malloc (cmdline_size);
  if (!linux_args)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }
  grub_memcpy (linux_args, LINUX_IMAGE, sizeof (LINUX_IMAGE));
  err = grub_create_loader_cmdline (argc, argv,
				    linux_args + sizeof (LINUX_IMAGE) - 1,
				    cmdline_size,
				    GRUB_VERIFY_KERNEL_CMDLINE);
  if (err)
    goto fail;

  if (grub_errno == GRUB_ERR_NONE)
    {
      grub_loader_set (grub_linux_boot, grub_linux_unload, 0);
      loaded = 1;
    }

fail:
  if (file)
    grub_file_close (file);

  if (grub_errno != GRUB_ERR_NONE)
    {
      grub_dl_unref (my_mod);
      loaded = 0;
    }

  if (linux_args && !loaded)
    grub_free (linux_args);

  if (kernel_addr && !loaded)
    grub_efi_free_pages ((grub_addr_t) kernel_addr,
			 GRUB_EFI_BYTES_TO_PAGES (kernel_size));

  return grub_errno;
}


static grub_command_t cmd_linux, cmd_initrd;

GRUB_MOD_INIT (linux)
{
  cmd_linux = grub_register_command ("linux", grub_cmd_linux, 0,
				     N_("Load Linux."));
  cmd_initrd = grub_register_command ("initrd", grub_cmd_initrd, 0,
				      N_("Load initrd."));
  my_mod = mod;
}

GRUB_MOD_FINI (linux)
{
  grub_unregister_command (cmd_linux);
  grub_unregister_command (cmd_initrd);
}
