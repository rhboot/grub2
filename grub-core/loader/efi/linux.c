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
#include <grub/efi/linux.h>
#include <grub/efi/pe32.h>
#include <grub/efi/linux.h>
#include <grub/efi/sb.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>
#include <grub/verify.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;
static int loaded;

static void *kernel_alloc_addr;
static grub_uint32_t kernel_alloc_pages;
static void *kernel_addr;
static grub_uint64_t kernel_size;
static grub_uint32_t handover_offset;

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

typedef void (*handover_func) (void *, grub_efi_system_table_t *, void *);

grub_err_t
grub_efi_linux_boot (void *kernel_address, grub_off_t ho_offset,
		     void *kernel_params)
{
  grub_efi_loaded_image_t *loaded_image = NULL;
  handover_func hf;
  int offset = 0;

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
    loaded_image->image_base = kernel_address;
  else
    grub_dprintf ("linux", "Loaded Image base address could not be set\n");

  grub_dprintf ("linux", "kernel_address: %p handover_offset: %p params: %p\n",
		kernel_address, (void *)(grub_efi_uintn_t)ho_offset, kernel_params);
  hf = (handover_func)((char *)kernel_address + ho_offset + offset);
  hf (grub_efi_image_handle, grub_efi_system_table, kernel_params);

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

  if ((lh->code0 & 0xffff) != GRUB_PE32_MAGIC)
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
  grub_efi_loaded_image_t *loaded_image = NULL;
  int node, retval, len;
  grub_err_t err = GRUB_ERR_NONE;
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

  grub_dprintf ("linux", "Installed/updated FDT configuration table @ %p\n",
                fdt);

  /* Convert command line to UCS-2 */
  loaded_image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (loaded_image == NULL)
    {
      err = grub_error(grub_errno, "Failed to install fdt");
      goto failure;
    }
  loaded_image->load_options_size = len =
    (grub_strlen (linux_args) + 1) * sizeof (grub_efi_char16_t);
  loaded_image->load_options =
    grub_efi_allocate_any_pages (GRUB_EFI_BYTES_TO_PAGES (loaded_image->load_options_size));
  if (!loaded_image->load_options)
    {
      err = grub_error(GRUB_ERR_BAD_OS, "failed to create kernel parameters");
      goto failure;
    }

  loaded_image->load_options_size =
    2 * grub_utf8_to_utf16 (loaded_image->load_options, len,
                           (grub_uint8_t *) linux_args, len, NULL);

  return GRUB_ERR_NONE;

failure:
  grub_fdt_unload();
  return err;
}
#endif

static void
free_params (void)
{
  grub_efi_loaded_image_t *loaded_image = NULL;

  loaded_image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (loaded_image)
    {
      if (loaded_image->load_options)
       grub_efi_free_pages ((grub_efi_physical_address_t)(grub_efi_uintn_t)loaded_image->load_options,
                            GRUB_EFI_BYTES_TO_PAGES (loaded_image->load_options_size));
      loaded_image->load_options = NULL;
      loaded_image->load_options_size = 0;
    }
}

grub_err_t
grub_arch_efi_linux_boot_image (grub_addr_t addr, char *args)
{
  grub_err_t retval;

  grub_dprintf ("linux", "linux command line: '%s'\n", args);

  retval = grub_efi_linux_boot ((char *)addr, handover_offset, (void *)addr);

  /* Never reached... */
  free_params();
  return retval;
 }

static grub_err_t
grub_linux_boot (void)
{
#if !defined(__i386__) && !defined(__x86_64__)
  if (finalize_params_linux () != GRUB_ERR_NONE)
    return grub_errno;
#endif

  return grub_arch_efi_linux_boot_image ((grub_addr_t) kernel_addr, linux_args);
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
  if (kernel_alloc_addr)
    grub_efi_free_pages ((grub_addr_t) kernel_alloc_addr, kernel_alloc_pages);
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

#if !defined(__i386__) && !defined(__x86_64__)
static grub_err_t
parse_pe_header (void *kernel, grub_uint64_t *total_size,
		 grub_uint32_t *entry_offset,
		 grub_uint32_t *alignment)
{
  struct linux_arch_kernel_header *lh = kernel;
  struct grub_armxx_linux_pe_header *pe;

  pe = (void *)((unsigned long)kernel + lh->hdr_offset);

  if (pe->opt.magic != GRUB_PE32_PEXX_MAGIC)
    return grub_error(GRUB_ERR_BAD_OS, "Invalid PE optional header magic");

  *total_size   = pe->opt.image_size;
  *entry_offset = pe->opt.entry_addr;
  *alignment    = pe->opt.section_alignment;

  return GRUB_ERR_NONE;
}
#endif

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_file_t file = 0;
  struct linux_arch_kernel_header lh;
  grub_off_t filelen;
  grub_uint32_t align;
  void *kernel = NULL;
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

  filelen = grub_file_size (file);
  kernel = grub_malloc(filelen);
  if (!kernel)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("cannot allocate kernel load buffer"));
      goto fail;
    }

  if (grub_file_read (file, kernel, filelen) < (grub_ssize_t)filelen)
    {
      grub_error (GRUB_ERR_FILE_READ_ERROR, N_("Can't read kernel %s"),
		  argv[0]);
      goto fail;
    }

#if !defined(__i386__) && !defined(__x86_64__)
  if (parse_pe_header (kernel, &kernel_size, &handover_offset, &align) != GRUB_ERR_NONE)
    goto fail;
  grub_dprintf ("linux", "kernel mem size     : %lld\n", (long long) kernel_size);
  grub_dprintf ("linux", "kernel entry offset : %d\n", handover_offset);
  grub_dprintf ("linux", "kernel alignment    : 0x%x\n", align);

  grub_loader_unset();

  kernel_alloc_pages = GRUB_EFI_BYTES_TO_PAGES (kernel_size + align - 1);
  kernel_alloc_addr = grub_efi_allocate_any_pages (kernel_alloc_pages);
  grub_dprintf ("linux", "kernel numpages: %d\n", kernel_alloc_pages);
  if (!kernel_alloc_addr)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }
  kernel_addr = (void *)ALIGN_UP((grub_uint64_t)kernel_alloc_addr, align);

  grub_dprintf ("linux", "kernel @ %p\n", kernel_addr);
  grub_memcpy (kernel_addr, kernel, grub_min(filelen, kernel_size));
  if (kernel_size > filelen)
    grub_memset ((char *)kernel_addr + filelen, 0, kernel_size - filelen);
  grub_free(kernel);
  kernel = NULL;
#endif

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
  if (kernel)
    grub_free (kernel);

  if (file)
    grub_file_close (file);

  if (grub_errno != GRUB_ERR_NONE)
    {
      grub_dl_unref (my_mod);
      loaded = 0;
    }

  if (linux_args && !loaded)
    grub_free (linux_args);

  if (kernel_alloc_addr && !loaded)
    grub_efi_free_pages ((grub_addr_t) kernel_alloc_addr, kernel_alloc_pages);

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
