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
#include <grub/cpu/linux.h>
#include <grub/efi/efi.h>
#include <grub/efi/fdtload.h>
#include <grub/efi/memory.h>
#include <grub/efi/linux.h>
#include <grub/efi/pe32.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;
static int loaded;

static void *kernel_addr;
static grub_uint64_t kernel_size;
static grub_uint32_t handover_offset;

static char *linux_args;
static grub_uint32_t cmdline_size;

static grub_addr_t initrd_start;
static grub_addr_t initrd_end;

grub_err_t
grub_armxx_efi_linux_check_image (struct linux_armxx_kernel_header * lh)
{
  if (lh->magic != GRUB_LINUX_ARMXX_MAGIC_SIGNATURE)
    return grub_error(GRUB_ERR_BAD_OS, "invalid magic number");

  if ((lh->code0 & 0xffff) != GRUB_PE32_MAGIC)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       N_("plain image kernel not supported - rebuild with CONFIG_(U)EFI_STUB enabled"));

  grub_dprintf ("linux", "UEFI stub kernel:\n");
  grub_dprintf ("linux", "PE/COFF header @ %08x\n", lh->hdr_offset);

  return GRUB_ERR_NONE;
}

static grub_err_t
finalize_params_linux (void)
{
  grub_efi_loaded_image_t *loaded_image = NULL;
  int node, retval, len;
  grub_err_t err = GRUB_ERR_NONE;
  void *fdt;

  fdt = grub_fdt_load (0x400);
  if (!fdt)
    {
      err = grub_error(GRUB_ERR_BAD_OS, "failed to load FDT");
      goto failure;
    }

  node = grub_fdt_find_subnode (fdt, 0, "chosen");
  if (node < 0)
    {
      /*
       * If we have to create a chosen node, Make sure we
       * have #address-cells and #size-cells properties.
       */
      retval = grub_fdt_set_prop32(fdt, 0, "#address-cells", 2);
      if (retval)
	{
	  err = grub_error(retval, "Could not find #address-cells");
	  goto failure;
	}

      retval = grub_fdt_set_prop32(fdt, 0, "#size-cells", 2);
      if (retval)
	{
	  err = grub_error(retval, "Could not find #size-cells");
	  goto failure;
	}

      node = grub_fdt_add_subnode (fdt, 0, "chosen");
    }

  if (node < 1)
    {
      err = grub_error(grub_errno, "failed to load chosen fdt node.");
      goto failure;
    }

  /* Set initrd info */
  if (initrd_start && initrd_end > initrd_start)
    {
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
  if (!loaded_image)
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
grub_armxx_efi_linux_boot_image (grub_addr_t addr, char *args)
{
  grub_err_t retval;

  retval = finalize_params_linux ();
  if (retval != GRUB_ERR_NONE)
    return grub_errno;

  grub_dprintf ("linux", "linux command line: '%s'\n", args);

  retval = grub_efi_linux_boot ((char *)addr, handover_offset, (void *)addr);

  /* Never reached... */
  free_params();
  return retval;
}

static grub_err_t
grub_linux_boot (void)
{
  return grub_armxx_efi_linux_boot_image((grub_addr_t)kernel_addr, linux_args);
}

static grub_err_t
grub_linux_unload (void)
{
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
  grub_fdt_unload ();
  return GRUB_ERR_NONE;
}

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

static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)),
		 int argc, char *argv[])
{
  struct grub_linux_initrd_context initrd_ctx = { 0, 0, 0 };
  int initrd_size, initrd_pages;
  void *initrd_mem = NULL;

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  if (!loaded)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT,
		  N_("you need to load the kernel first"));
      goto fail;
    }

  if (grub_initrd_init (argc, argv, &initrd_ctx))
    goto fail;

  initrd_size = grub_get_initrd_size (&initrd_ctx);
  grub_dprintf ("linux", "Loading initrd\n");

  initrd_pages = (GRUB_EFI_BYTES_TO_PAGES (initrd_size));
  initrd_mem = allocate_initrd_mem (initrd_pages);

  if (!initrd_mem)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }

  if (grub_initrd_load (&initrd_ctx, argv, initrd_mem))
    goto fail;

  initrd_start = (grub_addr_t) initrd_mem;
  initrd_end = initrd_start + initrd_size;
  grub_dprintf ("linux", "[addr=%p, size=0x%x]\n",
		(void *) initrd_start, initrd_size);

 fail:
  grub_initrd_close (&initrd_ctx);
  if (initrd_mem && !initrd_start)
    grub_efi_free_pages ((grub_addr_t) initrd_mem, initrd_pages);

  return grub_errno;
}

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_file_t file = 0;
  struct linux_armxx_kernel_header lh;
  struct grub_armxx_linux_pe_header *pe;
  int rc;

  grub_dl_ref (my_mod);

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  file = grub_file_open (argv[0]);
  if (!file)
    goto fail;

  kernel_size = grub_file_size (file);

  if (grub_file_read (file, &lh, sizeof (lh)) < (long) sizeof (lh))
    return grub_errno;

  if (grub_armxx_efi_linux_check_image (&lh) != GRUB_ERR_NONE)
    goto fail;

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

  rc = grub_linuxefi_secure_validate (kernel_addr, kernel_size);
  if (rc < 0)
    {
      grub_error (GRUB_ERR_INVALID_COMMAND, N_("%s has invalid signature"), argv[0]);
      goto fail;
    }

  pe = (void *)((unsigned long)kernel_addr + lh.hdr_offset);
  handover_offset = pe->opt.entry_addr;

  cmdline_size = grub_loader_cmdline_size (argc, argv) + sizeof (LINUX_IMAGE);
  linux_args = grub_malloc (cmdline_size);
  if (!linux_args)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }
  grub_memcpy (linux_args, LINUX_IMAGE, sizeof (LINUX_IMAGE));
  grub_create_loader_cmdline (argc, argv,
			      linux_args + sizeof (LINUX_IMAGE) - 1,
			      cmdline_size);

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
