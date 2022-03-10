/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2012  Free Software Foundation, Inc.
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

#include <grub/loader.h>
#include <grub/file.h>
#include <grub/err.h>
#include <grub/types.h>
#include <grub/mm.h>
#include <grub/cpu/linux.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>
#include <grub/efi/efi.h>
#include <grub/efi/linux.h>
#include <grub/cpu/efi/memory.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;
static int loaded;
static void *kernel_mem;
static grub_uint64_t kernel_size;
static void *initrd_mem;
static grub_uint32_t handover_offset;
struct linux_kernel_params *params;
static char *linux_cmdline;

#define MIN(a, b) \
  ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
     _a < _b ? _a : _b; })

#define BYTES_TO_PAGES(bytes)   (((bytes) + 0xfff) >> 12)

struct allocation_choice {
    grub_efi_physical_address_t addr;
    grub_efi_allocate_type_t alloc_type;
};

static struct allocation_choice max_addresses[4] =
  {
    /* the kernel overrides this one with pref_address and
     * GRUB_EFI_ALLOCATE_ADDRESS */
    { GRUB_EFI_MAX_ALLOCATION_ADDRESS, GRUB_EFI_ALLOCATE_MAX_ADDRESS },
    /* this one is always below 4GB, which we still *prefer* even if the flag
     * is set. */
    { GRUB_EFI_MAX_ALLOCATION_ADDRESS, GRUB_EFI_ALLOCATE_MAX_ADDRESS },
    /* If the flag in params is set, this one gets changed to be above 4GB. */
    { GRUB_EFI_MAX_ALLOCATION_ADDRESS, GRUB_EFI_ALLOCATE_MAX_ADDRESS },
    { 0, 0 }
  };
static struct allocation_choice saved_addresses[4];

#define save_addresses() grub_memcpy(saved_addresses, max_addresses, sizeof(max_addresses))
#define restore_addresses() grub_memcpy(max_addresses, saved_addresses, sizeof(max_addresses))

static inline void
kernel_free(void *addr, grub_efi_uintn_t size)
{
  if (addr && size)
    grub_efi_free_pages ((grub_efi_physical_address_t)(grub_addr_t)addr,
			 BYTES_TO_PAGES(size));
}

static void *
kernel_alloc(grub_efi_uintn_t size, const char * const errmsg)
{
  void *addr = 0;
  unsigned int i;
  grub_efi_physical_address_t prev_max = 0;

  for (i = 0; max_addresses[i].addr != 0 && addr == 0; i++)
    {
      grub_uint64_t max = max_addresses[i].addr;
      grub_efi_uintn_t pages;

      /*
       * When we're *not* loading the kernel, or >4GB allocations aren't
       * supported, these entries are basically all the same, so don't re-try
       * the same parameters.
       */
      if (max == prev_max)
	continue;

      pages = BYTES_TO_PAGES(size);
      grub_dprintf ("linux", "Trying to allocate %lu pages from %p\n",
		    pages, (void *)max);

      prev_max = max;
      addr = grub_efi_allocate_pages_real (max, pages,
					   max_addresses[i].alloc_type,
					   GRUB_EFI_LOADER_DATA);
      if (addr)
	grub_dprintf ("linux", "Allocated at %p\n", addr);
    }

  while (grub_error_pop ())
    {
      ;
    }

  if (addr == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "%s", errmsg);

  return addr;
}

static grub_err_t
grub_linuxefi_boot (void)
{
  asm volatile ("cli");

  return grub_efi_linux_boot ((char *)kernel_mem,
			      handover_offset,
			      params);
}

static grub_err_t
grub_linuxefi_unload (void)
{
  grub_dl_unref (my_mod);
  loaded = 0;

  kernel_free(initrd_mem, params->ramdisk_size);
  kernel_free(linux_cmdline, params->cmdline_size + 1);
  kernel_free(kernel_mem, kernel_size);
  kernel_free(params, sizeof(*params));

  return GRUB_ERR_NONE;
}

#define BOUNCE_BUFFER_MAX 0x10000000ull

static grub_ssize_t
read(grub_file_t file, grub_uint8_t *bufp, grub_size_t len)
{
  grub_ssize_t bufpos = 0;
  static grub_size_t bbufsz = 0;
  static char *bbuf = NULL;

  if (bbufsz == 0)
    bbufsz = MIN(BOUNCE_BUFFER_MAX, len);

  while (!bbuf && bbufsz)
    {
      bbuf = grub_malloc(bbufsz);
      if (!bbuf)
	bbufsz >>= 1;
    }
  if (!bbuf)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("cannot allocate bounce buffer"));

  while (bufpos < (long long)len)
    {
      grub_ssize_t sz;

      sz = grub_file_read (file, bbuf, MIN(bbufsz, len - bufpos));
      if (sz < 0)
	return sz;
      if (sz == 0)
	break;

      grub_memcpy(bufp + bufpos, bbuf, sz);
      bufpos += sz;
    }

  return bufpos;
}

#define LOW_U32(val) ((grub_uint32_t)(((grub_addr_t)(val)) & 0xffffffffull))
#define HIGH_U32(val) ((grub_uint32_t)(((grub_addr_t)(val) >> 32) & 0xffffffffull))

static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)),
                 int argc, char *argv[])
{
  grub_file_t *files = 0;
  int i, nfiles = 0;
  grub_size_t size = 0;
  grub_uint8_t *ptr;

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  if (!loaded)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("you need to load the kernel first"));
      goto fail;
    }

  files = grub_zalloc (argc * sizeof (files[0]));
  if (!files)
    goto fail;

  for (i = 0; i < argc; i++)
    {
      files[i] = grub_file_open (argv[i], GRUB_FILE_TYPE_LINUX_INITRD | GRUB_FILE_TYPE_NO_DECOMPRESS);
      if (! files[i])
        goto fail;
      nfiles++;
      size += ALIGN_UP (grub_file_size (files[i]), 4);
    }

  initrd_mem = kernel_alloc(size, N_("can't allocate initrd"));
  if (initrd_mem == NULL)
    goto fail;
  grub_dprintf ("linux", "initrd_mem = %p\n", initrd_mem);

  params->ramdisk_size = LOW_U32(size);
  params->ramdisk_image = LOW_U32(initrd_mem);
#if defined(__x86_64__)
  params->ext_ramdisk_size = HIGH_U32(size);
  params->ext_ramdisk_image = HIGH_U32(initrd_mem);
#endif

  ptr = initrd_mem;

  for (i = 0; i < nfiles; i++)
    {
      grub_ssize_t cursize = grub_file_size (files[i]);
      if (read (files[i], ptr, cursize) != cursize)
        {
          if (!grub_errno)
            grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file %s"),
                        argv[i]);
          goto fail;
        }
      ptr += cursize;
      grub_memset (ptr, 0, ALIGN_UP_OVERHEAD (cursize, 4));
      ptr += ALIGN_UP_OVERHEAD (cursize, 4);
    }

  params->ramdisk_size = size;

 fail:
  for (i = 0; i < nfiles; i++)
    grub_file_close (files[i]);
  grub_free (files);

  if (initrd_mem && grub_errno)
    grub_efi_free_pages ((grub_efi_physical_address_t)(grub_addr_t)initrd_mem,
			 BYTES_TO_PAGES(size));

  return grub_errno;
}

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_file_t file = 0;
  struct linux_i386_kernel_header *lh = NULL;
  grub_ssize_t start, filelen;
  void *kernel = NULL;
  int setup_header_end_offset;
  int rc;

  grub_dl_ref (my_mod);

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  file = grub_file_open (argv[0], GRUB_FILE_TYPE_LINUX_KERNEL);
  if (! file)
    goto fail;

  filelen = grub_file_size (file);

  kernel = grub_malloc(filelen);
  if (!kernel)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("cannot allocate kernel buffer"));
      goto fail;
    }

  if (grub_file_read (file, kernel, filelen) != filelen)
    {
      grub_error (GRUB_ERR_FILE_READ_ERROR, N_("Can't read kernel %s"),
		  argv[0]);
      goto fail;
    }

  rc = grub_linuxefi_secure_validate (kernel, filelen);
  if (rc < 0)
    {
      grub_error (GRUB_ERR_INVALID_COMMAND, N_("%s has invalid signature"),
		  argv[0]);
      goto fail;
    }

  lh = (struct linux_i386_kernel_header *)kernel;
  grub_dprintf ("linux", "original lh is at %p\n", kernel);

  grub_dprintf ("linux", "checking lh->boot_flag\n");
  if (lh->boot_flag != grub_cpu_to_le16 (0xaa55))
    {
      grub_error (GRUB_ERR_BAD_OS, N_("invalid magic number"));
      goto fail;
    }

  grub_dprintf ("linux", "checking lh->setup_sects\n");
  if (lh->setup_sects > GRUB_LINUX_MAX_SETUP_SECTS)
    {
      grub_error (GRUB_ERR_BAD_OS, N_("too many setup sectors"));
      goto fail;
    }

  grub_dprintf ("linux", "checking lh->version\n");
  if (lh->version < grub_cpu_to_le16 (0x020b))
    {
      grub_error (GRUB_ERR_BAD_OS, N_("kernel too old"));
      goto fail;
    }

  grub_dprintf ("linux", "checking lh->handover_offset\n");
  if (!lh->handover_offset)
    {
      grub_error (GRUB_ERR_BAD_OS, N_("kernel doesn't support EFI handover"));
      goto fail;
    }

#if defined(__x86_64__)
  grub_dprintf ("linux", "checking lh->xloadflags\n");
  if (!(lh->xloadflags & LINUX_XLF_KERNEL_64))
    {
      grub_error (GRUB_ERR_BAD_OS, N_("kernel doesn't support 64-bit CPUs"));
      goto fail;
    }
#endif

#if defined(__i386__)
  if ((lh->xloadflags & LINUX_XLF_KERNEL_64) &&
      !(lh->xloadflags & LINUX_XLF_EFI_HANDOVER_32))
    {
      grub_error (GRUB_ERR_BAD_OS,
		  N_("kernel doesn't support 32-bit handover"));
      goto fail;
    }
#endif

#if defined(__x86_64__)
  if (lh->xloadflags & LINUX_XLF_CAN_BE_LOADED_ABOVE_4G)
    {
      grub_dprintf ("linux", "Loading kernel above 4GB is supported; enabling.\n");
      max_addresses[2].addr = GRUB_EFI_MAX_USABLE_ADDRESS;
    }
  else
    {
      grub_dprintf ("linux", "Loading kernel above 4GB is not supported\n");
    }
#endif

  params = kernel_alloc (sizeof(*params), "cannot allocate kernel parameters");
  if (!params)
    goto fail;
  grub_dprintf ("linux", "params = %p\n", params);

  grub_memset (params, 0, sizeof(*params));

  setup_header_end_offset = *((grub_uint8_t *)kernel + 0x201);
  grub_dprintf ("linux", "copying %lu bytes from %p to %p\n",
		MIN((grub_size_t)0x202+setup_header_end_offset,
		    sizeof (*params)) - 0x1f1,
		(grub_uint8_t *)kernel + 0x1f1,
		(grub_uint8_t *)params + 0x1f1);
  grub_memcpy ((grub_uint8_t *)params + 0x1f1,
	       (grub_uint8_t *)kernel + 0x1f1,
		MIN((grub_size_t)0x202+setup_header_end_offset,sizeof (*params)) - 0x1f1);

  lh = (struct linux_i386_kernel_header *)params;
  grub_dprintf ("linux", "new lh is at %p\n", lh);

  grub_dprintf ("linux", "setting up cmdline\n");
  linux_cmdline = kernel_alloc (lh->cmdline_size + 1, N_("can't allocate cmdline"));
  if (!linux_cmdline)
    goto fail;
  grub_dprintf ("linux", "linux_cmdline = %p\n", linux_cmdline);

  grub_memcpy (linux_cmdline, LINUX_IMAGE, sizeof (LINUX_IMAGE));
  grub_create_loader_cmdline (argc, argv,
                              linux_cmdline + sizeof (LINUX_IMAGE) - 1,
			      lh->cmdline_size - (sizeof (LINUX_IMAGE) - 1),
			      GRUB_VERIFY_KERNEL_CMDLINE);

  grub_dprintf ("linux", "cmdline:%s\n", linux_cmdline);
  grub_dprintf ("linux", "setting lh->cmd_line_ptr to 0x%08x\n",
		LOW_U32(linux_cmdline));
  lh->cmd_line_ptr = LOW_U32(linux_cmdline);
#if defined(__x86_64__)
  if ((grub_efi_uintn_t)linux_cmdline > 0xffffffffull)
    {
      grub_dprintf ("linux", "setting params->ext_cmd_line_ptr to 0x%08x\n",
		    HIGH_U32(linux_cmdline));
      params->ext_cmd_line_ptr = HIGH_U32(linux_cmdline);
    }
#endif

  handover_offset = lh->handover_offset;
  grub_dprintf("linux", "handover_offset: 0x%08x\n", handover_offset);

  start = (lh->setup_sects + 1) * 512;

  /*
   * AFAICS >4GB for kernel *cannot* work because of params->code32_start being
   * 32-bit and getting called unconditionally in head_64.S from either entry
   * point.
   *
   * so nerf that out here...
   */
  save_addresses();
  grub_dprintf ("linux", "lh->pref_address: %p\n", (void *)(grub_addr_t)lh->pref_address);
  if (lh->pref_address < (grub_uint64_t)GRUB_EFI_MAX_ALLOCATION_ADDRESS)
    {
      max_addresses[0].addr = lh->pref_address;
      max_addresses[0].alloc_type = GRUB_EFI_ALLOCATE_ADDRESS;
    }
  max_addresses[1].addr = GRUB_EFI_MAX_ALLOCATION_ADDRESS;
  max_addresses[2].addr = GRUB_EFI_MAX_ALLOCATION_ADDRESS;
  kernel_mem = kernel_alloc (lh->init_size, N_("can't allocate kernel"));
  restore_addresses();
  if (!kernel_mem)
    goto fail;
  grub_dprintf("linux", "kernel_mem = %p\n", kernel_mem);

  grub_loader_set (grub_linuxefi_boot, grub_linuxefi_unload, 0);

  loaded = 1;

  grub_dprintf ("linux", "setting lh->code32_start to 0x%08x\n",
		LOW_U32(kernel_mem));
  lh->code32_start = LOW_U32(kernel_mem);

  grub_memcpy (kernel_mem, (char *)kernel + start, filelen - start);

  lh->type_of_loader = 0x6;
  grub_dprintf ("linux", "setting lh->type_of_loader = 0x%02x\n",
		lh->type_of_loader);

  params->ext_loader_type = 0;
  params->ext_loader_ver = 2;
  grub_dprintf ("linux",
		"setting lh->ext_loader_{type,ver} = {0x%02x,0x%02x}\n",
		params->ext_loader_type, params->ext_loader_ver);

fail:
  if (file)
    grub_file_close (file);

  if (kernel)
    grub_free (kernel);

  if (grub_errno != GRUB_ERR_NONE)
    {
      grub_dl_unref (my_mod);
      loaded = 0;
    }

  if (!loaded)
    {
      if (lh)
	kernel_free (linux_cmdline, lh->cmdline_size + 1);

      kernel_free (kernel_mem, kernel_size);
      kernel_free (params, sizeof(*params));
    }

  return grub_errno;
}

static grub_command_t cmd_linux, cmd_initrd;
static grub_command_t cmd_linuxefi, cmd_initrdefi;

GRUB_MOD_INIT(linux)
{
  cmd_linux =
    grub_register_command ("linux", grub_cmd_linux,
                           0, N_("Load Linux."));
  cmd_linuxefi =
    grub_register_command ("linuxefi", grub_cmd_linux,
                           0, N_("Load Linux."));
  cmd_initrd =
    grub_register_command ("initrd", grub_cmd_initrd,
                           0, N_("Load initrd."));
  cmd_initrdefi =
    grub_register_command ("initrdefi", grub_cmd_initrd,
                           0, N_("Load initrd."));
  my_mod = mod;
}

GRUB_MOD_FINI(linux)
{
  grub_unregister_command (cmd_linux);
  grub_unregister_command (cmd_linuxefi);
  grub_unregister_command (cmd_initrd);
  grub_unregister_command (cmd_initrdefi);
}
