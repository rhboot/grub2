/*  init.c -- Initialize GRUB on the newworld mac (PPC).  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2007,2008,2009 Free Software Foundation, Inc.
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

#include <grub/kernel.h>
#include <grub/dl.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/partition.h>
#include <grub/normal.h>
#include <grub/fs.h>
#include <grub/setjmp.h>
#include <grub/env.h>
#include <grub/misc.h>
#include <grub/time.h>
#include <grub/ieee1275/console.h>
#include <grub/ieee1275/ofdisk.h>
#ifdef __sparc__
#include <grub/ieee1275/obdisk.h>
#endif
#include <grub/ieee1275/ieee1275.h>
#include <grub/net.h>
#include <grub/offsets.h>
#include <grub/memory.h>
#include <grub/loader.h>
#ifdef __i386__
#include <grub/cpu/tsc.h>
#endif
#ifdef __sparc__
#include <grub/machine/kernel.h>
#endif
#include <grub/lockdown.h>

/* The maximum heap size we're going to claim. Not used by sparc.
   We allocate 1/4 of the available memory under 4G, up to this limit. */
#ifdef __i386__
#define HEAP_MAX_SIZE		(unsigned long) (64 * 1024 * 1024)
#else // __powerpc__
#define HEAP_MAX_SIZE		(unsigned long) (1 * 1024 * 1024 * 1024)
#endif

extern char _end[];

#ifdef __sparc__
grub_addr_t grub_ieee1275_original_stack;
#endif

void
grub_exit (int rc __attribute__((unused)))
{
  grub_ieee1275_exit ();
}

/* Translate an OF filesystem path (separated by backslashes), into a GRUB
   path (separated by forward slashes).  */
static void
grub_translate_ieee1275_path (char *filepath)
{
  char *backslash;

  backslash = grub_strchr (filepath, '\\');
  while (backslash != 0)
    {
      *backslash = '/';
      backslash = grub_strchr (filepath, '\\');
    }
}

void (*grub_ieee1275_net_config) (const char *dev, char **device, char **path,
                                  char *bootpath);
void
grub_machine_get_bootlocation (char **device, char **path)
{
  char *bootpath;
  char *filename;
  char *type;

  bootpath = grub_ieee1275_get_boot_dev ();
  if (! bootpath)
    return;

  /* Transform an OF device path to a GRUB path.  */

  type = grub_ieee1275_get_device_type (bootpath);
  if (type && grub_strcmp (type, "network") == 0)
    {
      char *dev, *canon;
      char *ptr;
      dev = grub_ieee1275_get_aliasdevname (bootpath);
      canon = grub_ieee1275_canonicalise_devname (dev);
      if (! canon)
        return;
      ptr = canon + grub_strlen (canon) - 1;
      while (ptr > canon && (*ptr == ',' || *ptr == ':'))
	ptr--;
      ptr++;
      *ptr = 0;

      if (grub_ieee1275_net_config)
	grub_ieee1275_net_config (canon, device, path, bootpath);
      grub_free (dev);
      grub_free (canon);
    }
  else
    {
      filename = grub_ieee1275_get_filename (bootpath);
      if (filename)
        {
          char *lastslash = grub_strrchr (filename, '\\');

          /* Truncate at last directory.  */
          if (lastslash)
            {
              *lastslash = '\0';
              grub_translate_ieee1275_path (filename);

              *path = filename;
            }
        }
      *device = grub_ieee1275_encode_devname (bootpath);
    }

  grub_free (type);
  grub_free (bootpath);
}

/* Claim some available memory in the first /memory node. */
#ifdef __sparc__
static void 
grub_claim_heap (void)
{
  grub_mm_init_region ((void *) (grub_modules_get_end ()
				 + GRUB_KERNEL_MACHINE_STACK_SIZE), 0x200000);
}
#else
/* Helper for grub_claim_heap on powerpc. */
static int
heap_size (grub_uint64_t addr, grub_uint64_t len, grub_memory_type_t type,
	   void *data)
{
  grub_uint32_t total = *(grub_uint32_t *)data;

  if (type != GRUB_MEMORY_AVAILABLE)
    return 0;

  /* Do not consider memory beyond 4GB */
  if (addr > 0xffffffffUL)
    return 0;

  if (addr + len > 0xffffffffUL)
    len = 0xffffffffUL - addr;

  total += len;
  *(grub_uint32_t *)data = total;

  return 0;
}

static int
heap_init (grub_uint64_t addr, grub_uint64_t len, grub_memory_type_t type,
	   void *data)
{
  grub_uint32_t total = *(grub_uint32_t *)data;

  if (type != GRUB_MEMORY_AVAILABLE)
    return 0;

  /* Do not consider memory beyond 4GB */
  if (addr > 0xffffffffUL)
    return 0;

  if (addr + len > 0xffffffffUL)
    len = 0xffffffffUL - addr;

  if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_NO_PRE1_5M_CLAIM))
    {
      if (addr + len <= 0x180000)
	return 0;

      if (addr < 0x180000)
	{
	  len = addr + len - 0x180000;
	  addr = 0x180000;
	}
    }
  len -= 1; /* Required for some firmware.  */

  /* In theory, firmware should already prevent this from happening by not
     listing our own image in /memory/available.  The check below is intended
     as a safeguard in case that doesn't happen.  However, it doesn't protect
     us from corrupting our module area, which extends up to a
     yet-undetermined region above _end.  */
  if ((addr < (grub_addr_t) _end) && ((addr + len) > (grub_addr_t) _start))
    {
      grub_printf ("Warning: attempt to claim over our own code!\n");
      len = 0;
    }

  /* If this block contains 0x30000000 (768MB), do not claim below that.
     Linux likes to claim memory at min(RMO top, 768MB) and works down
     without reference to /memory/available. */
  if ((addr < 0x30000000) && ((addr + len) > 0x30000000))
    {
      len = len - (0x30000000 - addr);
      addr = 0x30000000;
    }

  if (len > total)
    len = total;

  if (len)
    {
      grub_err_t err;
      /* Claim and use it.  */
      err = grub_claimmap (addr, len);
      if (err)
	return err;
      grub_mm_init_region ((void *) (grub_addr_t) addr, len);
      total -= len;
    }

  *(grub_uint32_t *)data = total;

  if (total == 0)
    return 1;

  return 0;
}

/* How much memory does OF believe it has? (regardless of whether
   it's accessible or not) */
static grub_err_t
grub_ieee1275_total_mem (grub_uint64_t *total)
{
  grub_ieee1275_phandle_t root;
  grub_ieee1275_phandle_t memory;
  grub_uint32_t reg[4];
  grub_ssize_t reg_size;
  grub_uint32_t address_cells = 1;
  grub_uint32_t size_cells = 1;
  grub_uint64_t size;

  /* If we fail to get to the end, report 0. */
  *total = 0;

  /* Determine the format of each entry in `reg'.  */
  grub_ieee1275_finddevice ("/", &root);
  grub_ieee1275_get_integer_property (root, "#address-cells", &address_cells,
				      sizeof address_cells, 0);
  grub_ieee1275_get_integer_property (root, "#size-cells", &size_cells,
				      sizeof size_cells, 0);

  if (size_cells > address_cells)
    address_cells = size_cells;

  /* Load `/memory/reg'.  */
  if (grub_ieee1275_finddevice ("/memory", &memory))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE,
		       "couldn't find /memory node");
  if (grub_ieee1275_get_integer_property (memory, "reg", reg,
					  sizeof reg, &reg_size))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE,
		       "couldn't examine /memory/reg property");
  if (reg_size < 0 || (grub_size_t) reg_size > sizeof (reg))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE,
                       "/memory response buffer exceeded");

  if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_BROKEN_ADDRESS_CELLS))
    {
      address_cells = 1;
      size_cells = 1;
    }

  /* Decode only the size */
  size = reg[address_cells];
  if (size_cells == 2)
    size = (size << 32) | reg[address_cells + 1];

  *total = size;

  return grub_errno;
}

/* Based on linux - arch/powerpc/kernel/prom_init.c */
struct option_vector2 {
	grub_uint8_t byte1;
	grub_uint16_t reserved;
	grub_uint32_t real_base;
	grub_uint32_t real_size;
	grub_uint32_t virt_base;
	grub_uint32_t virt_size;
	grub_uint32_t load_base;
	grub_uint32_t min_rma;
	grub_uint32_t min_load;
	grub_uint8_t min_rma_percent;
	grub_uint8_t max_pft_size;
} __attribute__((packed));

struct pvr_entry {
	  grub_uint32_t mask;
	  grub_uint32_t entry;
};

struct cas_vector {
    struct {
      struct pvr_entry terminal;
    } pvr_list;
    grub_uint8_t num_vecs;
    grub_uint8_t vec1_size;
    grub_uint8_t vec1;
    grub_uint8_t vec2_size;
    struct option_vector2 vec2;
} __attribute__((packed));

/* Call ibm,client-architecture-support to try to get more RMA.
   We ask for 512MB which should be enough to verify a distro kernel.
   We ignore most errors: if we don't succeed we'll proceed with whatever
   memory we have. */
static void
grub_ieee1275_ibm_cas (void)
{
  int rc;
  grub_ieee1275_ihandle_t root;
  struct cas_args {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t method;
    grub_ieee1275_ihandle_t ihandle;
    grub_ieee1275_cell_t cas_addr;
    grub_ieee1275_cell_t result;
  } args;
  struct cas_vector vector = {
    .pvr_list = { { 0x00000000, 0xffffffff } }, /* any processor */
    .num_vecs = 2 - 1,
    .vec1_size = 0,
    .vec1 = 0x80, /* ignore */
    .vec2_size = 1 + sizeof(struct option_vector2) - 2,
    .vec2 = {
      0, 0, -1, -1, -1, -1, -1, 512, -1, 0, 48
    },
  };

  INIT_IEEE1275_COMMON (&args.common, "call-method", 3, 2);
  args.method = (grub_ieee1275_cell_t)"ibm,client-architecture-support";
  rc = grub_ieee1275_open("/", &root);
  if (rc) {
	  grub_error (GRUB_ERR_IO, "could not open root when trying to call CAS");
	  return;
  }
  args.ihandle = root;
  args.cas_addr = (grub_ieee1275_cell_t)&vector;

  grub_printf("Calling ibm,client-architecture-support...");
  IEEE1275_CALL_ENTRY_FN (&args);
  grub_printf("done\n");

  grub_ieee1275_close(root);
}

static void 
grub_claim_heap (void)
{
  grub_uint32_t total = 0;

  if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_FORCE_CLAIM))
    {
      heap_init (GRUB_IEEE1275_STATIC_HEAP_START,
		 GRUB_IEEE1275_STATIC_HEAP_LEN, 1, &total);
      return;
    }

  if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_CAN_TRY_CAS_FOR_MORE_MEMORY))
    {
      grub_uint64_t rma_size;
      grub_err_t err;

      err = grub_ieee1275_total_mem (&rma_size);
      /* if we have an error, don't call CAS, just hope for the best */
      if (!err && rma_size < (512 * 1024 * 1024))
	grub_ieee1275_ibm_cas();
    }

  grub_machine_mmap_iterate (heap_size, &total);

  total = total / 4;
  if (total > HEAP_MAX_SIZE)
    total = HEAP_MAX_SIZE;

  grub_machine_mmap_iterate (heap_init, &total);
}
#endif

static void
grub_parse_cmdline (void)
{
  grub_ssize_t actual;
  char args[256];

  if (grub_ieee1275_get_property (grub_ieee1275_chosen, "bootargs", &args,
				  sizeof args, &actual) == 0
      && actual > 1)
    {
      int i = 0;

      while (i < actual)
	{
	  char *command = &args[i];
	  char *end;
	  char *val;

	  end = grub_strchr (command, ';');
	  if (end == 0)
	    i = actual; /* No more commands after this one.  */
	  else
	    {
	      *end = '\0';
	      i += end - command + 1;
	      while (grub_isspace(args[i]))
		i++;
	    }

	  /* Process command.  */
	  val = grub_strchr (command, '=');
	  if (val)
	    {
	      *val = '\0';
	      grub_env_set (command, val + 1);
	    }
	}
    }
}

static void
grub_get_ieee1275_secure_boot (void)
{
  grub_ieee1275_phandle_t root;
  int rc;
  grub_uint32_t is_sb;

  grub_ieee1275_finddevice ("/", &root);

  rc = grub_ieee1275_get_integer_property (root, "ibm,secure-boot", &is_sb,
                                           sizeof (is_sb), 0);

  /* ibm,secure-boot:
   * 0 - disabled
   * 1 - audit
   * 2 - enforce
   * 3 - enforce + OS-specific behaviour
   *
   * We only support enforce.
   */
  if (rc >= 0 && is_sb >= 2)
    grub_lockdown ();
}

grub_addr_t grub_modbase;

void
grub_machine_init (void)
{
  grub_modbase = ALIGN_UP((grub_addr_t) _end 
			  + GRUB_KERNEL_MACHINE_MOD_GAP,
			  GRUB_KERNEL_MACHINE_MOD_ALIGN);
  grub_ieee1275_init ();

  grub_console_init_early ();
  grub_claim_heap ();
  grub_console_init_lately ();
#ifdef __sparc__
  grub_obdisk_init ();
#else
  grub_ofdisk_init ();
#endif
  grub_parse_cmdline ();

#ifdef __i386__
  grub_tsc_init ();
#else
  grub_install_get_time_ms (grub_rtc_get_time_ms);
#endif

  grub_get_ieee1275_secure_boot ();
}

void
grub_machine_fini (int flags)
{
  if (flags & GRUB_LOADER_FLAG_NORETURN)
    {
#ifdef __sparc__
      grub_obdisk_fini ();
#else
      grub_ofdisk_fini ();
#endif
      grub_console_fini ();
    }
}

grub_uint64_t
grub_rtc_get_time_ms (void)
{
  grub_uint32_t msecs = 0;

  grub_ieee1275_milliseconds (&msecs);

  return msecs;
}
