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

#include <stddef.h> /* offsetof() */

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
#if defined(__powerpc__) || defined(__i386__)
#include <grub/ieee1275/alloc.h>
#endif

/* The maximum heap size we're going to claim at boot. Not used by sparc. */
#ifdef __i386__
#define HEAP_MAX_SIZE		(unsigned long) (64 * 1024 * 1024)
#else /* __powerpc__ */
#define HEAP_MAX_SIZE		(unsigned long) (32 * 1024 * 1024)
#endif

/* RMO max. address at 768 MB */
#define RMO_ADDR_MAX		(grub_uint64_t) (768 * 1024 * 1024)

/*
 * The amount of OF space we will not claim here so as to leave space for
 * the loader and linux to service early allocations.
 *
 * In 2021, Daniel Axtens claims that we should leave at least 128MB to
 * ensure we can load a stock kernel and initrd on a pseries guest with
 * a 512MB real memory area under PowerVM.
 */
#define RUNTIME_MIN_SPACE (128UL * 1024 * 1024)

extern char _start[];
extern char _end[];

#ifdef __sparc__
grub_addr_t grub_ieee1275_original_stack;
#endif

/* Options vector5 properties. */

#define LPAR                0x80
#define SPLPAR              0x40
#define DYN_RCON_MEM        0x20
#define LARGE_PAGES         0x10
#define DONATE_DCPU_CLS     0x02
#define PCI_EXP             0x01
#define BYTE2               (LPAR | SPLPAR | DYN_RCON_MEM | LARGE_PAGES | DONATE_DCPU_CLS | PCI_EXP)

#define CMOC                0x80
#define EXT_CMO             0x40
#define CMO                 (CMOC | EXT_CMO)

#define ASSOC_REF           0x80
#define AFFINITY            0x40
#define NUMA                0x20
#define ASSOCIATIVITY       (ASSOC_REF | AFFINITY | NUMA)

#define HOTPLUG_INTRPT      0x04
#define HPT_RESIZE          0x01
#define BIN_OPTS            (HOTPLUG_INTRPT | HPT_RESIZE)

#define MAX_CPU             256

#define PFO_HWRNG           0x80000000
#define PFO_HW_COMP         0x40000000
#define PFO_ENCRYPT         0x20000000
#define PLATFORM_FACILITIES (PFO_HWRNG | PFO_HW_COMP | PFO_ENCRYPT)

#define SUB_PROCESSORS      1

#define DY_MEM_V2           0x80
#define DRC_INFO            0x40
#define BYTE22              (DY_MEM_V2 | DRC_INFO)

void
grub_exit (void)
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
    *device = grub_ieee1275_encode_devname (bootpath);
  grub_free (type);

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
/* Helpers for mm on powerpc. */

/* ibm,kernel-dump data structures */
struct kd_section
{
  grub_uint32_t flags;
  grub_uint16_t src_datatype;
#define KD_SRC_DATATYPE_REAL_MODE_REGION  0x0011
  grub_uint16_t error_flags;
  grub_uint64_t src_address;
  grub_uint64_t num_bytes;
  grub_uint64_t act_bytes;
  grub_uint64_t dst_address;
} GRUB_PACKED;

#define MAX_KD_SECTIONS 10

struct kernel_dump
{
  grub_uint32_t format;
  grub_uint16_t num_sections;
  grub_uint16_t status_flags;
  grub_uint32_t offset_1st_section;
  grub_uint32_t num_blocks;
  grub_uint64_t start_block;
  grub_uint64_t num_blocks_avail;
  grub_uint32_t offet_path_string;
  grub_uint32_t max_time_allowed;
  struct kd_section kds[MAX_KD_SECTIONS]; /* offset_1st_section should point to kds[0] */
} GRUB_PACKED;

/*
 * Determine if a kernel dump exists and if it does, then determine the highest
 * address that grub can use for memory allocations.
 * The caller must have initialized *highest to rmo_top. *highest will not
 * be modified if no kernel dump is found.
 */
static void
check_kernel_dump (grub_uint64_t *highest)
{
  struct kernel_dump kernel_dump;
  grub_ssize_t kernel_dump_size;
  grub_ieee1275_phandle_t rtas;
  struct kd_section *kds;
  grub_size_t i;

  /* If there's a kernel-dump it must have at least one section */
  if (grub_ieee1275_finddevice ("/rtas", &rtas) ||
      grub_ieee1275_get_property (rtas, "ibm,kernel-dump", &kernel_dump,
                                  sizeof (kernel_dump), &kernel_dump_size) ||
      kernel_dump_size <= (grub_ssize_t) offsetof (struct kernel_dump, kds[1]))
    return;

  kernel_dump_size = grub_min (kernel_dump_size, (grub_ssize_t) sizeof (kernel_dump));

  if (grub_be_to_cpu32 (kernel_dump.format) != 1)
    {
      grub_printf (_("Error: ibm,kernel-dump has an unexpected format version '%u'\n"),
                   grub_be_to_cpu32 (kernel_dump.format));
      return;
    }

  if (grub_be_to_cpu16 (kernel_dump.num_sections) > MAX_KD_SECTIONS)
    {
      grub_printf (_("Error: Too many kernel dump sections: %d\n"),
                   grub_be_to_cpu32 (kernel_dump.num_sections));
      return;
    }

  for (i = 0; i < grub_be_to_cpu16 (kernel_dump.num_sections); i++)
    {
      kds = (struct kd_section *) ((grub_addr_t) &kernel_dump +
                                   grub_be_to_cpu32 (kernel_dump.offset_1st_section) +
                                   i * sizeof (struct kd_section));
      /* sanity check the address is within the 'kernel_dump' struct */
      if ((grub_addr_t) kds > (grub_addr_t) &kernel_dump + kernel_dump_size + sizeof (*kds))
        {
          grub_printf (_("Error: 'kds' address beyond last available section\n"));
          return;
        }

      if ((grub_be_to_cpu16 (kds->src_datatype) == KD_SRC_DATATYPE_REAL_MODE_REGION) &&
          (grub_be_to_cpu64 (kds->src_address) == 0))
        {
          *highest = grub_min (*highest, grub_be_to_cpu64 (kds->num_bytes));
          break;
        }
    }

  return;
}

/*
 * How much memory does OF believe exists in total?
 *
 * This isn't necessarily the true total. It can be the total memory
 * accessible in real mode for a pseries guest, for example.
 */
static grub_uint64_t rmo_top;

static int
count_free (grub_uint64_t addr, grub_uint64_t len, grub_memory_type_t type,
	    void *data)
{
  if (type != GRUB_MEMORY_AVAILABLE)
    return 0;

  /* Do not consider memory beyond 4GB */
  if (addr > 0xffffffffULL)
    return 0;

  if (addr + len > 0xffffffffULL)
    len = 0xffffffffULL - addr;

  *(grub_uint32_t *) data += len;

  return 0;
}

int
grub_regions_claim (grub_uint64_t addr, grub_uint64_t len,
		    grub_memory_type_t type, void *data)
{
  struct regions_claim_request *rcr = data;
  grub_uint64_t linux_rmo_save;

  if (type != GRUB_MEMORY_AVAILABLE)
    return 0;

  /* Do not consider memory beyond 4GB */
  if (addr > 0xffffffffULL)
    return 0;

  if (addr + len > 0xffffffffULL)
    len = 0xffffffffULL - addr;

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

  /*
   * Linux likes to claim memory at min(RMO top, 768MB) and works down
   * without reference to /memory/available. (See prom_init.c::alloc_down)
   *
   * If this block contains min(RMO top, 768MB), do not claim below that for
   * at least a few MB (this is where RTAS, SML and potentially TCEs live).
   *
   * We also need to leave enough space for the DT in the RMA. (See
   * prom_init.c::alloc_up)
   *
   * Finally, we also want to make sure that when grub loads the kernel,
   * it isn't going to use up all the memory we're trying to reserve! So
   * enforce our entire RUNTIME_MIN_SPACE here (no fadump):
   *
   * | Top of memory == upper_mem_limit -|
   * |                                   |
   * |             available             |
   * |                                   |
   * |----------     768 MB    ----------|
   * |                                   |
   * |              reserved             |
   * |                                   |
   * |--- 768 MB - runtime min space  ---|
   * |                                   |
   * |             available             |
   * |                                   |
   * |----------      0 MB     ----------|
   *
   * In case fadump is used, we allow the following:
   *
   * |---------- Top of memory ----------|
   * |                                   |
   * |             unavailable           |
   * |         (kernel dump area)        |
   * |                                   |
   * |--------- upper_mem_limit ---------|
   * |                                   |
   * |             available             |
   * |                                   |
   * |----------     768 MB    ----------|
   * |                                   |
   * |              reserved             |
   * |                                   |
   * |--- 768 MB - runtime min space  ---|
   * |                                   |
   * |             available             |
   * |                                   |
   * |----------      0 MB     ----------|
   *
   * Edge cases:
   *
   * - Total memory less than RUNTIME_MIN_SPACE: only claim up to HEAP_MAX_SIZE.
   *   (enforced elsewhere)
   *
   * - Total memory between RUNTIME_MIN_SPACE and 768MB:
   *
   * |---------- Top of memory ----------|
   * |                                   |
   * |              reserved             |
   * |                                   |
   * |----  top - runtime min space  ----|
   * |                                   |
   * |             available             |
   * |                                   |
   * |----------      0 MB     ----------|
   *
   * This by itself would not leave us with RUNTIME_MIN_SPACE of free bytes: if
   * rmo_top < 768MB, we will almost certainly have FW claims in the reserved
   * region. We try to address that elsewhere: grub_ieee1275_mm_add_region will
   * not call us if the resulting free space would be less than RUNTIME_MIN_SPACE.
   */
  linux_rmo_save = grub_min (RMO_ADDR_MAX, rmo_top) - RUNTIME_MIN_SPACE;
  if (rmo_top > RUNTIME_MIN_SPACE)
    {
      if (rmo_top <= RMO_ADDR_MAX)
        {
          if (addr > linux_rmo_save)
            {
              grub_dprintf ("ieee1275", "rejecting region in RUNTIME_MIN_SPACE reservation (%llx)\n",
                            addr);
              return 0;
            }
          else if (addr + len > linux_rmo_save)
            {
              grub_dprintf ("ieee1275", "capping region: (%llx -> %llx) -> (%llx -> %llx)\n",
                            addr, addr + len, addr, rmo_top - RUNTIME_MIN_SPACE);
              len = linux_rmo_save - addr;
            }
        }
      else
        {
          grub_uint64_t upper_mem_limit = rmo_top;
          grub_uint64_t orig_addr = addr;

          check_kernel_dump (&upper_mem_limit);

          grub_dprintf ("ieee1275", "upper_mem_limit is at %llx (%lld MiB)\n",
                        upper_mem_limit, upper_mem_limit >> 20);

          /*
           * we order these cases to prefer higher addresses and avoid some
           * splitting issues
           * The following shows the order of variables:
           *  no   kernel dump: linux_rmo_save < RMO_ADDR_MAX <= upper_mem_limit == rmo_top
           *  with kernel dump: liuxx_rmo_save < RMO_ADDR_MAX <= upper_mem_limit <= rmo_top
           */
          if (addr < RMO_ADDR_MAX && (addr + len) > RMO_ADDR_MAX && upper_mem_limit >= RMO_ADDR_MAX)
            {
              grub_dprintf ("ieee1275",
                            "adjusting region for RUNTIME_MIN_SPACE: (%llx -> %llx) -> (%llx -> %llx)\n",
                            addr, addr + len, RMO_ADDR_MAX, addr + len);
              len = (addr + len) - RMO_ADDR_MAX;
              addr = RMO_ADDR_MAX;

              /* We must not exceed the upper_mem_limit (assuming it's >= RMO_ADDR_MAX) */
              if (addr + len > upper_mem_limit)
                {
                  /* Take the bigger chunk from either below linux_rmo_save or above RMO_ADDR_MAX. */
                  len = upper_mem_limit - addr;
                  if (orig_addr < linux_rmo_save && linux_rmo_save - orig_addr > len)
                    {
                      /* lower part is bigger */
                      addr = orig_addr;
                      len = linux_rmo_save - addr;
                    }

                  grub_dprintf ("ieee1275", "re-adjusted region to: (%llx -> %llx)\n",
                                addr, addr + len);

                  if (len == 0)
                    return 0;
                }
            }
          else if ((addr < linux_rmo_save) && ((addr + len) > linux_rmo_save))
            {
              grub_dprintf ("ieee1275", "capping region: (%llx -> %llx) -> (%llx -> %llx)\n",
                            addr, addr + len, addr, linux_rmo_save);
              len = linux_rmo_save - addr;
            }
          else if (addr >= linux_rmo_save && (addr + len) <= RMO_ADDR_MAX)
            {
              grub_dprintf ("ieee1275", "rejecting region in RUNTIME_MIN_SPACE reservation (%llx)\n",
                            addr);
              return 0;
            }
        }
    }

  /* Honor alignment restrictions on candidate addr */
  if (rcr->align)
    {
      grub_uint64_t align_addr = ALIGN_UP (addr, rcr->align);
      grub_uint64_t d = align_addr - addr;

      if (d > len)
        return 0;

      len -= d;
      addr = align_addr;
    }

  if (rcr->flags & GRUB_MM_ADD_REGION_CONSECUTIVE && len < rcr->total)
    return 0;

  if (len > rcr->total)
    len = rcr->total;

  if (len)
    {
      grub_err_t err;
      /* Claim and use it.  */
      err = grub_claimmap (addr, len);
      if (err)
	return err;
      if (rcr->init_region)
          grub_mm_init_region ((void *) (grub_addr_t) addr, len);
      rcr->total -= len;

      rcr->addr = addr;
    }

  *(grub_uint32_t *) data = rcr->total;

  if (rcr->total == 0)
    return 1;

  return 0;
}

static int
heap_init (grub_uint64_t addr, grub_uint64_t len, grub_memory_type_t type,
	   void *data)
{
  struct regions_claim_request rcr = {
    .flags = GRUB_MM_ADD_REGION_NONE,
    .total = *(grub_uint32_t *) data,
    .init_region = true,
  };
  int ret;

  ret = grub_regions_claim (addr, len, type, &rcr);

  *(grub_uint32_t *) data = rcr.total;

  return ret;
}

static int
region_claim (grub_uint64_t addr, grub_uint64_t len, grub_memory_type_t type,
	   void *data)
{
  struct regions_claim_request rcr = {
    .flags = GRUB_MM_ADD_REGION_CONSECUTIVE,
    .total = *(grub_uint32_t *) data,
    .init_region = true,
  };
  int ret;

  ret = grub_regions_claim (addr, len, type, &rcr);

  *(grub_uint32_t *) data = rcr.total;

  return ret;
}

static grub_err_t
grub_ieee1275_mm_add_region (grub_size_t size, unsigned int flags)
{
  grub_uint32_t free_memory = 0;
  grub_uint32_t avail = 0;
  grub_uint32_t total;

  grub_dprintf ("ieee1275", "mm requested region of size %x, flags %x\n",
               size, flags);

  /*
   * Update free memory each time, which is a bit inefficient but guards us
   * against a situation where some OF driver goes out to firmware for
   * memory and we don't realise.
   */
  grub_machine_mmap_iterate (count_free, &free_memory);

  /* Ensure we leave enough space to boot. */
  if (free_memory <= RUNTIME_MIN_SPACE + size)
    {
      grub_dprintf ("ieee1275", "Cannot satisfy allocation and retain minimum runtime space\n");
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  if (free_memory > RUNTIME_MIN_SPACE)
      avail = free_memory - RUNTIME_MIN_SPACE;

  grub_dprintf ("ieee1275", "free = 0x%x available = 0x%x\n", free_memory, avail);

  if (flags & GRUB_MM_ADD_REGION_CONSECUTIVE)
    {
      /* first try rounding up hard for the sake of speed */
      total = grub_max (ALIGN_UP (size, 1024 * 1024) + 1024 * 1024, 32 * 1024 * 1024);
      total = grub_min (avail, total);

      grub_dprintf ("ieee1275", "looking for %x bytes of memory (%x requested)\n", total, size);

      grub_machine_mmap_iterate (region_claim, &total);
      grub_dprintf ("ieee1275", "get memory from fw %s\n", total == 0 ? "succeeded" : "failed");

      if (total != 0)
        {
          total = grub_min (avail, size);

          grub_dprintf ("ieee1275", "fallback for %x bytes of memory (%x requested)\n", total, size);

          grub_machine_mmap_iterate (region_claim, &total);
          grub_dprintf ("ieee1275", "fallback from fw %s\n", total == 0 ? "succeeded" : "failed");
        }
    }
  else
    {
      /* provide padding for a grub_mm_header_t and region */
      total = grub_min (avail, size);
      grub_machine_mmap_iterate (heap_init, &total);
      grub_dprintf ("ieee1275", "get noncontig memory from fw %s\n", total == 0 ? "succeeded" : "failed");
    }

  if (total == 0)
    return GRUB_ERR_NONE;
  else
    return GRUB_ERR_OUT_OF_MEMORY;
}

/*
 * How much memory does OF believe it has? (regardless of whether
 * it's accessible or not)
 */
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
  if (grub_ieee1275_finddevice ("/", &root))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "couldn't find / node");
  if (grub_ieee1275_get_integer_property (root, "#address-cells", &address_cells,
					  sizeof (address_cells), 0))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "couldn't examine #address-cells");
  if (grub_ieee1275_get_integer_property (root, "#size-cells", &size_cells,
					  sizeof (size_cells), 0))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "couldn't examine #size-cells");

  if (size_cells > address_cells)
    address_cells = size_cells;

  /* Load `/memory/reg'.  */
  if (grub_ieee1275_finddevice ("/memory", &memory))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "couldn't find /memory node");
  if (grub_ieee1275_get_integer_property (memory, "reg", reg,
					  sizeof (reg), &reg_size))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "couldn't examine /memory/reg property");
  if (reg_size < 0 || (grub_size_t) reg_size > sizeof (reg))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "/memory response buffer exceeded");

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

#if defined(__powerpc__)

/* See PAPR or arch/powerpc/kernel/prom_init.c */
struct option_vector2
{
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
} GRUB_PACKED;

struct option_vector5
{
  grub_uint8_t byte1;
  grub_uint8_t byte2;
  grub_uint8_t byte3;
  grub_uint8_t cmo;
  grub_uint8_t associativity;
  grub_uint8_t bin_opts;
  grub_uint8_t micro_checkpoint;
  grub_uint8_t reserved0;
  grub_uint32_t max_cpus;
  grub_uint16_t base_papr;
  grub_uint16_t mem_reference;
  grub_uint32_t platform_facilities;
  grub_uint8_t sub_processors;
  grub_uint8_t byte22;
} GRUB_PACKED;

struct pvr_entry
{
  grub_uint32_t mask;
  grub_uint32_t entry;
};

struct cas_vector
{
  struct
  {
    struct pvr_entry terminal;
  } pvr_list;
  grub_uint8_t num_vecs;
  grub_uint8_t vec1_size;
  grub_uint8_t vec1;
  grub_uint8_t vec2_size;
  struct option_vector2 vec2;
  grub_uint8_t vec3_size;
  grub_uint16_t vec3;
  grub_uint8_t vec4_size;
  grub_uint16_t vec4;
  grub_uint8_t vec5_size;
  struct option_vector5 vec5;
} GRUB_PACKED;

/*
 * Call ibm,client-architecture-support to try to get more RMA.
 * We ask for 512MB which should be enough to verify a distro kernel.
 * We ignore most errors: if we don't succeed we'll proceed with whatever
 * memory we have.
 */
static void
grub_ieee1275_ibm_cas (void)
{
  int rc;
  grub_ieee1275_ihandle_t root;
  struct cas_args
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t method;
    grub_ieee1275_ihandle_t ihandle;
    grub_ieee1275_cell_t cas_addr;
    grub_ieee1275_cell_t result;
  } args;
  struct cas_vector vector =
  {
    .pvr_list = { { 0x00000000, 0xffffffff } }, /* any processor */
    .num_vecs = 5 - 1,
    .vec1_size = 0,
    .vec1 = 0x80, /* ignore */
    .vec2_size = 1 + sizeof (struct option_vector2) - 2,
    .vec2 = {
      0, 0, -1, -1, -1, -1, -1, 512, -1, 0, 48
    },
    .vec3_size = 2 - 1,
    .vec3 = 0x00e0, /* ask for FP + VMX + DFP but don't halt if unsatisfied */
    .vec4_size = 2 - 1,
    .vec4 = 0x0001, /* set required minimum capacity % to the lowest value */
    .vec5_size = 1 + sizeof (struct option_vector5) - 2,
    .vec5 = {
      0, BYTE2, 0, CMO, ASSOCIATIVITY, BIN_OPTS, 0, 0, MAX_CPU, 0, 0, PLATFORM_FACILITIES, SUB_PROCESSORS, BYTE22
    }
  };

  INIT_IEEE1275_COMMON (&args.common, "call-method", 3, 2);
  args.method = (grub_ieee1275_cell_t) "ibm,client-architecture-support";
  rc = grub_ieee1275_open ("/", &root);
  if (rc)
    {
      grub_error (GRUB_ERR_IO, "could not open root when trying to call CAS");
      return;
    }
  args.ihandle = root;
  args.cas_addr = (grub_ieee1275_cell_t) &vector;

  grub_printf ("Calling ibm,client-architecture-support from grub...");
  IEEE1275_CALL_ENTRY_FN (&args);
  grub_printf ("done\n");

  grub_ieee1275_close (root);
}

#endif /* __powerpc__ */

static void
grub_claim_heap (void)
{
  grub_err_t err;
  grub_uint32_t total = HEAP_MAX_SIZE;

  err = grub_ieee1275_total_mem (&rmo_top);

  /*
   * If we cannot size the available memory, we can't be sure we're leaving
   * space for the kernel, initrd and things Linux loads early in boot. So only
   * allow further allocations from firmware on success
   */
  if (err == GRUB_ERR_NONE)
    grub_mm_add_region_fn = grub_ieee1275_mm_add_region;

#if defined(__powerpc__)
  if (grub_ieee1275_test_flag (GRUB_IEEE1275_FLAG_CAN_TRY_CAS_FOR_MORE_MEMORY))
    {
      /* if we have an error, don't call CAS, just hope for the best */
      if (err == GRUB_ERR_NONE && rmo_top < (512 * 1024 * 1024))
	grub_ieee1275_ibm_cas ();
    }
#endif

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
