/* mm.c - generic EFI memory management */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007,2008,2009  Free Software Foundation, Inc.
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
#include <grub/mm.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/cpu/efi/memory.h>

#if defined (__i386__) || defined (__x86_64__)
#include <grub/pci.h>
#endif

#define NEXT_MEMORY_DESCRIPTOR(desc, size)	\
  ((grub_efi_memory_descriptor_t *) ((char *) (desc) + (size)))

#define BYTES_TO_PAGES(bytes)	(((bytes) + 0xfff) >> 12)
#define BYTES_TO_PAGES_DOWN(bytes)	((bytes) >> 12)
#define PAGES_TO_BYTES(pages)	((pages) << 12)

/* The size of a memory map obtained from the firmware. This must be
   a multiplier of 4KB.  */
#define MEMORY_MAP_SIZE	0x3000

/* The default heap size for GRUB itself in bytes.  */
#define DEFAULT_HEAP_SIZE	0x100000

static void *finish_mmap_buf = 0;
static grub_efi_uintn_t finish_mmap_size = 0;
static grub_efi_uintn_t finish_key = 0;
static grub_efi_uintn_t finish_desc_size;
static grub_efi_uint32_t finish_desc_version;
int grub_efi_is_finished = 0;

/*
 * We need to roll back EFI allocations on exit. Remember allocations that
 * we'll free on exit.
 */
struct efi_allocation;
struct efi_allocation {
	grub_efi_physical_address_t address;
	grub_efi_uint64_t pages;
	struct efi_allocation *next;
};
static struct efi_allocation *efi_allocated_memory;

static void
grub_efi_store_alloc (grub_efi_physical_address_t address,
                         grub_efi_uintn_t pages)
{
  grub_efi_boot_services_t *b;
  struct efi_allocation *alloc;
  grub_efi_status_t status;

  b = grub_efi_system_table->boot_services;
  status = efi_call_3 (b->allocate_pool, GRUB_EFI_LOADER_DATA,
                           sizeof(*alloc), (void**)&alloc);

  if (status == GRUB_EFI_SUCCESS)
    {
      alloc->next = efi_allocated_memory;
      alloc->address = address;
      alloc->pages = pages;
      efi_allocated_memory = alloc;
    }
  else
      grub_printf ("Could not malloc memory to remember EFI allocation. "
                   "Exiting GRUB won't free all memory.\n");
}

static void
grub_efi_drop_alloc (grub_efi_physical_address_t address,
                           grub_efi_uintn_t pages)
{
  struct efi_allocation *ea, *eap;
  grub_efi_boot_services_t *b;

  b = grub_efi_system_table->boot_services;

  for (eap = NULL, ea = efi_allocated_memory; ea; eap = ea, ea = ea->next)
    {
      if (ea->address != address || ea->pages != pages)
         continue;

      /* Remove the current entry from the list. */
      if (eap)
        eap->next = ea->next;
      else
        efi_allocated_memory = ea->next;

      /* Then free the memory backing it. */
      efi_call_1 (b->free_pool, ea);

      /* And leave, we're done. */
      break;
    }
}

/* Allocate pages below a specified address */
void *
grub_efi_allocate_pages_max (grub_efi_physical_address_t max,
			     grub_efi_uintn_t pages)
{
  grub_efi_status_t status;
  grub_efi_boot_services_t *b;
  grub_efi_physical_address_t address = max;

  if (max > GRUB_EFI_MAX_USABLE_ADDRESS)
    return 0;

  b = grub_efi_system_table->boot_services;
  status = efi_call_4 (b->allocate_pages, GRUB_EFI_ALLOCATE_MAX_ADDRESS, GRUB_EFI_LOADER_DATA, pages, &address);

  if (status != GRUB_EFI_SUCCESS)
    return 0;

  if (address == 0)
    {
      /* Uggh, the address 0 was allocated... This is too annoying,
	 so reallocate another one.  */
      address = max;
      status = efi_call_4 (b->allocate_pages, GRUB_EFI_ALLOCATE_MAX_ADDRESS, GRUB_EFI_LOADER_DATA, pages, &address);
      grub_efi_free_pages (0, pages);
      if (status != GRUB_EFI_SUCCESS)
	return 0;
    }

  return (void *) ((grub_addr_t) address);
}

/* Allocate pages. Return the pointer to the first of allocated pages.  */
void *
grub_efi_allocate_pages_real (grub_efi_physical_address_t address,
			      grub_efi_uintn_t pages,
			      grub_efi_allocate_type_t alloctype,
			      grub_efi_memory_type_t memtype)
{
  grub_efi_status_t status;
  grub_efi_boot_services_t *b;
  grub_efi_physical_address_t ret = address;

  /* Limit the memory access to less than 4GB for 32-bit platforms.  */
  if (address > GRUB_EFI_MAX_USABLE_ADDRESS)
    {
      char inv_addr[17], max_addr[17]; /* log16(2^64) = 16, plus NUL. */

      grub_snprintf (inv_addr, sizeof (inv_addr) - 1, "%" PRIxGRUB_UINT64_T,
		     address);
      grub_snprintf (max_addr, sizeof (max_addr) - 1, "%" PRIxGRUB_UINT64_T,
		     (grub_efi_uint64_t) GRUB_EFI_MAX_USABLE_ADDRESS);
      grub_error (GRUB_ERR_BAD_ARGUMENT,
		  N_("invalid memory address (0x%s > 0x%s)"), inv_addr, max_addr);
      return NULL;
    }

  b = grub_efi_system_table->boot_services;
  status = efi_call_4 (b->allocate_pages, alloctype, memtype, pages, &ret);
  if (status != GRUB_EFI_SUCCESS)
    {
      grub_dprintf ("efi",
		    "allocate_pages(%d, %d, 0x%0lx, 0x%016lx) = 0x%016lx\n",
		    alloctype, memtype, pages, address, status);
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      return NULL;
    }

  if (ret == 0)
    {
      /* Uggh, the address 0 was allocated... This is too annoying,
	 so reallocate another one.  */
      ret = address;
      status = efi_call_4 (b->allocate_pages, alloctype, memtype, pages, &ret);
      grub_efi_free_pages (0, pages);
      if (status != GRUB_EFI_SUCCESS)
	{
	  grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	  return NULL;
	}
    }

  grub_efi_store_alloc (ret, pages);

  return (void *) ((grub_addr_t) ret);
}

void *
grub_efi_allocate_any_pages (grub_efi_uintn_t pages)
{
  return grub_efi_allocate_pages_real (GRUB_EFI_MAX_USABLE_ADDRESS,
				       pages, GRUB_EFI_ALLOCATE_MAX_ADDRESS,
				       GRUB_EFI_LOADER_DATA);
}

void *
grub_efi_allocate_fixed (grub_efi_physical_address_t address,
			 grub_efi_uintn_t pages)
{
  return grub_efi_allocate_pages_real (address, pages,
				       GRUB_EFI_ALLOCATE_ADDRESS,
				       GRUB_EFI_LOADER_DATA);
}

/* Free pages starting from ADDRESS.  */
void
grub_efi_free_pages (grub_efi_physical_address_t address,
		     grub_efi_uintn_t pages)
{
  grub_efi_boot_services_t *b;

  b = grub_efi_system_table->boot_services;
  efi_call_2 (b->free_pages, address, pages);

  grub_efi_drop_alloc (address, pages);
}

#if defined (__i386__) || defined (__x86_64__)

/* Helper for stop_broadcom.  */
static int
find_card (grub_pci_device_t dev, grub_pci_id_t pciid,
	   void *data __attribute__ ((unused)))
{
  grub_pci_address_t addr;
  grub_uint8_t cap;
  grub_uint16_t pm_state;

  if ((pciid & 0xffff) != GRUB_PCI_VENDOR_BROADCOM)
    return 0;

  addr = grub_pci_make_address (dev, GRUB_PCI_REG_CLASS);
  if (grub_pci_read (addr) >> 24 != GRUB_PCI_CLASS_NETWORK)
    return 0;
  cap = grub_pci_find_capability (dev, GRUB_PCI_CAP_POWER_MANAGEMENT);
  if (!cap)
    return 0;
  addr = grub_pci_make_address (dev, cap + 4);
  pm_state = grub_pci_read_word (addr);
  pm_state = pm_state | 0x03;
  grub_pci_write_word (addr, pm_state);
  grub_pci_read_word (addr);
  return 0;
}

static void
stop_broadcom (void)
{
  grub_pci_iterate (find_card, NULL);
}

#endif

grub_err_t
grub_efi_finish_boot_services (grub_efi_uintn_t *outbuf_size, void *outbuf,
			       grub_efi_uintn_t *map_key,
			       grub_efi_uintn_t *efi_desc_size,
			       grub_efi_uint32_t *efi_desc_version)
{
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;

#if defined (__i386__) || defined (__x86_64__)
  const grub_uint16_t apple[] = { 'A', 'p', 'p', 'l', 'e' };
  int is_apple;

  is_apple = (grub_memcmp (grub_efi_system_table->firmware_vendor,
			   apple, sizeof (apple)) == 0);
#endif

  while (1)
    {
      if (grub_efi_get_memory_map (&finish_mmap_size, finish_mmap_buf, &finish_key,
				   &finish_desc_size, &finish_desc_version) < 0)
	return grub_error (GRUB_ERR_IO, "couldn't retrieve memory map");

      if (outbuf && *outbuf_size < finish_mmap_size)
	return grub_error (GRUB_ERR_IO, "memory map buffer is too small");

      finish_mmap_buf = grub_malloc (finish_mmap_size);
      if (!finish_mmap_buf)
	return grub_errno;

      if (grub_efi_get_memory_map (&finish_mmap_size, finish_mmap_buf, &finish_key,
				   &finish_desc_size, &finish_desc_version) <= 0)
	{
	  grub_free (finish_mmap_buf);
	  return grub_error (GRUB_ERR_IO, "couldn't retrieve memory map");
	}

      b = grub_efi_system_table->boot_services;
      status = efi_call_2 (b->exit_boot_services, grub_efi_image_handle,
			   finish_key);
      if (status == GRUB_EFI_SUCCESS)
	break;

      if (status != GRUB_EFI_INVALID_PARAMETER)
	{
	  grub_free (finish_mmap_buf);
	  return grub_error (GRUB_ERR_IO, "couldn't terminate EFI services");
	}

      grub_free (finish_mmap_buf);
      grub_printf ("Trying to terminate EFI services again\n");
    }
  grub_efi_is_finished = 1;
  if (outbuf_size)
    *outbuf_size = finish_mmap_size;
  if (outbuf)
    grub_memcpy (outbuf, finish_mmap_buf, finish_mmap_size);
  if (map_key)
    *map_key = finish_key;
  if (efi_desc_size)
    *efi_desc_size = finish_desc_size;
  if (efi_desc_version)
    *efi_desc_version = finish_desc_version;

#if defined (__i386__) || defined (__x86_64__)
  if (is_apple)
    stop_broadcom ();
#endif

  return GRUB_ERR_NONE;
}

/*
 * To obtain the UEFI memory map, we must pass a buffer of sufficient size
 * to hold the entire map. This function returns a sane start value for
 * buffer size.
 */
grub_efi_uintn_t
grub_efi_find_mmap_size (void)
{
  grub_efi_uintn_t mmap_size = 0;
  grub_efi_uintn_t desc_size;

  if (grub_efi_get_memory_map (&mmap_size, NULL, NULL, &desc_size, 0) < 0)
    {
      grub_error (GRUB_ERR_IO, "cannot get EFI memory map size");
      return 0;
    }

  /*
   * Add an extra page, since UEFI can alter the memory map itself on
   * callbacks or explicit calls, including console output.
   */
  return ALIGN_UP (mmap_size + GRUB_EFI_PAGE_SIZE, GRUB_EFI_PAGE_SIZE);
}

/* Get the memory map as defined in the EFI spec. Return 1 if successful,
   return 0 if partial, or return -1 if an error occurs.  */
int
grub_efi_get_memory_map (grub_efi_uintn_t *memory_map_size,
			 grub_efi_memory_descriptor_t *memory_map,
			 grub_efi_uintn_t *map_key,
			 grub_efi_uintn_t *descriptor_size,
			 grub_efi_uint32_t *descriptor_version)
{
  grub_efi_status_t status;
  grub_efi_boot_services_t *b;
  grub_efi_uintn_t key;
  grub_efi_uint32_t version;
  grub_efi_uintn_t size;

  if (grub_efi_is_finished)
    {
      int ret = 1;

      if (memory_map != NULL)
	{
	  if (*memory_map_size < finish_mmap_size)
	    {
	      grub_memcpy (memory_map, finish_mmap_buf, *memory_map_size);
	      ret = 0;
	    }
          else
	    grub_memcpy (memory_map, finish_mmap_buf, finish_mmap_size);
	}
      else
	{
	  /*
	   * Incomplete, no buffer to copy into, same as
	   * GRUB_EFI_BUFFER_TOO_SMALL below.
	   */
	  ret = 0;
	}
      *memory_map_size = finish_mmap_size;
      if (map_key)
	*map_key = finish_key;
      if (descriptor_size)
	*descriptor_size = finish_desc_size;
      if (descriptor_version)
	*descriptor_version = finish_desc_version;
      return ret;
    }

  /* Allow some parameters to be missing.  */
  if (! map_key)
    map_key = &key;
  if (! descriptor_version)
    descriptor_version = &version;
  if (! descriptor_size)
    descriptor_size = &size;

  b = grub_efi_system_table->boot_services;
  status = efi_call_5 (b->get_memory_map, memory_map_size, memory_map, map_key,
			      descriptor_size, descriptor_version);
  if (*descriptor_size == 0)
    *descriptor_size = sizeof (grub_efi_memory_descriptor_t);
  if (status == GRUB_EFI_SUCCESS)
    return 1;
  else if (status == GRUB_EFI_BUFFER_TOO_SMALL)
    return 0;
  else
    return -1;
}

/* Sort the memory map in place.  */
static void
sort_memory_map (grub_efi_memory_descriptor_t *memory_map,
		 grub_efi_uintn_t desc_size,
		 grub_efi_memory_descriptor_t *memory_map_end)
{
  grub_efi_memory_descriptor_t *d1;
  grub_efi_memory_descriptor_t *d2;

  for (d1 = memory_map;
       d1 < memory_map_end;
       d1 = NEXT_MEMORY_DESCRIPTOR (d1, desc_size))
    {
      grub_efi_memory_descriptor_t *max_desc = d1;

      for (d2 = NEXT_MEMORY_DESCRIPTOR (d1, desc_size);
	   d2 < memory_map_end;
	   d2 = NEXT_MEMORY_DESCRIPTOR (d2, desc_size))
	{
	  if (max_desc->num_pages < d2->num_pages)
	    max_desc = d2;
	}

      if (max_desc != d1)
	{
	  grub_efi_memory_descriptor_t tmp;

	  tmp = *d1;
	  *d1 = *max_desc;
	  *max_desc = tmp;
	}
    }
}

/* Filter the descriptors. GRUB needs only available memory.  */
static grub_efi_memory_descriptor_t *
filter_memory_map (grub_efi_memory_descriptor_t *memory_map,
		   grub_efi_memory_descriptor_t *filtered_memory_map,
		   grub_efi_uintn_t desc_size,
		   grub_efi_memory_descriptor_t *memory_map_end)
{
  grub_efi_memory_descriptor_t *desc;
  grub_efi_memory_descriptor_t *filtered_desc;

  for (desc = memory_map, filtered_desc = filtered_memory_map;
       desc < memory_map_end;
       desc = NEXT_MEMORY_DESCRIPTOR (desc, desc_size))
    {
      if (desc->type == GRUB_EFI_CONVENTIONAL_MEMORY
#if 1
	  && desc->physical_start <= GRUB_EFI_MAX_ALLOCATION_ADDRESS
#endif
	  && desc->physical_start + PAGES_TO_BYTES (desc->num_pages) > 0x100000
	  && desc->num_pages != 0)
	{
	  grub_memcpy (filtered_desc, desc, desc_size);

	  /* Avoid less than 1MB, because some loaders seem to be confused.  */
	  if (desc->physical_start < 0x100000)
	    {
	      desc->num_pages -= BYTES_TO_PAGES (0x100000
						 - desc->physical_start);
	      desc->physical_start = 0x100000;
	    }

#if 1
	  if (BYTES_TO_PAGES (filtered_desc->physical_start)
	      + filtered_desc->num_pages
	      > BYTES_TO_PAGES_DOWN (GRUB_EFI_MAX_ALLOCATION_ADDRESS))
	    filtered_desc->num_pages
	      = (BYTES_TO_PAGES_DOWN (GRUB_EFI_MAX_ALLOCATION_ADDRESS)
		 - BYTES_TO_PAGES (filtered_desc->physical_start));
#endif

	  if (filtered_desc->num_pages == 0)
	    continue;

	  filtered_desc = NEXT_MEMORY_DESCRIPTOR (filtered_desc, desc_size);
	}
    }

  return filtered_desc;
}

/* Add memory regions.  */
static grub_err_t
add_memory_regions (grub_efi_memory_descriptor_t *memory_map,
		    grub_efi_uintn_t desc_size,
		    grub_efi_memory_descriptor_t *memory_map_end,
		    grub_efi_uint64_t required_pages,
		    unsigned int flags)
{
  grub_efi_memory_descriptor_t *desc;

  for (desc = memory_map;
       desc < memory_map_end;
       desc = NEXT_MEMORY_DESCRIPTOR (desc, desc_size))
    {
      grub_efi_uint64_t pages;
      grub_efi_physical_address_t start;
      void *addr;

      start = desc->physical_start;
      pages = desc->num_pages;

      if (pages < required_pages && (flags & GRUB_MM_ADD_REGION_CONSECUTIVE))
	continue;

      if (pages > required_pages)
	{
	  start += PAGES_TO_BYTES (pages - required_pages);
	  pages = required_pages;
	}

      addr = grub_efi_allocate_pages_real (start, pages,
					   GRUB_EFI_ALLOCATE_ADDRESS,
					   GRUB_EFI_LOADER_CODE);      
      if (! addr)
	return grub_error (GRUB_ERR_OUT_OF_MEMORY,
			    "Memory starting at %p (%u pages) marked as free, but EFI would not allocate",
			    (void *) ((grub_addr_t) start), (unsigned) pages);

      grub_mm_init_region (addr, PAGES_TO_BYTES (pages));

      required_pages -= pages;
      if (required_pages == 0)
	break;
    }

  if (required_pages > 0)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate all requested memory: %" PRIuGRUB_UINT64_T " pages still required after iterating EFI memory map",
                       required_pages);

  return GRUB_ERR_NONE;
}

void
grub_efi_memory_fini (void)
{
  /*
   * Free all stale allocations. grub_efi_free_pages() will remove
   * the found entry from the list and it will always find the first
   * list entry (efi_allocated_memory is the list start). Hence we
   * remove all entries from the list until none is left altogether.
   */
  while (efi_allocated_memory)
      grub_efi_free_pages (efi_allocated_memory->address,
                           efi_allocated_memory->pages);
}

#if 0
/* Print the memory map.  */
static void
print_memory_map (grub_efi_memory_descriptor_t *memory_map,
		  grub_efi_uintn_t desc_size,
		  grub_efi_memory_descriptor_t *memory_map_end)
{
  grub_efi_memory_descriptor_t *desc;
  int i;

  for (desc = memory_map, i = 0;
       desc < memory_map_end;
       desc = NEXT_MEMORY_DESCRIPTOR (desc, desc_size), i++)
    {
      grub_printf ("MD: t=%x, p=%llx, v=%llx, n=%llx, a=%llx\n",
		   desc->type, desc->physical_start, desc->virtual_start,
		   desc->num_pages, desc->attribute);
    }
}
#endif

grub_addr_t grub_stack_addr = (grub_addr_t)-1ll;
grub_size_t grub_stack_size = 0;

static void
grub_nx_init (void)
{
  grub_uint64_t attrs, stack_attrs;
  grub_err_t err;
  grub_addr_t stack_current, stack_end;
  const grub_uint64_t page_size = 4096;
  const grub_uint64_t page_mask = ~(page_size - 1);

  /*
   * These are to confirm that the flags are working as expected when
   * debugging.
   */
  attrs = 0;
  stack_current = (grub_addr_t)grub_nx_init & page_mask;
  err = grub_get_mem_attrs (stack_current, page_size, &attrs);
  if (err)
    {
      grub_dprintf ("nx",
		    "grub_get_mem_attrs(0x%"PRIxGRUB_UINT64_T", ...) -> 0x%x\n",
		    stack_current, err);
      grub_error_pop ();
    }
  else
    grub_dprintf ("nx", "page attrs for grub_nx_init (%p) are %c%c%c\n",
		  grub_dl_load_core,
		  (attrs & GRUB_MEM_ATTR_R) ? 'r' : '-',
		  (attrs & GRUB_MEM_ATTR_R) ? 'w' : '-',
		  (attrs & GRUB_MEM_ATTR_R) ? 'x' : '-');

  stack_current = (grub_addr_t)&stack_current & page_mask;
  err = grub_get_mem_attrs (stack_current, page_size, &stack_attrs);
  if (err)
    {
      grub_dprintf ("nx",
		    "grub_get_mem_attrs(0x%"PRIxGRUB_UINT64_T", ...) -> 0x%x\n",
		    stack_current, err);
      grub_error_pop ();
    }
  else
    {
      attrs = stack_attrs;
      grub_dprintf ("nx", "page attrs for stack (%p) are %c%c%c\n",
                    &attrs,
                    (attrs & GRUB_MEM_ATTR_R) ? 'r' : '-',
                    (attrs & GRUB_MEM_ATTR_R) ? 'w' : '-',
                    (attrs & GRUB_MEM_ATTR_R) ? 'x' : '-');
    }
  for (stack_end = stack_current + page_size ;
       !(attrs & GRUB_MEM_ATTR_R);
       stack_end += page_size)
    {
      err = grub_get_mem_attrs (stack_current, page_size, &attrs);
      if (err)
	{
	  grub_dprintf ("nx",
			"grub_get_mem_attrs(0x%"PRIxGRUB_UINT64_T", ...) -> 0x%x\n",
			stack_current, err);
	  grub_error_pop ();
	  break;
	}
    }
  if (stack_end > stack_current)
    {
      grub_stack_addr = stack_current;
      grub_stack_size = stack_end - stack_current;
      grub_dprintf ("nx",
		    "detected stack from 0x%"PRIxGRUB_ADDR" to 0x%"PRIxGRUB_ADDR"\n",
		    grub_stack_addr, grub_stack_addr + grub_stack_size - 1);
    }
}

static grub_err_t
grub_efi_mm_add_regions (grub_size_t required_bytes, unsigned int flags)
{
  grub_efi_memory_descriptor_t *memory_map;
  grub_efi_memory_descriptor_t *memory_map_end;
  grub_efi_memory_descriptor_t *filtered_memory_map;
  grub_efi_memory_descriptor_t *filtered_memory_map_end;
  grub_efi_uintn_t map_size;
  grub_efi_uintn_t desc_size;
  grub_err_t err;
  int mm_status;

  grub_nx_init ();

  /* Prepare a memory region to store two memory maps.  */
  memory_map = grub_efi_allocate_any_pages (2 * BYTES_TO_PAGES (MEMORY_MAP_SIZE));
  if (! memory_map)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "cannot allocate memory for memory map");

  /* Obtain descriptors for available memory.  */
  map_size = MEMORY_MAP_SIZE;

  mm_status = grub_efi_get_memory_map (&map_size, memory_map, 0, &desc_size, 0);

  if (mm_status == 0)
    {
      grub_efi_free_pages
	((grub_efi_physical_address_t) ((grub_addr_t) memory_map),
	 2 * BYTES_TO_PAGES (MEMORY_MAP_SIZE));

      /* Freeing/allocating operations may increase memory map size.  */
      map_size += desc_size * 32;

      memory_map = grub_efi_allocate_any_pages (2 * BYTES_TO_PAGES (map_size));
      if (! memory_map)
	return grub_error (GRUB_ERR_OUT_OF_MEMORY, "cannot allocate memory for new memory map");

      mm_status = grub_efi_get_memory_map (&map_size, memory_map, 0,
					   &desc_size, 0);
    }

  if (mm_status < 0)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "error fetching memory map from EFI");

  memory_map_end = NEXT_MEMORY_DESCRIPTOR (memory_map, map_size);

  filtered_memory_map = memory_map_end;

  filtered_memory_map_end = filter_memory_map (memory_map, filtered_memory_map,
					       desc_size, memory_map_end);

  /* Sort the filtered descriptors, so that GRUB can allocate pages
     from smaller regions.  */
  sort_memory_map (filtered_memory_map, desc_size, filtered_memory_map_end);

  /* Allocate memory regions for GRUB's memory management.  */
  err = add_memory_regions (filtered_memory_map, desc_size,
			    filtered_memory_map_end,
			    BYTES_TO_PAGES (required_bytes),
			    flags);
  if (err != GRUB_ERR_NONE)
    return err;

#if 0
  /* For debug.  */
  map_size = MEMORY_MAP_SIZE;

  if (grub_efi_get_memory_map (&map_size, memory_map, 0, &desc_size, 0) < 0)
    grub_fatal ("cannot get memory map");

  grub_printf ("printing memory map\n");
  print_memory_map (memory_map, desc_size,
		    NEXT_MEMORY_DESCRIPTOR (memory_map, map_size));
  grub_fatal ("Debug. ");
#endif

  /* Release the memory maps.  */
  grub_efi_free_pages ((grub_addr_t) memory_map,
		       2 * BYTES_TO_PAGES (MEMORY_MAP_SIZE));

  return GRUB_ERR_NONE;
}

void
grub_efi_mm_init (void)
{
  if (grub_efi_mm_add_regions (DEFAULT_HEAP_SIZE, GRUB_MM_ADD_REGION_NONE) != GRUB_ERR_NONE)
    grub_fatal ("%s", grub_errmsg);
  grub_mm_add_region_fn = grub_efi_mm_add_regions;
}

#if defined (__aarch64__) || defined (__arm__) || defined (__riscv)
grub_err_t
grub_efi_get_ram_base(grub_addr_t *base_addr)
{
  grub_efi_memory_descriptor_t *memory_map, *desc;
  grub_efi_uintn_t memory_map_size, desc_size;
  int ret;

  memory_map_size = grub_efi_find_mmap_size();

  memory_map = grub_malloc (memory_map_size);
  if (! memory_map)
    return GRUB_ERR_OUT_OF_MEMORY;
  ret = grub_efi_get_memory_map (&memory_map_size, memory_map, NULL,
				 &desc_size, NULL);

  if (ret < 1)
    return GRUB_ERR_BUG;

  for (desc = memory_map, *base_addr = GRUB_EFI_MAX_USABLE_ADDRESS;
       (grub_addr_t) desc < ((grub_addr_t) memory_map + memory_map_size);
       desc = NEXT_MEMORY_DESCRIPTOR (desc, desc_size))
    {
      if (desc->type == GRUB_EFI_CONVENTIONAL_MEMORY &&
          (desc->attribute & GRUB_EFI_MEMORY_WB))
        {
          *base_addr = grub_min (*base_addr, desc->physical_start);
          grub_dprintf ("efi", "setting base_addr=0x%016lx\n", *base_addr);
        }
      else
        {
          grub_dprintf ("efi", "ignoring address 0x%016lx\n", desc->physical_start);
        }
    }

  if (*base_addr == GRUB_EFI_MAX_USABLE_ADDRESS)
    grub_dprintf ("efi", "base_addr 0x%016lx is probably wrong.\n", *base_addr);

  grub_free(memory_map);

  return GRUB_ERR_NONE;
}
#endif

static inline grub_uint64_t
grub_mem_attrs_to_uefi_mem_attrs (grub_uint64_t attrs)
{
  grub_uint64_t ret = GRUB_EFI_MEMORY_RP |
		      GRUB_EFI_MEMORY_RO |
		      GRUB_EFI_MEMORY_XP;

  if (attrs & GRUB_MEM_ATTR_R)
    ret &= ~GRUB_EFI_MEMORY_RP;

  if (attrs & GRUB_MEM_ATTR_W)
    ret &= ~GRUB_EFI_MEMORY_RO;

  if (attrs & GRUB_MEM_ATTR_X)
    ret &= ~GRUB_EFI_MEMORY_XP;

  return ret;
}

static inline grub_uint64_t
uefi_mem_attrs_to_grub_mem_attrs (grub_uint64_t attrs)
{
  grub_uint64_t ret = GRUB_MEM_ATTR_R |
		      GRUB_MEM_ATTR_W |
		      GRUB_MEM_ATTR_X;

  if (attrs & GRUB_EFI_MEMORY_RP)
    ret &= ~GRUB_MEM_ATTR_R;

  if (attrs & GRUB_EFI_MEMORY_RO)
    ret &= ~GRUB_MEM_ATTR_W;

  if (attrs & GRUB_EFI_MEMORY_XP)
    ret &= ~GRUB_MEM_ATTR_X;

  return ret;
}

grub_err_t
grub_get_mem_attrs (grub_addr_t addr, grub_size_t size, grub_uint64_t *attrs)
{
  grub_efi_memory_attribute_protocol_t *proto;
  grub_efi_physical_address_t physaddr = addr;
  grub_efi_guid_t protocol_guid = GRUB_EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID;
  grub_efi_status_t efi_status;

  proto = grub_efi_locate_protocol (&protocol_guid, 0);
  if (!proto)
    return GRUB_ERR_NOT_IMPLEMENTED_YET;

  if (physaddr & 0xfff || size & 0xfff || size == 0 || attrs == NULL)
    {
      grub_dprintf ("nx", "%s called on 0x%"PRIxGRUB_ADDR"-0x%"PRIxGRUB_ADDR" and attrs %p\n",
		    __func__, physaddr, physaddr+size-1, attrs);
      return 0;
    }

  efi_status = efi_call_4(proto->get_memory_attributes,
			  proto, physaddr, size, attrs);
  *attrs = uefi_mem_attrs_to_grub_mem_attrs (*attrs);

  return grub_efi_status_to_err (efi_status);
}

grub_err_t
grub_update_mem_attrs (grub_addr_t addr, grub_size_t size,
		       grub_uint64_t set_attrs, grub_uint64_t clear_attrs)
{
  grub_efi_memory_attribute_protocol_t *proto;
  grub_efi_physical_address_t physaddr = addr;
  grub_efi_guid_t protocol_guid = GRUB_EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID;
  grub_efi_status_t efi_status = GRUB_EFI_SUCCESS;
  grub_uint64_t before = 0, after = 0, uefi_set_attrs, uefi_clear_attrs;
  grub_err_t err;

  proto = grub_efi_locate_protocol (&protocol_guid, 0);
  if (!proto)
    return GRUB_ERR_NONE;

  err = grub_get_mem_attrs (addr, size, &before);
  if (err)
    grub_dprintf ("nx", "grub_get_mem_attrs(0x%"PRIxGRUB_ADDR", %"PRIuGRUB_SIZE", %p) -> 0x%x\n",
		  addr, size, &before, err);

  if (physaddr & 0xfff || size & 0xfff || size == 0)
    {
      grub_dprintf ("nx", "%s called on 0x%"PRIxGRUB_ADDR"-0x%"PRIxGRUB_ADDR" +%s%s%s -%s%s%s\n",
		    __func__, physaddr, physaddr + size - 1,
		    (set_attrs & GRUB_MEM_ATTR_R) ? "r" : "",
		    (set_attrs & GRUB_MEM_ATTR_W) ? "w" : "",
		    (set_attrs & GRUB_MEM_ATTR_X) ? "x" : "",
		    (clear_attrs & GRUB_MEM_ATTR_R) ? "r" : "",
		    (clear_attrs & GRUB_MEM_ATTR_W) ? "w" : "",
		    (clear_attrs & GRUB_MEM_ATTR_X) ? "x" : "");
      return 0;
    }

  uefi_set_attrs = grub_mem_attrs_to_uefi_mem_attrs (set_attrs);
  grub_dprintf ("nx", "translating set_attrs from 0x%lx to 0x%lx\n", set_attrs, uefi_set_attrs);
  uefi_clear_attrs = grub_mem_attrs_to_uefi_mem_attrs (clear_attrs);
  grub_dprintf ("nx", "translating clear_attrs from 0x%lx to 0x%lx\n", clear_attrs, uefi_clear_attrs);
  if (uefi_set_attrs)
    efi_status = efi_call_4(proto->set_memory_attributes,
			    proto, physaddr, size, uefi_set_attrs);
  if (efi_status == GRUB_EFI_SUCCESS && uefi_clear_attrs)
    efi_status = efi_call_4(proto->clear_memory_attributes,
			    proto, physaddr, size, uefi_clear_attrs);

  err = grub_get_mem_attrs (addr, size, &after);
  if (err)
    grub_dprintf ("nx", "grub_get_mem_attrs(0x%"PRIxGRUB_ADDR", %"PRIuGRUB_SIZE", %p) -> 0x%x\n",
		  addr, size, &after, err);

  grub_dprintf ("nx", "set +%s%s%s -%s%s%s on 0x%"PRIxGRUB_ADDR"-0x%"PRIxGRUB_ADDR" before:%c%c%c after:%c%c%c\n",
		(set_attrs & GRUB_MEM_ATTR_R) ? "r" : "",
		(set_attrs & GRUB_MEM_ATTR_W) ? "w" : "",
		(set_attrs & GRUB_MEM_ATTR_X) ? "x" : "",
		(clear_attrs & GRUB_MEM_ATTR_R) ? "r" : "",
		(clear_attrs & GRUB_MEM_ATTR_W) ? "w" : "",
		(clear_attrs & GRUB_MEM_ATTR_X) ? "x" : "",
		addr, addr + size - 1,
		(before & GRUB_MEM_ATTR_R) ? 'r' : '-',
		(before & GRUB_MEM_ATTR_W) ? 'w' : '-',
		(before & GRUB_MEM_ATTR_X) ? 'x' : '-',
		(after & GRUB_MEM_ATTR_R) ? 'r' : '-',
		(after & GRUB_MEM_ATTR_W) ? 'w' : '-',
		(after & GRUB_MEM_ATTR_X) ? 'x' : '-');

  return grub_efi_status_to_err (efi_status);
}
