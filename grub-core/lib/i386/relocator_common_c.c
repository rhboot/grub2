/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009-2013  Free Software Foundation, Inc.
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

#include <grub/mm.h>
#include <grub/misc.h>

#include <grub/types.h>
#include <grub/err.h>
#include <grub/term.h>

#include <grub/relocator.h>
#include <grub/relocator_private.h>

#include <grub/i386/memory.h>

extern grub_uint8_t grub_relocator_forward_start;
extern grub_uint8_t grub_relocator_forward_end;
extern grub_uint8_t grub_relocator_backward_start;
extern grub_uint8_t grub_relocator_backward_end;

extern void *grub_relocator_backward_dest;
extern void *grub_relocator_backward_src;
extern grub_size_t grub_relocator_backward_chunk_size;

extern void *grub_relocator_forward_dest;
extern void *grub_relocator_forward_src;
extern grub_size_t grub_relocator_forward_chunk_size;

#define RELOCATOR_SIZEOF(x)	(&grub_relocator##x##_end - &grub_relocator##x##_start)

grub_size_t grub_relocator_forward_size;
grub_size_t grub_relocator_backward_size;
grub_size_t grub_relocator_preamble_size = 0;
#ifdef __x86_64__
grub_size_t grub_relocator_jumper_size = 12;
#else
grub_size_t grub_relocator_jumper_size = 7;
#endif
#if defined(__x86_64__) && defined(GRUB_MACHINE_EFI)
grub_size_t grub_relocator_align = 4096;
#else
grub_size_t grub_relocator_align = 1;
#endif

#if defined(__x86_64__) && defined(GRUB_MACHINE_EFI)

#define PAGE_PRESENT 1
#define PAGE_WRITABLE 2
#define PAGE_USER 4
#define PAGE_PS 0x80
#define PAGE_IDX_SIZE 9
#define PAGE_PS_SHIFT 21
#define PAGE_NUM_ENTRIES 0x200
#define PS_PAGE_SIZE 0x200000

static grub_uint64_t max_ram_size;

  /* Helper for grub_get_multiboot_mmap_count.  */
static int
max_hook (grub_uint64_t addr,
	  grub_uint64_t size,
	  grub_memory_type_t type __attribute__ ((unused)),
	  void *data __attribute__ ((unused)))
{
  max_ram_size = grub_max (max_ram_size, addr + size);
  return 0;
}

static grub_uint64_t
find_max_size (void)
{
  if (!max_ram_size)
    {
      /* We need to map the first 4GiB of address space as well as all the
	 available RAM, so start with 4GiB and increase if we see any RAM
	 above this. */
      max_ram_size = 1ULL << 32;

      grub_mmap_iterate (max_hook, NULL);
    }

  return max_ram_size;
}

void
grub_cpu_relocator_preamble (void *rels)
{
  grub_uint64_t nentries = (find_max_size () + PS_PAGE_SIZE - 1) >> PAGE_PS_SHIFT;
  grub_uint64_t npt2pages = (nentries + PAGE_NUM_ENTRIES - 1) >> PAGE_IDX_SIZE;
  grub_uint64_t npt3pages = (npt2pages + PAGE_NUM_ENTRIES - 1) >> PAGE_IDX_SIZE;
  grub_uint8_t *p = rels;
  grub_uint64_t *pt4 = (grub_uint64_t *) (p + GRUB_PAGE_SIZE);
  grub_uint64_t *pt3 = pt4 + PAGE_NUM_ENTRIES;
  grub_uint64_t *pt2 = pt3 + (npt3pages << PAGE_IDX_SIZE);
  grub_uint64_t *endpreamble = pt2 + (npt2pages << PAGE_IDX_SIZE);
  grub_uint64_t i;

  /* movabs $pt4, %rax.  */
  *p++ = 0x48;
  *p++ = 0xb8;
  *(grub_uint64_t *) p = (grub_uint64_t) pt4;
  p += 8;

  /* mov %rax, %cr3.  */
  *p++ = 0x0f;
  *p++ = 0x22;
  *p++ = 0xd8;

  /* jmp $endpreamble.  */
  *p++ = 0xe9;
  *(grub_uint32_t *) p = (grub_uint8_t *) endpreamble - p - 4;

  for (i = 0; i < npt3pages; i++)
    pt4[i] = ((grub_uint64_t) pt3 + (i << GRUB_PAGE_SHIFT)) | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

  for (i = 0; i < npt2pages; i++)
    pt3[i] = ((grub_uint64_t) pt2 + (i << GRUB_PAGE_SHIFT)) | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;

  for (i = 0; i < (npt2pages << PAGE_IDX_SIZE); i++)
    pt2[i] = (i << PAGE_PS_SHIFT) | PAGE_PS | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;
}

static void
compute_preamble_size (void)
{
  grub_uint64_t nentries = (find_max_size () + PS_PAGE_SIZE - 1) >> PAGE_PS_SHIFT;
  grub_uint64_t npt2pages = (nentries + PAGE_NUM_ENTRIES - 1) >> PAGE_IDX_SIZE;
  grub_uint64_t npt3pages = (npt2pages + PAGE_NUM_ENTRIES - 1) >> PAGE_IDX_SIZE;
  grub_relocator_preamble_size = (npt2pages + npt3pages + 1 + 1) << GRUB_PAGE_SHIFT;
}

#else
void
grub_cpu_relocator_preamble (void *rels __attribute__((unused)))
{
}
#endif

void
grub_cpu_relocator_init (void)
{
  grub_relocator_forward_size = RELOCATOR_SIZEOF (_forward);
  grub_relocator_backward_size = RELOCATOR_SIZEOF (_backward);
#if defined(__x86_64__) && defined(GRUB_MACHINE_EFI)
  compute_preamble_size ();
#endif
}

void
grub_cpu_relocator_jumper (void *rels, grub_addr_t addr)
{
  grub_uint8_t *ptr;
  ptr = rels;
#ifdef __x86_64__
  /* movq imm64, %rax (for relocator) */
  *(grub_uint8_t *) ptr = 0x48;
  ptr++;
  *(grub_uint8_t *) ptr = 0xb8;
  ptr++;
  *(grub_uint64_t *) ptr = addr;
  ptr += sizeof (grub_uint64_t);
#else
  /* movl imm32, %eax (for relocator) */
  *(grub_uint8_t *) ptr = 0xb8;
  ptr++;
  *(grub_uint32_t *) ptr = addr;
  ptr += sizeof (grub_uint32_t);
#endif
  /* jmp $eax/$rax */
  *(grub_uint8_t *) ptr = 0xff;
  ptr++;
  *(grub_uint8_t *) ptr = 0xe0;
  ptr++;
}

void
grub_cpu_relocator_backward (void *ptr, void *src, void *dest,
			     grub_size_t size)
{
  grub_relocator_backward_dest = dest;
  grub_relocator_backward_src = src;
  grub_relocator_backward_chunk_size = size;

  grub_memmove (ptr,
		&grub_relocator_backward_start, RELOCATOR_SIZEOF (_backward));
}

void
grub_cpu_relocator_forward (void *ptr, void *src, void *dest,
			    grub_size_t size)
{
  grub_relocator_forward_dest = dest;
  grub_relocator_forward_src = src;
  grub_relocator_forward_chunk_size = size;

  grub_memmove (ptr,
		&grub_relocator_forward_start, RELOCATOR_SIZEOF (_forward));
}
