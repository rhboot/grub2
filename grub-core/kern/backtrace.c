/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
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
#include <grub/command.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/mm.h>
#include <grub/term.h>
#include <grub/backtrace.h>

GRUB_MOD_LICENSE ("GPLv3+");

static void
grub_backtrace_print_address_default (void *addr)
{
#ifndef GRUB_UTIL
  grub_dl_t mod;
  void *start_addr;

  FOR_DL_MODULES (mod)
  {
    grub_dl_segment_t segment;
    for (segment = mod->segment; segment; segment = segment->next)
      if (segment->addr <= addr && (grub_uint8_t *) segment->addr
	  + segment->size > (grub_uint8_t *) addr)
	{
	  grub_printf ("%s.%x+%" PRIxGRUB_SIZE, mod->name,
		       segment->section,
		       (grub_size_t)
		       ((grub_uint8_t *)addr - (grub_uint8_t *)segment->addr));
	  return;
	}
  }

  start_addr = grub_resolve_symbol ("_start");
  if (start_addr && start_addr < addr)
    grub_printf ("kernel+%" PRIxGRUB_SIZE,
		 (grub_size_t)
		  ((grub_uint8_t *)addr - (grub_uint8_t *)start_addr));
  else
#endif
    grub_printf ("%p", addr);
}

static void
grub_backtrace_pointer_default (void *frame __attribute__((__unused__)),
				unsigned int skip __attribute__((__unused__)))
{
  return;
}

void
grub_backtrace_pointer (void *frame, unsigned int skip)
     __attribute__((__weak__,
		    __alias__(("grub_backtrace_pointer_default"))));

void
grub_backtrace_print_address (void *addr)
     __attribute__((__weak__,
		    __alias__(("grub_backtrace_print_address_default"))));

static void
grub_backtrace_arch_default(unsigned int skip)
{
  grub_backtrace_pointer(__builtin_frame_address(0), skip + 1);
}

void grub_backtrace_arch (unsigned int skip)
     __attribute__((__weak__, __alias__(("grub_backtrace_arch_default"))));

void grub_backtrace (unsigned int skip)
{
  grub_backtrace_arch(skip + 1);
}

void grub_debug_backtrace (const char * const debug,
			   unsigned int skip)
{
  if (grub_debug_enabled (debug))
    grub_backtrace (skip + 1);
}
