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

#define MAX_STACK_FRAME 102400

struct fplr
{
  void *lr;
  struct fplr *fp;
};

void
grub_backtrace_pointer (void *frame, unsigned int skip)
{
  unsigned int x = 0;
  struct fplr *fplr = (struct fplr *)frame;

  while (fplr)
    {
      const char *name = NULL;
      char *addr = NULL;

      grub_dprintf("backtrace", "fp is %p next_fp is %p\n",
		   fplr, fplr->fp);

      if (x >= skip)
	{
	  name = grub_get_symbol_by_addr (fplr->lr, 1);
	  if (name)
	    addr = grub_resolve_symbol (name);
	  grub_backtrace_print_address (fplr->lr);

	  if (addr && addr != fplr->lr)
	    grub_printf (" %s() %p+%p \n", name ? name : "unknown", addr,
			 (void *)((grub_uint64_t)fplr->lr - (grub_uint64_t)addr));
	  else
	    grub_printf(" %s() %p \n", name ? name : "unknown", addr);

	}

      x += 1;

      if (fplr->fp < fplr ||
	  (grub_uint64_t)fplr->fp - (grub_uint64_t)fplr > MAX_STACK_FRAME ||
	  fplr->fp == fplr)
	{
	  break;
	}
      fplr = fplr->fp;
    }
}

asm ("\t.global \"_text\"\n"
     "_text:\n"
     "\t.quad .text\n"
     "\t.global \"_data\"\n"
     "_data:\n"
     "\t.quad .data\n"
     );

extern grub_uint64_t _text;
extern grub_uint64_t _data;

void
grub_backtrace_arch (unsigned int skip)
{
  grub_printf ("Backtrace (.text %p .data %p):\n",
	       (void *)_text, (void *)_data);
  skip += 1;
  grub_backtrace_pointer(__builtin_frame_address(0), skip);
}
