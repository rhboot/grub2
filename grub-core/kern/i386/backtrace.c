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

void
grub_backtrace_pointer (void *frame, unsigned int skip)
{
  void **ebp = (void **)frame;
  unsigned long x = 0;

  while (ebp)
    {
      void **next_ebp = (void **)ebp[0];
      const char *name = NULL;
      char *addr = NULL;

      grub_dprintf("backtrace", "ebp is %p next_ebp is %p\n", ebp, next_ebp);

      if (x >= skip)
	{
	  name = grub_get_symbol_by_addr (ebp[1], 1);
	  if (name)
	    addr = grub_resolve_symbol (name);
	  grub_backtrace_print_address (ebp[1]);

	  if (addr && addr != ebp[1])
	    grub_printf (" %s() %p+%p \n", name ? name : "unknown", addr,
			 (char *)((char *)ebp[1] - addr));
	  else
	    grub_printf(" %s() %p \n", name ? name : "unknown", addr);

#if 0
	  grub_printf ("(");
	  for (i = 0, arg = ebp[2]; arg != next_ebp && i < 12; arg++, i++)
	    grub_printf ("%p,", arg);
	  grub_printf (")\n");
#endif
	}

      x += 1;

      if (next_ebp < ebp || next_ebp - ebp > MAX_STACK_FRAME || next_ebp == ebp)
	{
	  //grub_printf ("Invalid stack frame at %p (%p)\n", ebp, next_ebp);
	  break;
	}
      ebp = next_ebp;
    }
}

#if defined (__x86_64__)
asm ("\t.global \"_text\"\n"
     "_text:\n"
     "\t.quad .text\n"
     "\t.global \"_data\"\n"
     "_data:\n"
     "\t.quad .data\n"
     );
#elif defined(__i386__)
asm ("\t.global \"_text\"\n"
     "_text:\n"
     "\t.long .text\n"
     "\t.global \"_data\"\n"
     "_data:\n"
     "\t.long .data\n"
     );
#else
#warning I dunno...
#endif

extern unsigned long _text;
extern unsigned long _data;

#ifdef GRUB_UTIL
#define EXT_C(x) x
#endif

void
grub_backtrace_arch (unsigned int skip)
{
  grub_printf ("Backtrace (.text %p .data %p):\n",
	       (void *)_text, (void *)_data);
  skip += 1;
#if defined (__x86_64__)
  asm volatile ("movq %%rbp, %%rdi\n"
		"movq 0, %%rsi\n"
		"movl %0, %%esi\n"
		"call " EXT_C("grub_backtrace_pointer")
		:
		: "r" (skip));
#elif defined(__i386__)
  asm volatile ("addl $8, %%esp\n"
		"pushl %0\n"
		"pushl %%ebp\n"
		"call " EXT_C("grub_backtrace_pointer")
		:
		: "r" (skip));
#else
  grub_backtrace_pointer(__builtin_frame_address(0), skip);
#endif
}
