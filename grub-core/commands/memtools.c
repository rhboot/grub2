/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2022 IBM Corporation
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

#include <config.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/memory.h>
#include <grub/mm.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_lsmem (grub_command_t cmd __attribute__ ((unused)),
		 int argc __attribute__ ((unused)),
		 char **args __attribute__ ((unused)))

{
#ifndef GRUB_MACHINE_EMU
  grub_mm_dump (0);
#endif

  return 0;
}

static grub_err_t
grub_cmd_lsfreemem (grub_command_t cmd __attribute__ ((unused)),
		    int argc __attribute__ ((unused)),
		    char **args __attribute__ ((unused)))

{
#ifndef GRUB_MACHINE_EMU
  grub_mm_dump_free ();
#endif

  return 0;
}


static grub_err_t
grub_cmd_stress_big_allocs (grub_command_t cmd __attribute__ ((unused)),
			    int argc __attribute__ ((unused)),
			    char **args __attribute__ ((unused)))
{
  int i, max_mb, blocks_alloced;
  void *mem;
  void **blocklist;

  grub_printf ("Test 1: increasingly sized allocs to 1GB block\n");
  for (i = 1; i < 1024; i++)
    {
      grub_printf ("%4d MB . ", i);
      mem = grub_malloc (i * 1024 * 1024);
      if (mem == NULL)
	{
	  grub_printf ("failed\n");
	  break;
	}
      else
	grub_free (mem);

      if (i % 7 == 0)
	grub_printf ("\n");
    }

  max_mb = i - 1;
  grub_printf ("\nMax sized allocation we did was %d MB\n", max_mb);

  grub_printf ("\nTest 2: 1MB at a time, max 4GB\n");
  blocklist = grub_calloc (4096, sizeof (void *));
  for (i = 0; i < 4096; i++)
    {
      blocklist[i] = grub_malloc (1024 * 1024);
      if (blocklist[i] == NULL)
	{
	  grub_printf ("Ran out of memory at iteration %d\n", i);
	  break;
	}
    }
  blocks_alloced = i;
  for (i = 0; i < blocks_alloced; i++)
    grub_free (blocklist[i]);

  grub_printf ("\nTest 3: 1MB aligned 900kB + 100kB\n");
  /* grub_mm_debug=1;*/
  for (i = 0; i < 4096; i += 2)
    {
      blocklist[i] = grub_memalign (1024 * 1024, 900 * 1024);
      if (blocklist[i] == NULL)
	{
	  grub_printf ("Failed big allocation, iteration %d\n", i);
	  blocks_alloced = i;
	  break;
	}

      blocklist[i + 1] = grub_malloc (100 * 1024);
      if (blocklist[i + 1] == NULL)
	{
	  grub_printf ("Failed small allocation, iteration %d\n", i);
	  blocks_alloced = i + 1;
	  break;
	}
      grub_printf (".");
    }
  for (i = 0; i < blocks_alloced; i++)
    grub_free (blocklist[i]);

  grub_free (blocklist);

#if defined(__powerpc__)
  grub_printf ("\nA reboot may now be required.\n");
#endif

  grub_errno = GRUB_ERR_NONE;
  return GRUB_ERR_NONE;
}

static grub_command_t cmd_lsmem, cmd_lsfreemem, cmd_sba;

GRUB_MOD_INIT (memtools)
{
  cmd_lsmem = grub_register_command ("lsmem", grub_cmd_lsmem,
				     0, N_("List free and allocated memory blocks."));
  cmd_lsfreemem = grub_register_command ("lsfreemem", grub_cmd_lsfreemem,
					 0, N_("List free memory blocks."));
  cmd_sba = grub_register_command ("stress_big_allocs", grub_cmd_stress_big_allocs,
				   0, N_("Stress test large allocations."));
}

GRUB_MOD_FINI (memtools)
{
  grub_unregister_command (cmd_lsmem);
  grub_unregister_command (cmd_lsfreemem);
  grub_unregister_command (cmd_sba);
}
