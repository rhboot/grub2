/*
 * Copyright (C) 2019 Free Software Foundation, Inc.
 *
 * This file is part of LIBTASN1.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/****************************************************************/
/* Description: run reproducers for several fixed issues        */
/****************************************************************/

#include <grub/libtasn1.h>
#include <grub/err.h>
#include <grub/mm.h>
#include "../wrap_tests.h"

#define CONST_DOWN        (1U<<29)

/* produces endless loop (fixed by d4b624b2):
 * The following translates into a single node with all pointers
 * (right,left,down) set to NULL. */
const asn1_static_node endless_asn1_tab[] = {
  { "TEST_TREE", 536875024, NULL },
  { NULL, 0, NULL }
};

/* produces memory leak (fixed by f16d1ff9):
 * 152 bytes in 1 blocks are definitely lost in loss record 1 of 1
 *    at 0x4837B65: calloc (vg_replace_malloc.c:762)
 *    by 0x4851C0D: _asn1_add_static_node (parser_aux.c:71)
 *    by 0x4853AAC: asn1_array2tree (structure.c:200)
 *    by 0x10923B: main (single_node.c:67)
 */
const asn1_static_node tab[] = {
{ "a", CONST_DOWN, "" },
{ "b", 0, "" },
{ "c", 0, "" },
{ NULL, 0, NULL }
};

void
test_reproducers (void)
{
  int result;
  asn1_node definitions = NULL;
  char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

  result = asn1_array2tree (endless_asn1_tab, &definitions, errorDescription);
  if (result != ASN1_SUCCESS)
    {
      grub_fatal ("Error: %s\nErrorDescription = %s\n\n",
		  asn1_strerror (result), errorDescription);
      return;
    }

  asn1_delete_structure (&definitions);

  definitions = NULL;
  result = asn1_array2tree (tab, &definitions, errorDescription);
  if (result != ASN1_SUCCESS)
    {
      grub_fatal ("Error: %s\nErrorDescription = %s\n\n",
		  asn1_strerror (result), errorDescription);
      return;
    }

  asn1_delete_structure (&definitions);
}
