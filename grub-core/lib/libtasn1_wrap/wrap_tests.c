/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020 IBM Corporation
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

#include <grub/dl.h>
#include <grub/command.h>
#include <grub/mm.h>
#include "wrap_tests.h"

/*
 * libtasn1 tests - from which this is derived - are provided under GPL3+.
 */
GRUB_MOD_LICENSE ("GPLv3+");

static grub_command_t cmd;

static grub_err_t
grub_cmd_asn1test (grub_command_t cmdd __attribute__((unused)),
		   int argc __attribute__((unused)),
		   char **args __attribute__((unused)))
{
  grub_printf ("test_CVE_2018_1000654\n");
  test_CVE_2018_1000654 ();

  grub_printf ("test_object_id_decoding\n");
  test_object_id_decoding ();

  grub_printf ("test_object_id_encoding\n");
  test_object_id_encoding ();

  grub_printf ("test_octet_string\n");
  test_octet_string ();

  grub_printf ("test_overflow\n");
  test_overflow ();

  grub_printf ("test_reproducers\n");
  test_overflow ();

  grub_printf ("test_simple\n");
  test_simple ();

  grub_printf ("test_strings\n");
  test_strings ();

  grub_printf ("ASN.1 self-tests passed\n");

  return GRUB_ERR_NONE;
}


GRUB_MOD_INIT(test_asn1)
{
  cmd = grub_register_command ("test_asn1", grub_cmd_asn1test, NULL,
			       "Run self-tests for the ASN.1 parser.");
}

GRUB_MOD_FINI(test_asn1)
{
  grub_unregister_command (cmd);
}
