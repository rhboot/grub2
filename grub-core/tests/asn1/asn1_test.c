/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020 IBM Corporation
 *  Copyright (C) 2024 Free Software Foundation, Inc.
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

#include <grub/test.h>
#include <grub/dl.h>
#include "asn1_test.h"

/*
 * libtasn1 tests - from which this is derived - are provided under GPL3+.
 */
GRUB_MOD_LICENSE ("GPLv3+");

static void
asn1_test (void)
{
  grub_test_assert (test_CVE_2018_1000654 () == 0, "CVE-2018-1000654 test failed");

  grub_test_assert (test_object_id_encoding () == 0, "ASN.1 object ID encoding test failed");

  grub_test_assert (test_object_id_decoding () == 0, "ASN.1 object ID decoding test failed");

  grub_test_assert (test_octet_string () == 0, "ASN.1 octet string test failed");

  grub_test_assert (test_overflow () == 0, "ASN.1 overflow test failed");

  grub_test_assert (test_reproducers () == 0, "ASN.1 reproducers test failed");

  grub_test_assert (test_simple () == 0, "ASN.1 simple test failed");

  grub_test_assert (test_strings () == 0, "ASN.1 strings test fail" );
}

/* Register asn1_test method as a functional test.  */
GRUB_FUNCTIONAL_TEST (asn1_test, asn1_test);
