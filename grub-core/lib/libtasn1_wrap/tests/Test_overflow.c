/*
 * Copyright (C) 2012-2014 Free Software Foundation, Inc.
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

/* Written by Simon Josefsson */

#include <grub/libtasn1.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/types.h>
#include "../wrap_tests.h"

void
test_overflow(void)
{
  /* Test that values larger than long are rejected.  This has worked
     fine with all versions of libtasn1. */

  {
    unsigned char der[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    long l;
    int len;

    l = asn1_get_length_der (der, sizeof der, &len);

    if (l != -2L)
      {
	grub_fatal ("ERROR: asn1_get_length_der bignum (l %ld len %d)\n", l, len);
	return;
      }
  }

  /* Test that values larger than int but smaller than long are
     rejected.  This limitation was introduced with libtasn1 2.12. */
#if (GRUB_LONG_MAX > GRUB_INT_MAX)
    {
      unsigned long num = ((long) GRUB_UINT_MAX) << 2;
      unsigned char der[20];
      int der_len;
      long l;
      int len;

      asn1_length_der (num, der, &der_len);

      l = asn1_get_length_der (der, der_len, &len);

      if (l != -2L)
	{
	  grub_fatal ("ERROR: asn1_get_length_der intnum (l %ld len %d)\n", l,
		      len);
	  return;
	}
    }
#endif

  /* Test that values larger than would fit in the input string are
     rejected.  This problem was fixed in libtasn1 2.12. */
  {
    unsigned long num = 64;
    unsigned char der[20];
    int der_len;
    long l;
    int len;

    asn1_length_der (num, der, &der_len);

    der_len = sizeof (der);
    l = asn1_get_length_der (der, der_len, &len);

    if (l != -4L)
      {
	grub_fatal ("ERROR: asn1_get_length_der overflow-small (l %ld len %d)\n",
		    l, len);
	return;
      }
  }

  /* Test that values larger than would fit in the input string are
     rejected.  This problem was fixed in libtasn1 2.12. */
  {
    unsigned long num = 1073741824;
    unsigned char der[20];
    int der_len;
    long l;
    int len;

    asn1_length_der (num, der, &der_len);

    der_len = sizeof (der);
    l = asn1_get_length_der (der, der_len, &len);

    if (l != -4L)
      {
	grub_fatal ("ERROR: asn1_get_length_der overflow-large1 (l %ld len %d)\n",
		    l, len);
	return;
      }
  }

  /* Test that values larger than would fit in the input string are
     rejected.  This problem was fixed in libtasn1 2.12. */
  {
    unsigned long num = 2147483649;
    unsigned char der[20];
    int der_len;
    long l;
    int len;

    asn1_length_der (num, der, &der_len);

    der_len = sizeof (der);
    l = asn1_get_length_der (der, der_len, &len);

    if (l != -2L)
      {
	grub_fatal ("ERROR: asn1_get_length_der overflow-large2 (l %ld len %d)\n",
		    l, len);
	return;
      }
  }
}
