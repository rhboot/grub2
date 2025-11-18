/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2022, 2025 IBM Corporation
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

#include <libtasn1.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/crypto.h>
#include <grub/misc.h>
#include <grub/gcrypt/gcrypt.h>

#include "appendedsig.h"

asn1_node grub_gnutls_gnutls_asn = NULL;
asn1_node grub_gnutls_pkix_asn = NULL;

extern const asn1_static_node grub_gnutls_asn1_tab[];
extern const asn1_static_node grub_pkix_asn1_tab[];

/*
 * Read a value from an ASN1 node, allocating memory to store it. It will work
 * for anything where the size libtasn1 returns is right:
 *  - Integers
 *  - Octet strings
 *  - DER encoding of other structures
 *
 * It will _not_ work for things where libtasn1 size requires adjustment:
 *  - Strings that require an extra NULL byte at the end
 *  - Bit strings because libtasn1 returns the length in bits, not bytes.
 *
 * If the function returns a non-NULL value, the caller must free it.
 */
void *
grub_asn1_allocate_and_read (asn1_node node, const char *name, const char *friendly_name,
                             grub_int32_t *content_size)
{
  grub_int32_t result;
  grub_uint8_t *tmpstr = NULL;
  grub_int32_t tmpstr_size = 0;

  result = asn1_read_value (node, name, NULL, &tmpstr_size);
  if (result != ASN1_MEM_ERROR)
    {
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "reading size of %s did not return expected status: %s",
                  friendly_name, asn1_strerror (result)) ;
      return NULL;
    }

  tmpstr = grub_malloc (tmpstr_size);
  if (tmpstr == NULL)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not allocate memory to store %s",
                  friendly_name) ;
      return NULL;
    }

  result = asn1_read_value (node, name, tmpstr, &tmpstr_size);
  if (result != ASN1_SUCCESS)
    {
      grub_free (tmpstr);
      grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading %s: %s", friendly_name,
                  asn1_strerror (result)) ;
      return NULL;
    }

  *content_size = tmpstr_size;

  return tmpstr;
}

int
grub_asn1_init (void)
{
  int res;

  res = asn1_array2tree (grub_gnutls_asn1_tab, &grub_gnutls_gnutls_asn, NULL);
  if (res != ASN1_SUCCESS)
    return res;

  res = asn1_array2tree (grub_pkix_asn1_tab, &grub_gnutls_pkix_asn, NULL);

  return res;
}
