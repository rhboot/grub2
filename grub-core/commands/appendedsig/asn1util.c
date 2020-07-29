/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  IBM Corporation.
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

#include <grub/libtasn1.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/crypto.h>
#include <grub/gcrypt/gcrypt.h>

#include "appendedsig.h"

asn1_node _gnutls_gnutls_asn = ASN1_TYPE_EMPTY;
asn1_node _gnutls_pkix_asn = ASN1_TYPE_EMPTY;

extern const ASN1_ARRAY_TYPE gnutls_asn1_tab[];
extern const ASN1_ARRAY_TYPE pkix_asn1_tab[];

/*
 * Read a value from an ASN1 node, allocating memory to store it.
 *
 * It will work for anything where the size libtasn1 returns is right:
 *  - Integers
 *  - Octet strings
 *  - DER encoding of other structures
 * It will _not_ work for things where libtasn1 size requires adjustment:
 *  - Strings that require an extra NULL byte at the end
 *  - Bit strings because libtasn1 returns the length in bits, not bytes.
 *
 * If the function returns a non-NULL value, the caller must free it.
 */
void *
grub_asn1_allocate_and_read (asn1_node node, const char *name,
			     const char *friendly_name, int *content_size)
{
  int result;
  grub_uint8_t *tmpstr = NULL;
  int tmpstr_size = 0;

  result = asn1_read_value (node, name, NULL, &tmpstr_size);
  if (result != ASN1_MEM_ERROR)
    {
      grub_snprintf (grub_errmsg, sizeof (grub_errmsg),
		     _
		     ("Reading size of %s did not return expected status: %s"),
		     friendly_name, asn1_strerror (result));
      grub_errno = GRUB_ERR_BAD_FILE_TYPE;
      return NULL;
    }

  tmpstr = grub_malloc (tmpstr_size);
  if (tmpstr == NULL)
    {
      grub_snprintf (grub_errmsg, sizeof (grub_errmsg),
		     "Could not allocate memory to store %s", friendly_name);
      grub_errno = GRUB_ERR_OUT_OF_MEMORY;
      return NULL;
    }

  result = asn1_read_value (node, name, tmpstr, &tmpstr_size);
  if (result != ASN1_SUCCESS)
    {
      grub_free (tmpstr);
      grub_snprintf (grub_errmsg, sizeof (grub_errmsg),
		     "Error reading %s: %s",
		     friendly_name, asn1_strerror (result));
      grub_errno = GRUB_ERR_BAD_FILE_TYPE;
      return NULL;
    }

  *content_size = tmpstr_size;

  return tmpstr;
}

int
asn1_init (void)
{
  int res;
  res = asn1_array2tree (gnutls_asn1_tab, &_gnutls_gnutls_asn, NULL);
  if (res != ASN1_SUCCESS)
    {
      return res;
    }
  res = asn1_array2tree (pkix_asn1_tab, &_gnutls_pkix_asn, NULL);
  return res;
}
