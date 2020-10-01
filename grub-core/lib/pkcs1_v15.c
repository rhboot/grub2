/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013  Free Software Foundation, Inc.
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
#include <grub/gcrypt/gcrypt.h>

GRUB_MOD_LICENSE ("GPLv3+");

/*
 * Given a hash value 'hval', of hash specification 'hash', perform
 * the EMSA-PKCS1-v1_5 padding suitable for a key with modulus 'mod'
 * (see RFC 8017 s 9.2) and place the result in 'hmpi'.
 */
gcry_err_code_t
grub_crypto_rsa_pad (gcry_mpi_t * hmpi, grub_uint8_t * hval,
		     const gcry_md_spec_t * hash, gcry_mpi_t mod)
{
  grub_size_t tlen, emlen, fflen;
  grub_uint8_t *em, *emptr;
  unsigned nbits = gcry_mpi_get_nbits (mod);
  int ret;
  tlen = hash->mdlen + hash->asnlen;
  emlen = (nbits + 7) / 8;
  if (emlen < tlen + 11)
    return GPG_ERR_TOO_SHORT;

  em = grub_malloc (emlen);
  if (!em)
    return 1;

  em[0] = 0x00;
  em[1] = 0x01;
  fflen = emlen - tlen - 3;
  for (emptr = em + 2; emptr < em + 2 + fflen; emptr++)
    *emptr = 0xff;
  *emptr++ = 0x00;
  grub_memcpy (emptr, hash->asnoid, hash->asnlen);
  emptr += hash->asnlen;
  grub_memcpy (emptr, hval, hash->mdlen);

  ret = gcry_mpi_scan (hmpi, GCRYMPI_FMT_USG, em, emlen, 0);
  grub_free (em);
  return ret;
}
