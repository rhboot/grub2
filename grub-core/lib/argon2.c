/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025  Free Software Foundation, Inc.
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

#include <grub/crypto.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

gcry_err_code_t
grub_crypto_argon2 (int subalgo,
		    const unsigned long *param, unsigned int paramlen,
		    const void *password, grub_size_t passwordlen,
		    const void *salt, grub_size_t saltlen,
		    const void *key, grub_size_t keylen,
		    const void *ad, grub_size_t adlen,
		    grub_size_t resultlen, void *result)
{
  gcry_kdf_hd_t hd = {0};
  gpg_err_code_t err;

  if (saltlen == 0)
    return GPG_ERR_INV_VALUE;

  err = _gcry_kdf_open (&hd, GRUB_GCRY_KDF_ARGON2, subalgo, param, paramlen,
			password, passwordlen, salt, saltlen, key, keylen,
			ad, adlen);
  if (err != GPG_ERR_NO_ERROR)
    return err;

  err = _gcry_kdf_compute (hd, NULL);
  if (err == GPG_ERR_NO_ERROR)
    err = _gcry_kdf_final (hd, resultlen, result);

  _gcry_kdf_close (hd);

  return err;
}
