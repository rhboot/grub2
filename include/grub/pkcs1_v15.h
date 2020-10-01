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

/*
 * Given a hash value 'hval', of hash specification 'hash', perform
 * the EMSA-PKCS1-v1_5 padding suitable for a key with modulus 'mod'
 * (See RFC 8017 s 9.2)
 */
gcry_err_code_t
grub_crypto_rsa_pad (gcry_mpi_t * hmpi, grub_uint8_t * hval,
		     const gcry_md_spec_t * hash, gcry_mpi_t mod);

