/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025 Free Software Foundation, Inc.
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
#include <grub/misc.h>
#include <grub/crypto.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define DIM(v) (sizeof(v)/sizeof((v)[0]))

static void
argon2_test (void)
{
  gcry_error_t err;
  static struct {
    int subalgo;
    unsigned long param[4];
    grub_size_t passlen;
    const char *pass;
    grub_size_t saltlen;
    const char *salt;
    grub_size_t keylen;
    const char *key;
    grub_size_t adlen;
    const char *ad;
    grub_size_t dklen;
    const char *dk;
  } tv[] = {
    {
      GRUB_GCRY_KDF_ARGON2D,
      { 32, 3, 32, 4 },
      32,
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
      16,
      "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02",
      8,
      "\x03\x03\x03\x03\x03\x03\x03\x03",
      12,
      "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04",
      32,
      "\x51\x2b\x39\x1b\x6f\x11\x62\x97\x53\x71\xd3\x09\x19\x73\x42\x94"
      "\xf8\x68\xe3\xbe\x39\x84\xf3\xc1\xa1\x3a\x4d\xb9\xfa\xbe\x4a\xcb"
    },
    {
      GRUB_GCRY_KDF_ARGON2I,
      { 32, 3, 32, 4 },
      32,
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
      16,
      "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02",
      8,
      "\x03\x03\x03\x03\x03\x03\x03\x03",
      12,
      "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04",
      32,
      "\xc8\x14\xd9\xd1\xdc\x7f\x37\xaa\x13\xf0\xd7\x7f\x24\x94\xbd\xa1"
      "\xc8\xde\x6b\x01\x6d\xd3\x88\xd2\x99\x52\xa4\xc4\x67\x2b\x6c\xe8"
    },
    {
      GRUB_GCRY_KDF_ARGON2ID,
      { 32, 3, 32, 4 },
      32,
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
      16,
      "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02",
      8,
      "\x03\x03\x03\x03\x03\x03\x03\x03",
      12,
      "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04",
      32,
      "\x0d\x64\x0d\xf5\x8d\x78\x76\x6c\x08\xc0\x37\xa3\x4a\x8b\x53\xc9"
      "\xd0\x1e\xf0\x45\x2d\x75\xb6\x5e\xb5\x25\x20\xe9\x6b\x01\xe6\x59"
    },
    {
      /* empty password */
      GRUB_GCRY_KDF_ARGON2I,
      { 32, 3, 128, 1 },
      0, NULL,
      16,
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
      0, NULL,
      0, NULL,
      32,
      "\xbb\x1f\xf2\xb9\x9f\xd4\x4a\xd9\xdf\x7f\xb9\x54\x55\x9e\xb8\xeb"
      "\xb5\x9d\xab\xce\x2e\x62\x9f\x9b\x89\x09\xfe\xde\x57\xcc\x63\x86"
    },
    {
      /* empty password */
      GRUB_GCRY_KDF_ARGON2ID,
      { 32, 3, 128, 1 },
      0, NULL,
      16,
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
      0, NULL,
      0, NULL,
      32,
      "\x09\x2f\x38\x35\xac\xb2\x43\x92\x93\xeb\xcd\xe8\x04\x16\x6a\x31"
      "\xce\x14\xd4\x55\xdb\xd8\xf7\xe6\xb4\xf5\x9d\x64\x8e\xd0\x3a\xdb"
    },
  };
  unsigned char out[32];
  unsigned int count;

  for (count = 0; count < DIM(tv); count++)
    {
      err = grub_crypto_argon2 (tv[count].subalgo,
				tv[count].param, 4,
				tv[count].pass, tv[count].passlen,
				tv[count].salt, tv[count].saltlen,
				tv[count].key, tv[count].keylen,
				tv[count].ad, tv[count].adlen,
				tv[count].dklen, out);
      grub_test_assert (err == 0, "argon2 test %d failed: %d", count, err);
      grub_test_assert (grub_memcmp (out, tv[count].dk, tv[count].dklen) == 0,
			"argon2 test %d failed: mismatch", count);
    }
}

GRUB_FUNCTIONAL_TEST (argon2_test, argon2_test);
