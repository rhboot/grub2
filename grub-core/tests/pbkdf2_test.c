/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013 Free Software Foundation, Inc.
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

static struct
{
  const char *P;
  grub_size_t Plen;
  const char *S;
  grub_size_t Slen;
  unsigned int c;
  grub_size_t dkLen;
  const gcry_md_spec_t *HMAC_variant;
  const char *DK;
} vectors[] = {
  /* RFC6070. */
  {
    "password", 8,
    "salt", 4,
    1, 20,
    GRUB_MD_SHA1,
    "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12"
    "\x06\x2f\xe0\x37\xa6"
  },
  {
    "password", 8,
    "salt", 4,
    2, 20,
    GRUB_MD_SHA1,
    "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c"
    "\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0"
    "\xd8\xde\x89\x57"
  },
  {
    "password", 8,
    "salt", 4,
    4096, 20,
    GRUB_MD_SHA1,
    "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7"
    "\x21\xd0\x65\xa4\x29\xc1"
  },
  {
    "passwordPASSWORDpassword", 24,
    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
    4096, 25,
    GRUB_MD_SHA1,
    "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0"
    "\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38"
  },
  {
    "pass\0word", 9,
    "sa\0lt", 5,
    4096, 16,
    GRUB_MD_SHA1,
    "\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3"
  },
  /* Re-using the above vectors for HMAC-SHA{256,512} */
  {
    "password", 8,
    "salt", 4,
    1, 20,
    GRUB_MD_SHA256,
    "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56\xc4\xf8"
    "\x37\xa8\x65\x48\xc9"
  },
  {
    "password", 8,
    "salt", 4,
    2, 20,
    GRUB_MD_SHA256,
    "\xae\x4d\x0c\x95\xaf\x6b\x46\xd3"
    "\x2d\x0a\xdf\xf9\x28\xf0\x6d\xd0"
    "\x2a\x30\x3f\x8e"
  },
  {
    "password", 8,
    "salt", 4,
    4096, 20,
    GRUB_MD_SHA256,
    "\xc5\xe4\x78\xd5\x92\x88\xc8\x41\xaa\x53\x0d\xb6\x84\x5c"
    "\x4c\x8d\x96\x28\x93\xa0"
  },
  {
    "passwordPASSWORDpassword", 24,
    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
    4096, 25,
    GRUB_MD_SHA256,
    "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e"
    "\x84\xcf\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c"
  },
  {
    "pass\0word", 9,
    "sa\0lt", 5,
    4096, 16,
    GRUB_MD_SHA256,
    "\x89\xb6\x9d\x05\x16\xf8\x29\x89\x3c\x69\x62\x26\x65\x0a\x86\x87"
  },
  {
    "password", 8,
    "salt", 4,
    1, 20,
    GRUB_MD_SHA512,
    "\x86\x7f\x70\xcf\x1a\xde\x02\xcf\xf3\x75\x25\x99\xa3\xa5\x3d"
    "\xc4\xaf\x34\xc7\xa6"
  },
  {
    "password", 8,
    "salt", 4,
    2, 20,
    GRUB_MD_SHA512,
    "\xe1\xd9\xc1\x6a\xa6\x81\x70\x8a"
    "\x45\xf5\xc7\xc4\xe2\x15\xce\xb6"
    "\x6e\x01\x1a\x2e"
  },
  {
    "password", 8,
    "salt", 4,
    4096, 20,
    GRUB_MD_SHA512,
    "\xd1\x97\xb1\xb3\x3d\xb0\x14\x3e\x01\x8b\x12\xf3\xd1\xd1"
    "\x47\x9e\x6c\xde\xbd\xcc"
  },
  {
    "passwordPASSWORDpassword", 24,
    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
    4096, 25,
    GRUB_MD_SHA512,
    "\x8c\x05\x11\xf4\xc6\xe5\x97\xc6\xac\x63\x15\xd8\xf0\x36"
    "\x2e\x22\x5f\x3c\x50\x14\x95\xba\x23\xb8\x68"
  },
  {
    "pass\0word", 9,
    "sa\0lt", 5,
    4096, 16,
    GRUB_MD_SHA512,
    "\x9d\x9e\x9c\x4c\xd2\x1f\xe4\xbe\x24\xd5\xb8\x24\x4c\x75\x96\x65"
  }
};

static void
pbkdf2_test (void)
{
  grub_size_t i;

  for (i = 0; i < ARRAY_SIZE (vectors); i++)
    {
      gcry_err_code_t err;
      grub_uint8_t DK[32];
      err = grub_crypto_pbkdf2 (vectors[i].HMAC_variant,
				(const grub_uint8_t *) vectors[i].P,
				vectors[i].Plen,
				(const grub_uint8_t *) vectors[i].S,
				vectors[i].Slen,
				vectors[i].c,
				DK, vectors[i].dkLen);
      grub_test_assert (err == 0, "gcry error %d", err);
      grub_test_assert (grub_memcmp (DK, vectors[i].DK, vectors[i].dkLen) == 0,
			"PBKDF2 mismatch");
    }
}

/* Register example_test method as a functional test.  */
GRUB_FUNCTIONAL_TEST (pbkdf2_test, pbkdf2_test);
