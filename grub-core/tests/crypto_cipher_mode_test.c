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

#include "crypto_cipher_mode_vectors.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Perform cipher lookup, handle init, and key setting. */
static grub_crypto_cipher_handle_t
handle_init (struct vector vec, grub_crypto_cipher_handle_t handle)
{
  gcry_err_code_t err;

  const gcry_cipher_spec_t *cipher = grub_crypto_lookup_cipher_by_name (vec.cipher);
  grub_test_assert (cipher != NULL, "\n%s: cipher lookup failed for %s", vec.mode, vec.cipher);
  if (cipher == NULL)
    return NULL;

  handle = grub_crypto_cipher_open (cipher);
  grub_test_assert (handle != NULL, "\n%s: handle init failed for %s", vec.mode, vec.cipher);
  if (handle == NULL)
    return NULL;

  err = grub_crypto_cipher_set_key (handle, (grub_uint8_t *) vec.key, vec.keylen);
  grub_test_assert (err == GPG_ERR_NO_ERROR, "\n%s: key set of size %d failed for %s with err = %d",
                    vec.mode, vec.keylen, vec.cipher, err);
  if (err != GPG_ERR_NO_ERROR)
    {
      grub_crypto_cipher_close (handle);
      return NULL;
    }

  return handle;
}

static void
ecb_test (struct vector vec)
{
  gcry_err_code_t gcry_err;
  grub_crypto_cipher_handle_t handle = NULL;
  grub_uint8_t *plaintext = NULL, *ciphertext = NULL;
  grub_int32_t rc;

  handle = handle_init (vec, handle);
  if (handle == NULL)
    return;

  /* Test encryption. */
  ciphertext = grub_zalloc (vec.plen);
  grub_test_assert (ciphertext != NULL, "\necb: ciphertext buffer allocation failed");
  if (ciphertext == NULL)
    goto out_handle;

  gcry_err = grub_crypto_ecb_encrypt (handle, ciphertext, vec.ptext, vec.plen);
  grub_test_assert (gcry_err == GPG_ERR_NO_ERROR, "\necb: encryption failed with err = %d",
                    gcry_err);
  if (gcry_err != GPG_ERR_NO_ERROR)
    goto out_ct;

  rc = grub_memcmp (ciphertext, vec.ctext, vec.plen);
  grub_test_assert (rc == 0, "\necb: ciphertext mismatch after encryption");
  if (rc != 0)
    goto out_ct;

  /* Test decryption. */
  plaintext = grub_zalloc (vec.plen);
  grub_test_assert (plaintext != NULL, "\necb: plaintext buffer allocation failed");
  if (plaintext == NULL)
    goto out_ct;

  gcry_err = grub_crypto_ecb_decrypt (handle, plaintext, ciphertext, vec.plen);
  grub_test_assert (gcry_err == GPG_ERR_NO_ERROR, "\necb: decryption failed failed with err = %d",
                    gcry_err);
  if (gcry_err != GPG_ERR_NO_ERROR)
    goto out_pt;

  rc = grub_memcmp (plaintext, vec.ptext, vec.plen);
  grub_test_assert (rc == 0, "\necb: plaintext mismatch after decryption");

 out_pt:
  grub_free(plaintext);
 out_ct:
  grub_free(ciphertext);
 out_handle:
  grub_crypto_cipher_close(handle);
}

static void
cbc_test (struct vector vec)
{
  gcry_err_code_t gcry_err;
  grub_crypto_cipher_handle_t handle = NULL;
  grub_uint8_t *plaintext = NULL, *ciphertext = NULL;
  grub_uint32_t *iv = NULL;
  grub_int32_t rc;

  handle = handle_init (vec, handle);
  if (handle == NULL)
    return;

  /* Test Encryption */
  iv = grub_malloc(vec.ivlen);
  grub_test_assert (iv != NULL, "\ncbc: IV buffer allocation failed");
  if (iv == NULL)
    goto out_handle;

  grub_memcpy (iv, vec.iv_in, vec.ivlen);

  ciphertext = grub_zalloc (vec.plen);
  grub_test_assert (ciphertext != NULL, "\ncbc: ciphertext buffer allocation failed");
  if (ciphertext == NULL)
    goto out_iv;

  gcry_err = grub_crypto_cbc_encrypt (handle, ciphertext, vec.ptext, vec.plen, iv);
  grub_test_assert (gcry_err == GPG_ERR_NO_ERROR, "\ncbc: encryption failed with err = %d",
                    gcry_err);
  if (gcry_err != GPG_ERR_NO_ERROR)
    goto out_ct;

  rc = grub_memcmp (ciphertext, vec.ctext, vec.plen);
  grub_test_assert (rc == 0, "\ncbc: ciphertext mismatch after encryption");
  if (rc != 0)
    goto out_ct;

  rc = grub_memcmp (iv, vec.iv_out, vec.ivlen);
  grub_test_assert (rc == 0, "\ncbc: IV out mismatch after encryption");
  if (rc != 0)
    goto out_ct;

  /* Test Decryption  */
  grub_memcpy (iv, vec.iv_in, vec.ivlen);

  plaintext = grub_zalloc (vec.plen);
  grub_test_assert (plaintext != NULL, "\ncbc: plaintext buffer allocation failed");
  if (plaintext == NULL)
    goto out_ct;

  gcry_err = grub_crypto_cbc_decrypt (handle, plaintext, ciphertext, vec.plen, iv);
  grub_test_assert (gcry_err == GPG_ERR_NO_ERROR, "\ncbc: decryption failed with err = %d",
                    gcry_err);
  if (gcry_err != GPG_ERR_NO_ERROR)
    goto out_pt;

  rc = grub_memcmp (plaintext, vec.ptext, vec.plen);
  grub_test_assert (rc == 0, "\ncbc: plaintext mismatch after decryption");

 out_pt:
  grub_free(plaintext);
 out_ct:
  grub_free(ciphertext);
 out_iv:
  grub_free(iv);
 out_handle:
  grub_crypto_cipher_close(handle);
}

static void
crypto_cipher_mode_test (void)
{
  grub_size_t i;

  for (i = 0; i < ARRAY_SIZE (vecs); i++)
    {
      if (grub_strcmp (vecs[i].mode, "ecb") == 0)
        ecb_test(vecs[i]);
      else if (grub_strcmp (vecs[i].mode, "cbc") == 0)
        cbc_test(vecs[i]);
      else
        {
          grub_test_assert(0, "\n%s mode unsupported for testing", vecs[i].mode);
          return;
        }
    }
}

/* Register example_test method as a functional test.  */
GRUB_FUNCTIONAL_TEST (crypto_cipher_mode_test, crypto_cipher_mode_test);
