/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2006
 *                2007, 2008, 2009  Free Software Foundation, Inc.
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
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/term.h>
#include <grub/dl.h>
#include <grub/i18n.h>
#include <grub/env.h>

GRUB_MOD_LICENSE ("GPLv3+");

struct grub_crypto_hmac_handle
{
  const struct gcry_md_spec *md;
  void *ctx;
  void *opad;
};

static gcry_cipher_spec_t *grub_ciphers = NULL;
static gcry_md_spec_t *grub_digests = NULL;

int _gcry_no_fips_mode_required = 1;

void (*grub_crypto_autoload_hook) (const char *name) = NULL;

/* Based on libgcrypt-1.4.4/src/misc.c.  */
void
grub_burn_stack (grub_size_t size)
{
  char buf[64];

  grub_memset (buf, 0, sizeof (buf));
  if (size > sizeof (buf))
    grub_burn_stack (size - sizeof (buf));
}

void
_gcry_burn_stack (int size)
{
  grub_burn_stack (size);
}

void
__gcry_burn_stack (unsigned int size)
{
  grub_burn_stack (size);
}

void
__gcry_burn_stack_dummy (void)
{
}

void __attribute__ ((noreturn))
_gcry_assert_failed (const char *expr, const char *file, int line,
		     const char *func)

{
  grub_fatal ("assertion %s at %s:%d (%s) failed\n", expr, file, line, func);
}

void
_gcry_bug( const char *file, int line, const char *func )
{
    grub_fatal ("... this is a bug (%s:%d:%s)\n", file, line, func);
}


void _gcry_log_error (const char *fmt, ...)
{
  va_list args;
  const char *debug = grub_env_get ("debug");

  if (! debug)
    return;

  if (grub_strword (debug, "all") || grub_strword (debug, "gcrypt"))
    {
      grub_printf ("gcrypt error: ");
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

void _gcry_log_info (const char *fmt, ...)
{
  va_list args;
  const char *debug = grub_env_get ("debug");

  if (! debug)
    return;

  if (grub_strword (debug, "all") || grub_strword (debug, "gcrypt"))
    {
      grub_printf ("gcrypt info: ");
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

void
_gcry_fast_wipememory2 (void *ptr, int set, grub_size_t len)
{
  grub_memset(ptr, set, len);
}

void
_gcry_fast_wipememory (void *ptr, grub_size_t len)
{
  grub_memset(ptr, 0, len);
}

void
grub_cipher_register (gcry_cipher_spec_t *cipher)
{
  cipher->next = grub_ciphers;
  grub_ciphers = cipher;
}

void
grub_cipher_unregister (gcry_cipher_spec_t *cipher)
{
  gcry_cipher_spec_t **ciph;
  for (ciph = &grub_ciphers; *ciph; ciph = &((*ciph)->next))
    if (*ciph == cipher)
      {
	*ciph = (*ciph)->next;
	break;
      }
}

void
grub_md_register (gcry_md_spec_t *digest)
{
  digest->next = grub_digests;
  grub_digests = digest;
}

void
grub_md_unregister (gcry_md_spec_t *cipher)
{
  gcry_md_spec_t **ciph;
  for (ciph = &grub_digests; *ciph; ciph = &((*ciph)->next))
    if (*ciph == cipher)
      {
	*ciph = (*ciph)->next;
	break;
      }
}

struct gcry_pk_spec *grub_crypto_pk_dsa;
struct gcry_pk_spec *grub_crypto_pk_ecdsa;
struct gcry_pk_spec *grub_crypto_pk_rsa;

void
grub_crypto_hash (const gcry_md_spec_t *hash, void *out, const void *in,
		  grub_size_t inlen)
{
  GRUB_PROPERLY_ALIGNED_ARRAY (ctx, GRUB_CRYPTO_MAX_MD_CONTEXT_SIZE);

  if (hash->contextsize > sizeof (ctx))
    grub_fatal ("Too large md context");
  hash->init (&ctx, 0);
  hash->write (&ctx, in, inlen);
  hash->final (&ctx);
  grub_memcpy (out, hash->read (&ctx), hash->mdlen);
}

const gcry_md_spec_t *
grub_crypto_lookup_md_by_name (const char *name)
{
  const gcry_md_spec_t *md;
  int first = 1;
  while (1)
    {
      for (md = grub_digests; md; md = md->next)
	if (grub_strcasecmp (name, md->name) == 0)
	  return md;
      if (grub_crypto_autoload_hook && first)
	grub_crypto_autoload_hook (name);
      else
	return NULL;
      first = 0;
    }
}

const gcry_md_spec_t *
grub_crypto_lookup_md_by_oid (const char *oid)
{
  const gcry_md_spec_t *md;

  if (!oid)
    return NULL;

  if (grub_strncmp (oid, "oid.", 4) == 0 || grub_strncmp (oid, "OID.", 4) == 0)
    oid += 4;


  for (md = grub_digests; md; md = md->next)
    {
      const gcry_md_oid_spec_t *oid_specs = md->oids;
      if (oid_specs)
        {
          for (int j = 0; oid_specs[j].oidstring; j++)
            if (grub_strcasecmp (oid, oid_specs[j].oidstring) == 0)
              return md;
        }
    }

  return NULL;
}

static const char *md_algos[] = {
    [1] = "MD5",
    [2] = "SHA1",
    [3] = "RIPEMD160",
    [6] = "TIGER",
    [8] = "SHA256",
    [9] = "SHA384",
    [10] = "SHA512",
    [11] = "SHA224",

    [301] = "MD4",
    [302] = "CRC32",
    [303] = "CRC32RFC1510",
    [304] = "CRC24RFC2440",
    [305] = "WHIRLPOOL",
    [306] = "TIGER1",
    [307] = "TIGER2",
    [308] = "GOSTR3411_94",
    [309] = "STRIBOG256",
    [310] = "STRIBOG512",
    [311] = "GOSTR3411_CP",
    [312] = "SHA3-224",
    [313] = "SHA3-256",
    [314] = "SHA3-384",
    [315] = "SHA3-512",
    [316] = "SHAKE128",
    [317] = "SHAKE256",
    [318] = "BLAKE2B_512",
    [319] = "BLAKE2B_384",
    [320] = "BLAKE2B_256",
    [321] = "BLAKE2B_160",
    [322] = "BLAKE2S_256",
    [323] = "BLAKE2S_224",
    [324] = "BLAKE2S_160",
    [325] = "BLAKE2S_128",
    [326] = "SM3",
    [327] = "SHA512_256",
    [328] = "SHA512_224",
};


const gcry_md_spec_t *
grub_crypto_lookup_md_by_algo (int algo)
{
  const gcry_md_spec_t *md;
  int first = 1;
  while (1)
    {
      for (md = grub_digests; md; md = md->next)
	if (algo == md->algo)
	  return md;
      if (grub_crypto_autoload_hook && first && algo > 0 && algo < (int)ARRAY_SIZE(md_algos) && md_algos[algo]) {
	grub_crypto_autoload_hook (md_algos[algo]);
      } else
	return NULL;
      first = 0;
    }
}

const gcry_cipher_spec_t *
grub_crypto_lookup_cipher_by_name (const char *name)
{
  const gcry_cipher_spec_t *ciph;
  int first = 1;
  while (1)
    {
      for (ciph = grub_ciphers; ciph; ciph = ciph->next)
	{
	  const char **alias;
	  if (grub_strcasecmp (name, ciph->name) == 0)
	    return ciph;
	  if (!ciph->aliases)
	    continue;
	  for (alias = ciph->aliases; *alias; alias++)
	    if (grub_strcasecmp (name, *alias) == 0)
	      return ciph;
	}
      if (grub_crypto_autoload_hook && first)
	grub_crypto_autoload_hook (name);
      else
	return NULL;
      first = 0;
    }
}


grub_crypto_cipher_handle_t
grub_crypto_cipher_open (const struct gcry_cipher_spec *cipher)
{
  grub_crypto_cipher_handle_t ret;
  ret = grub_malloc (sizeof (*ret) + cipher->contextsize);
  if (!ret)
    return NULL;
  ret->cipher = cipher;
  return ret;
}

gcry_err_code_t
grub_crypto_cipher_set_key (grub_crypto_cipher_handle_t cipher,
			    const unsigned char *key,
			    unsigned keylen)
{
  /* TODO: Fix this. It's ugly as hell.  */
  void *bulk_ops[100];
  return cipher->cipher->setkey (cipher->ctx, key, keylen, (void *) bulk_ops);
}

gcry_err_code_t
grub_crypto_ecb_decrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size)
{
  const grub_uint8_t *inptr, *end;
  grub_uint8_t *outptr;
  grub_size_t blocksize;
  if (!cipher->cipher->decrypt)
    return GPG_ERR_NOT_SUPPORTED;
  blocksize = cipher->cipher->blocksize;
  if (blocksize == 0 || (((blocksize - 1) & blocksize) != 0)
      || ((size & (blocksize - 1)) != 0))
    return GPG_ERR_INV_ARG;
  end = (const grub_uint8_t *) in + size;
  for (inptr = in, outptr = out; inptr < end;
       inptr += blocksize, outptr += blocksize)
    cipher->cipher->decrypt (cipher->ctx, outptr, inptr);
  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
grub_crypto_ecb_encrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size)
{
  const grub_uint8_t *inptr, *end;
  grub_uint8_t *outptr;
  grub_size_t blocksize;
  if (!cipher->cipher->encrypt)
    return GPG_ERR_NOT_SUPPORTED;
  blocksize = cipher->cipher->blocksize;
  if (blocksize == 0 || (((blocksize - 1) & blocksize) != 0)
      || ((size & (blocksize - 1)) != 0))
    return GPG_ERR_INV_ARG;
  end = (const grub_uint8_t *) in + size;
  for (inptr = in, outptr = out; inptr < end;
       inptr += blocksize, outptr += blocksize)
    cipher->cipher->encrypt (cipher->ctx, outptr, inptr);
  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
grub_crypto_cbc_encrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size,
			 void *iv_in)
{
  grub_uint8_t *outptr;
  const grub_uint8_t *inptr, *end;
  void *iv;
  grub_size_t blocksize;
  if (!cipher->cipher->encrypt)
    return GPG_ERR_NOT_SUPPORTED;
  blocksize = cipher->cipher->blocksize;
  if (blocksize == 0 || (((blocksize - 1) & blocksize) != 0)
      || ((size & (blocksize - 1)) != 0))
    return GPG_ERR_INV_ARG;
  end = (const grub_uint8_t *) in + size;
  iv = iv_in;
  for (inptr = in, outptr = out; inptr < end;
       inptr += blocksize, outptr += blocksize)
    {
      grub_crypto_xor (outptr, inptr, iv, blocksize);
      cipher->cipher->encrypt (cipher->ctx, outptr, outptr);
      iv = outptr;
    }
  grub_memcpy (iv_in, iv, blocksize);
  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
grub_crypto_cbc_decrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size,
			 void *iv)
{
  const grub_uint8_t *inptr, *end;
  grub_uint8_t *outptr;
  grub_uint8_t ivt[GRUB_CRYPTO_MAX_CIPHER_BLOCKSIZE];
  grub_size_t blocksize;
  if (!cipher->cipher->decrypt)
    return GPG_ERR_NOT_SUPPORTED;
  blocksize = cipher->cipher->blocksize;
  if (blocksize == 0 || (((blocksize - 1) & blocksize) != 0)
      || ((size & (blocksize - 1)) != 0))
    return GPG_ERR_INV_ARG;
  if (blocksize > GRUB_CRYPTO_MAX_CIPHER_BLOCKSIZE)
    return GPG_ERR_INV_ARG;
  end = (const grub_uint8_t *) in + size;
  for (inptr = in, outptr = out; inptr < end;
       inptr += blocksize, outptr += blocksize)
    {
      grub_memcpy (ivt, inptr, blocksize);
      cipher->cipher->decrypt (cipher->ctx, outptr, inptr);
      grub_crypto_xor (outptr, outptr, iv, blocksize);
      grub_memcpy (iv, ivt, blocksize);
    }
  return GPG_ERR_NO_ERROR;
}

/* Based on gcry/cipher/md.c.  */
struct grub_crypto_hmac_handle *
grub_crypto_hmac_init (const struct gcry_md_spec *md,
		       const void *key, grub_size_t keylen)
{
  grub_uint8_t *helpkey = NULL;
  grub_uint8_t *ipad = NULL, *opad = NULL;
  void *ctx = NULL;
  struct grub_crypto_hmac_handle *ret = NULL;
  unsigned i;

  if (md->mdlen > md->blocksize)
    return NULL;

  ctx = grub_malloc (md->contextsize);
  if (!ctx)
    goto err;

  if ( keylen > md->blocksize )
    {
      helpkey = grub_malloc (md->mdlen);
      if (!helpkey)
	goto err;
      grub_crypto_hash (md, helpkey, key, keylen);

      key = helpkey;
      keylen = md->mdlen;
    }

  ipad = grub_zalloc (md->blocksize);
  if (!ipad)
    goto err;

  opad = grub_zalloc (md->blocksize);
  if (!opad)
    goto err;

  grub_memcpy ( ipad, key, keylen );
  grub_memcpy ( opad, key, keylen );
  for (i=0; i < md->blocksize; i++ )
    {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
    }
  grub_free (helpkey);
  helpkey = NULL;

  md->init (ctx, 0);

  md->write (ctx, ipad, md->blocksize); /* inner pad */
  grub_memset (ipad, 0, md->blocksize);
  grub_free (ipad);
  ipad = NULL;

  ret = grub_malloc (sizeof (*ret));
  if (!ret)
    goto err;

  ret->md = md;
  ret->ctx = ctx;
  ret->opad = opad;

  return ret;

 err:
  grub_free (helpkey);
  grub_free (ctx);
  grub_free (ipad);
  grub_free (opad);
  return NULL;
}

void
grub_crypto_hmac_write (struct grub_crypto_hmac_handle *hnd,
			const void *data,
			grub_size_t datalen)
{
  hnd->md->write (hnd->ctx, data, datalen);
}

gcry_err_code_t
grub_crypto_hmac_fini (struct grub_crypto_hmac_handle *hnd, void *out)
{
  grub_uint8_t *p;
  grub_uint8_t *ctx2;

  ctx2 = grub_malloc (hnd->md->contextsize);
  if (!ctx2)
    return GPG_ERR_OUT_OF_MEMORY;

  hnd->md->final (hnd->ctx);
  hnd->md->read (hnd->ctx);
  p = hnd->md->read (hnd->ctx);

  hnd->md->init (ctx2, 0);
  hnd->md->write (ctx2, hnd->opad, hnd->md->blocksize);
  hnd->md->write (ctx2, p, hnd->md->mdlen);
  hnd->md->final (ctx2);
  grub_memset (hnd->opad, 0, hnd->md->blocksize);
  grub_free (hnd->opad);
  grub_memset (hnd->ctx, 0, hnd->md->contextsize);
  grub_free (hnd->ctx);

  grub_memcpy (out, hnd->md->read (ctx2), hnd->md->mdlen);
  grub_memset (ctx2, 0, hnd->md->contextsize);
  grub_free (ctx2);

  grub_memset (hnd, 0, sizeof (*hnd));
  grub_free (hnd);

  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
grub_crypto_hmac_buffer (const struct gcry_md_spec *md,
			 const void *key, grub_size_t keylen,
			 const void *data, grub_size_t datalen, void *out)
{
  struct grub_crypto_hmac_handle *hnd;

  hnd = grub_crypto_hmac_init (md, key, keylen);
  if (!hnd)
    return GPG_ERR_OUT_OF_MEMORY;

  grub_crypto_hmac_write (hnd, data, datalen);
  return grub_crypto_hmac_fini (hnd, out);
}


grub_err_t
grub_crypto_gcry_error (gcry_err_code_t in)
{
  if (in == GPG_ERR_NO_ERROR)
    return GRUB_ERR_NONE;
  return GRUB_ACCESS_DENIED;
}


/*
 * Compare byte arrays of length LEN, return 1 if it's not same,
 * 0, otherwise.
 */
int
grub_crypto_memcmp (const void *b1, const void *b2, grub_size_t len)
{
  const grub_uint8_t *a = b1;
  const grub_uint8_t *b = b2;
  int ab, ba;
  grub_size_t i;

  /* Constant-time compare. */
  for (i = 0, ab = 0, ba = 0; i < len; i++)
    {
      /* If a[i] != b[i], either ab or ba will be negative. */
      ab |= a[i] - b[i];
      ba |= b[i] - a[i];
    }

  /* 'ab | ba' is negative when buffers are not equal, extract sign bit.  */
  return ((unsigned int)(ab | ba) >> (sizeof(unsigned int) * 8 - 1)) & 1;
}


void *
_gcry_malloc_secure (grub_size_t n)
{
  return grub_malloc(n);
}

void *
_gcry_malloc (grub_size_t n)
{
  return grub_malloc(n);
}

void *
_gcry_xmalloc(grub_size_t n)
{
  void *ret = grub_malloc(n);
  if (ret == NULL)
    grub_fatal("_gcry_xmalloc failed");
  return ret;
}

void *
_gcry_xmalloc_secure(grub_size_t n)
{
  void *ret = grub_malloc(n);
  if (ret == NULL)
    grub_fatal("_gcry_xmalloc_secure failed");
  return ret;
}

void _gcry_free (void *p)
{
  grub_free (p);
}

void *
_gcry_xrealloc (void *a, grub_size_t n)
{
  void *ret = grub_realloc(a, n);
  if (ret == NULL)
    grub_fatal("_gcry_xrealloc failed");
  return ret;
}

void *
_gcry_xcalloc (grub_size_t n, grub_size_t m)
{
  void *ret = grub_calloc(n, m);
  if (ret == NULL)
    grub_fatal("_gcry_xcalloc failed");
  return ret;
}

void *
_gcry_xcalloc_secure (grub_size_t n, grub_size_t m)
{
  void *ret = grub_calloc(n, m);
  if (ret == NULL)
    grub_fatal("_gcry_xcalloc_secure failed");
  return ret;
}


int
_gcry_is_secure (const void *a)
{
  (void) a;

  return 0;
}

void _gcry_divide_by_zero (void)
{
  grub_fatal("gcrypt division by zero");
}

#ifndef GRUB_UTIL

int
grub_password_get (char buf[], unsigned buf_size)
{
  unsigned cur_len = 0;
  int key;

  while (1)
    {
      key = grub_getkey ();
      if (key == '\n' || key == '\r')
	break;

      if (key == GRUB_TERM_ESC)
	{
	  cur_len = 0;
	  break;
	}

      if (key == '\b')
	{
	  if (cur_len)
	    cur_len--;
	  continue;
	}

      if (!grub_isprint (key))
	continue;

      if (cur_len + 2 < buf_size)
	buf[cur_len++] = key;
    }

  grub_memset (buf + cur_len, 0, buf_size - cur_len);

  grub_xputs ("\n");
  grub_refresh ();

  return (key != GRUB_TERM_ESC);
}
#endif

