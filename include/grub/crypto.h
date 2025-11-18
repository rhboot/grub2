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

/* Contains elements based on gcrypt-module.h and gcrypt.h.in.
   If it's changed please update this file.  */

#ifndef GRUB_CRYPTO_HEADER
#define GRUB_CRYPTO_HEADER 1

#include <grub/symbol.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>

typedef enum
  {
    GPG_ERR_NO_ERROR,
    GPG_ERR_BAD_MPI,
    GPG_ERR_BAD_SECKEY,
    GPG_ERR_BAD_SIGNATURE,
    GPG_ERR_CIPHER_ALGO,
    GPG_ERR_CONFLICT,
    GPG_ERR_DECRYPT_FAILED,
    GPG_ERR_DIGEST_ALGO,
    GPG_ERR_GENERAL,
    GPG_ERR_INTERNAL,
    GPG_ERR_INV_ARG,
    GPG_ERR_INV_CIPHER_MODE,
    GPG_ERR_INV_FLAG,
    GPG_ERR_INV_KEYLEN,
    GPG_ERR_INV_OBJ,
    GPG_ERR_INV_OP,
    GPG_ERR_INV_SEXP,
    GPG_ERR_INV_VALUE,
    GPG_ERR_MISSING_VALUE,
    GPG_ERR_NO_ENCRYPTION_SCHEME,
    GPG_ERR_NO_OBJ,
    GPG_ERR_NO_PRIME,
    GPG_ERR_NO_SIGNATURE_SCHEME,
    GPG_ERR_NOT_FOUND,
    GPG_ERR_NOT_IMPLEMENTED,
    GPG_ERR_NOT_SUPPORTED,
    GPG_ERR_PUBKEY_ALGO,
    GPG_ERR_SELFTEST_FAILED,
    GPG_ERR_TOO_SHORT,
    GPG_ERR_UNSUPPORTED,
    GPG_ERR_WEAK_KEY,
    GPG_ERR_WRONG_KEY_USAGE,
    GPG_ERR_WRONG_PUBKEY_ALGO,
    GPG_ERR_OUT_OF_MEMORY,
    GPG_ERR_TOO_LARGE,
    GPG_ERR_ENOMEM,
    GPG_ERR_CHECKSUM,
    GPG_ERR_INV_LENGTH,
    GPG_ERR_VALUE_NOT_FOUND,
    GPG_ERR_ERANGE,
    GPG_ERR_INV_DATA,
    GPG_ERR_ENCODING_PROBLEM,
    GPG_ERR_BUFFER_TOO_SHORT,
    GPG_ERR_SYNTAX,
    GPG_ERR_SEXP_INV_LEN_SPEC,
    GPG_ERR_SEXP_UNMATCHED_DH,
    GPG_ERR_SEXP_UNMATCHED_PAREN,
    GPG_ERR_SEXP_ZERO_PREFIX,
    GPG_ERR_SEXP_NESTED_DH,
    GPG_ERR_SEXP_UNEXPECTED_PUNC,
    GPG_ERR_SEXP_BAD_CHARACTER,
    GPG_ERR_SEXP_NOT_CANONICAL,
    GPG_ERR_SEXP_STRING_TOO_LONG,
    GPG_ERR_SEXP_BAD_QUOTATION,
    GPG_ERR_SEXP_ODD_HEX_NUMBERS,
    GPG_ERR_SEXP_BAD_HEX_CHAR,
    GPG_ERR_LIMIT_REACHED,
    GPG_ERR_EOF,
    GPG_ERR_BAD_DATA,
    GPG_ERR_EINVAL,
    GPG_ERR_INV_STATE,
  } gpg_err_code_t;
typedef gpg_err_code_t gpg_error_t;
typedef gpg_error_t gcry_error_t;
typedef gpg_err_code_t gcry_err_code_t;
#define gcry_error_t gcry_err_code_t
#if 0
enum gcry_cipher_modes
  {
    GCRY_CIPHER_MODE_NONE   = 0,  /* Not yet specified. */
    GCRY_CIPHER_MODE_ECB    = 1,  /* Electronic codebook. */
    GCRY_CIPHER_MODE_CFB    = 2,  /* Cipher feedback. */
    GCRY_CIPHER_MODE_CBC    = 3,  /* Cipher block chaining. */
    GCRY_CIPHER_MODE_STREAM = 4,  /* Used with stream ciphers. */
    GCRY_CIPHER_MODE_OFB    = 5,  /* Outer feedback. */
    GCRY_CIPHER_MODE_CTR    = 6   /* Counter. */
  };
#endif

/* Extra algo IDs not coming from gcrypt.  */
#define GCRY_MD_ADLER32 10301
#define GCRY_MD_CRC64 10302

/* Don't rely on this. Check!  */
#define GRUB_CRYPTO_MAX_MDLEN 64
#define GRUB_CRYPTO_MAX_CIPHER_BLOCKSIZE 16
#define GRUB_CRYPTO_MAX_MD_CONTEXT_SIZE 256

/* Type for the cipher_setkey function.  */
struct cipher_bulk_ops;

typedef gcry_err_code_t (*gcry_cipher_setkey_t) (void *c,
						 const unsigned char *key,
						 unsigned keylen,
						 struct cipher_bulk_ops *bulk_ops);

/* Type for the cipher_encrypt function.  */
typedef unsigned int (*gcry_cipher_encrypt_t) (void *c,
					       unsigned char *outbuf,
					       const unsigned char *inbuf);

/* Type for the cipher_decrypt function.  */
typedef unsigned int (*gcry_cipher_decrypt_t) (void *c,
					       unsigned char *outbuf,
					       const unsigned char *inbuf);

/* Type for the cipher_stencrypt function.  */
typedef void (*gcry_cipher_stencrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 grub_size_t n);

/* Type for the cipher_stdecrypt function.  */
typedef void (*gcry_cipher_stdecrypt_t) (void *c,
					 unsigned char *outbuf,
					 const unsigned char *inbuf,
					 grub_size_t n);

typedef void (*selftest_report_func_t)(const char *domain,
                                       int algo,
                                       const char *what,
                                       const char *errdesc);

/* The type used to convey additional information to a cipher.  */
typedef gpg_err_code_t (*gcry_cipher_set_extra_info_t)
     (void *c, int what, const void *buffer, grub_size_t buflen);

/* The type used to set an IV directly in the algorithm module.  */
typedef void (*gcry_cipher_setiv_func_t)(void *c, const grub_uint8_t *iv, grub_size_t ivlen);

/* Definition of the selftest functions.  */
typedef gpg_err_code_t (*gcry_selftest_func_t)
     (int algo, int extended, selftest_report_func_t report);

typedef struct gcry_cipher_oid_spec
{
  const char *oid;
  int mode;
} gcry_cipher_oid_spec_t;

/* Module specification structure for ciphers.  */
typedef struct gcry_cipher_spec
{
  int algo;
  struct {
    unsigned int disabled:1;
    unsigned int fips:1;
  } flags;
  const char *name;
  const char **aliases;
  const gcry_cipher_oid_spec_t *oids;
  grub_size_t blocksize;
  grub_size_t keylen;
  grub_size_t contextsize;
  gcry_cipher_setkey_t setkey;
  gcry_cipher_encrypt_t encrypt;
  gcry_cipher_decrypt_t decrypt;
  gcry_cipher_stencrypt_t stencrypt;
  gcry_cipher_stdecrypt_t stdecrypt;
  gcry_selftest_func_t selftest;
  gcry_cipher_set_extra_info_t set_extra_info;
  gcry_cipher_setiv_func_t setiv;

#ifdef GRUB_UTIL
  const char *modname;
#endif
  struct gcry_cipher_spec *next;
} gcry_cipher_spec_t;

/* Type for the md_init function.  */
typedef void (*gcry_md_init_t) (void *c, unsigned int flags);

/* Type for the md_write function.  */
typedef void (*gcry_md_write_t) (void *c, const void *buf, grub_size_t nbytes);

/* Type for the md_final function.  */
typedef void (*gcry_md_final_t) (void *c);

/* Type for the md_read function.  */
typedef unsigned char *(*gcry_md_read_t) (void *c);

typedef struct gcry_md_oid_spec
{
  const char *oidstring;
} gcry_md_oid_spec_t;

/* Module specification structure for message digests.  */
typedef struct gcry_md_spec
{
  int algo;
  struct {
    unsigned int disabled:1;
    unsigned int fips:1;
  } flags;
  const char *name;
  const unsigned char *asnoid;
  int asnlen;
  const gcry_md_oid_spec_t *oids;
  grub_size_t mdlen;
  gcry_md_init_t init;
  gcry_md_write_t write;
  gcry_md_final_t final;
  gcry_md_read_t read;
  void *extract;
  void *hash_buffers;
  grub_size_t contextsize; /* allocate this amount of context */

  /* Block size, needed for HMAC.  */
  grub_size_t blocksize;
#ifdef GRUB_UTIL
  const char *modname;
#endif
  struct gcry_md_spec *next;
} gcry_md_spec_t;

typedef struct gcry_md_handle*gcry_md_hd_t;

struct gcry_mpi;
typedef struct gcry_mpi *gcry_mpi_t;

struct gcry_sexp;
typedef struct gcry_sexp *gcry_sexp_t;


#define PUBKEY_FLAG_NO_BLINDING    (1 << 0)
#define PUBKEY_FLAG_RFC6979        (1 << 1)
#define PUBKEY_FLAG_FIXEDLEN       (1 << 2)
#define PUBKEY_FLAG_LEGACYRESULT   (1 << 3)
#define PUBKEY_FLAG_RAW_FLAG       (1 << 4)
#define PUBKEY_FLAG_TRANSIENT_KEY  (1 << 5)
#define PUBKEY_FLAG_USE_X931       (1 << 6)
#define PUBKEY_FLAG_USE_FIPS186    (1 << 7)
#define PUBKEY_FLAG_USE_FIPS186_2  (1 << 8)
#define PUBKEY_FLAG_PARAM          (1 << 9)
#define PUBKEY_FLAG_COMP           (1 << 10)
#define PUBKEY_FLAG_NOCOMP         (1 << 11)
#define PUBKEY_FLAG_EDDSA          (1 << 12)
#define PUBKEY_FLAG_GOST           (1 << 13)
#define PUBKEY_FLAG_NO_KEYTEST     (1 << 14)
#define PUBKEY_FLAG_DJB_TWEAK      (1 << 15)
#define PUBKEY_FLAG_SM2            (1 << 16)
#define PUBKEY_FLAG_PREHASH        (1 << 17)

enum pk_operation
  {
    PUBKEY_OP_ENCRYPT,
    PUBKEY_OP_DECRYPT,
    PUBKEY_OP_SIGN,
    PUBKEY_OP_VERIFY
  };

enum pk_encoding
  {
    PUBKEY_ENC_RAW,
    PUBKEY_ENC_PKCS1,
    PUBKEY_ENC_PKCS1_RAW,
    PUBKEY_ENC_OAEP,
    PUBKEY_ENC_PSS,
    PUBKEY_ENC_UNKNOWN
  };

struct pk_encoding_ctx
{
  enum pk_operation op;
  unsigned int nbits;

  enum pk_encoding encoding;
  int flags;

  int hash_algo;

  /* for OAEP */
  unsigned char *label;
  grub_size_t labellen;

  /* for PSS */
  grub_size_t saltlen;

  int (* verify_cmp) (void *opaque, gcry_mpi_t tmp);
  void *verify_arg;
};

/* Type for the pk_generate function.  */
typedef gcry_err_code_t (*gcry_pk_generate_t) (gcry_sexp_t genparms,
                                               gcry_sexp_t *r_skey);

/* Type for the pk_check_secret_key function.  */
typedef gcry_err_code_t (*gcry_pk_check_secret_key_t) (gcry_sexp_t keyparms);

/* Type for the pk_encrypt function.  */
typedef gcry_err_code_t (*gcry_pk_encrypt_t) (gcry_sexp_t *r_ciph,
                                              gcry_sexp_t s_data,
                                              gcry_sexp_t keyparms);

/* Type for the pk_decrypt function.  */
typedef gcry_err_code_t (*gcry_pk_decrypt_t) (gcry_sexp_t *r_plain,
                                              gcry_sexp_t s_data,
                                              gcry_sexp_t keyparms);

/* Type for the pk_sign function.  */
typedef gcry_err_code_t (*gcry_pk_sign_t) (gcry_sexp_t *r_sig,
                                           gcry_sexp_t s_data,
                                           gcry_sexp_t keyparms);

/* Type for the pk_verify function.  */
typedef gcry_err_code_t (*gcry_pk_verify_t) (gcry_sexp_t s_sig,
                                             gcry_sexp_t s_data,
                                             gcry_sexp_t keyparms);

/* Type for the pk_get_nbits function.  */
typedef unsigned (*gcry_pk_get_nbits_t) (gcry_sexp_t keyparms);

/* The type used to compute the keygrip.  */
typedef gpg_err_code_t (*pk_comp_keygrip_t) (gcry_md_hd_t md,
                                             gcry_sexp_t keyparm);

/* The type used to query an ECC curve name.  */
typedef const char *(*pk_get_curve_t)(gcry_sexp_t keyparms, int iterator,
                                      unsigned int *r_nbits);

/* The type used to query ECC curve parameters by name.  */
typedef gcry_sexp_t (*pk_get_curve_param_t)(const char *name);

/* Module specification structure for message digests.  */
typedef struct gcry_pk_spec
{
  int algo;
  struct {
    unsigned int disabled:1;
    unsigned int fips:1;
  } flags;
  int use;
  const char *name;
  const char **aliases;
  const char *elements_pkey;
  const char *elements_skey;
  const char *elements_enc;
  const char *elements_sig;
  const char *elements_grip;
  gcry_pk_generate_t generate;
  gcry_pk_check_secret_key_t check_secret_key;
  gcry_pk_encrypt_t encrypt;
  gcry_pk_decrypt_t decrypt;
  gcry_pk_sign_t sign;
  gcry_pk_verify_t verify;
  gcry_pk_get_nbits_t get_nbits;
  pk_comp_keygrip_t comp_keygrip;
  pk_get_curve_t get_curve;
  pk_get_curve_param_t get_curve_param;

#ifdef GRUB_UTIL
  const char *modname;
#endif
} gcry_pk_spec_t;

struct grub_crypto_cipher_handle
{
  const struct gcry_cipher_spec *cipher;
  char ctx[0];
};

typedef struct grub_crypto_cipher_handle *grub_crypto_cipher_handle_t;

struct grub_crypto_hmac_handle;

const gcry_cipher_spec_t *
grub_crypto_lookup_cipher_by_name (const char *name);

grub_crypto_cipher_handle_t
grub_crypto_cipher_open (const struct gcry_cipher_spec *cipher);

gcry_err_code_t
grub_crypto_cipher_set_key (grub_crypto_cipher_handle_t cipher,
			    const unsigned char *key,
			    unsigned keylen);

static inline void
grub_crypto_cipher_close (grub_crypto_cipher_handle_t cipher)
{
  grub_free (cipher);
}

static inline void
grub_crypto_xor (void *out, const void *in1, const void *in2, grub_size_t size)
{
  const grub_uint8_t *in1ptr = in1, *in2ptr = in2;
  grub_uint8_t *outptr = out;
  while (size && (((grub_addr_t) in1ptr & (sizeof (grub_uint64_t) - 1))
		  || ((grub_addr_t) in2ptr & (sizeof (grub_uint64_t) - 1))
		  || ((grub_addr_t) outptr & (sizeof (grub_uint64_t) - 1))))
    {
      *outptr = *in1ptr ^ *in2ptr;
      in1ptr++;
      in2ptr++;
      outptr++;
      size--;
    }
  while (size >= sizeof (grub_uint64_t))
    {
      /* We've already checked that all pointers are aligned.  */
      *(grub_uint64_t *) (void *) outptr
	= (*(const grub_uint64_t *) (const void *) in1ptr
	   ^ *(const grub_uint64_t *) (const void *) in2ptr);
      in1ptr += sizeof (grub_uint64_t);
      in2ptr += sizeof (grub_uint64_t);
      outptr += sizeof (grub_uint64_t);
      size -= sizeof (grub_uint64_t);
    }
  while (size)
    {
      *outptr = *in1ptr ^ *in2ptr;
      in1ptr++;
      in2ptr++;
      outptr++;
      size--;
    }
}

gcry_err_code_t
grub_crypto_ecb_decrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size);

gcry_err_code_t
grub_crypto_ecb_encrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size);
gcry_err_code_t
grub_crypto_cbc_encrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size,
			 void *iv_in);
gcry_err_code_t
grub_crypto_cbc_decrypt (grub_crypto_cipher_handle_t cipher,
			 void *out, const void *in, grub_size_t size,
			 void *iv);
void
grub_cipher_register (gcry_cipher_spec_t *cipher);
void
grub_cipher_unregister (gcry_cipher_spec_t *cipher);
void
grub_md_register (gcry_md_spec_t *digest);
void
grub_md_unregister (gcry_md_spec_t *cipher);

extern struct gcry_pk_spec *grub_crypto_pk_dsa;
extern struct gcry_pk_spec *grub_crypto_pk_ecdsa;
extern struct gcry_pk_spec *grub_crypto_pk_ecdh;
extern struct gcry_pk_spec *grub_crypto_pk_rsa;

void
grub_crypto_hash (const gcry_md_spec_t *hash, void *out, const void *in,
		  grub_size_t inlen);
const gcry_md_spec_t *
grub_crypto_lookup_md_by_name (const char *name);
const gcry_md_spec_t *
grub_crypto_lookup_md_by_algo (int algo);
const gcry_md_spec_t *
grub_crypto_lookup_md_by_oid (const char *oid);

grub_err_t
grub_crypto_gcry_error (gcry_err_code_t in);

void grub_burn_stack (grub_size_t size);

struct grub_crypto_hmac_handle *
grub_crypto_hmac_init (const struct gcry_md_spec *md,
		       const void *key, grub_size_t keylen);
void
grub_crypto_hmac_write (struct grub_crypto_hmac_handle *hnd,
			const void *data,
			grub_size_t datalen);
gcry_err_code_t
grub_crypto_hmac_fini (struct grub_crypto_hmac_handle *hnd, void *out);

gcry_err_code_t
grub_crypto_hmac_buffer (const struct gcry_md_spec *md,
			 const void *key, grub_size_t keylen,
			 const void *data, grub_size_t datalen, void *out);

extern gcry_md_spec_t _gcry_digest_spec_md5;
extern gcry_md_spec_t _gcry_digest_spec_sha1;
extern gcry_md_spec_t _gcry_digest_spec_sha256;
extern gcry_md_spec_t _gcry_digest_spec_sha384;
extern gcry_md_spec_t _gcry_digest_spec_sha512;
extern gcry_md_spec_t _gcry_digest_spec_crc32;
extern gcry_cipher_spec_t _gcry_cipher_spec_aes;
#define GRUB_MD_MD5 ((const gcry_md_spec_t *) &_gcry_digest_spec_md5)
#define GRUB_MD_SHA1 ((const gcry_md_spec_t *) &_gcry_digest_spec_sha1)
#define GRUB_MD_SHA256 ((const gcry_md_spec_t *) &_gcry_digest_spec_sha256)
#define GRUB_MD_SHA512 ((const gcry_md_spec_t *) &_gcry_digest_spec_sha512)
#define GRUB_MD_CRC32 ((const gcry_md_spec_t *) &_gcry_digest_spec_crc32)
#define GRUB_CIPHER_AES ((const gcry_cipher_spec_t *) &_gcry_cipher_spec_aes)

/* Implement PKCS#5 PBKDF2 as per RFC 2898.  The PRF to use is HMAC variant
   of digest supplied by MD.  Inputs are the password P of length PLEN,
   the salt S of length SLEN, the iteration counter C (> 0), and the
   desired derived output length DKLEN.  Output buffer is DK which
   must have room for at least DKLEN octets.  The output buffer will
   be filled with the derived data.  */
gcry_err_code_t
grub_crypto_pbkdf2 (const struct gcry_md_spec *md,
		    const grub_uint8_t *P, grub_size_t Plen,
		    const grub_uint8_t *S, grub_size_t Slen,
		    unsigned int c,
		    grub_uint8_t *DK, grub_size_t dkLen);

int
grub_crypto_memcmp (const void *a, const void *b, grub_size_t n);

int
grub_password_get (char buf[], unsigned buf_size);

/* For indistinguishibility.  */
#define GRUB_ACCESS_DENIED grub_error (GRUB_ERR_ACCESS_DENIED, N_("access denied"))

extern void (*grub_crypto_autoload_hook) (const char *name);

void _gcry_assert_failed (const char *expr, const char *file, int line,
                          const char *func) __attribute__ ((noreturn));

void _gcry_burn_stack (int bytes);
void _gcry_log_error( const char *fmt, ... )  __attribute__ ((format (__printf__, 1, 2)));
void _gcry_log_info (const char *fmt, ...);
void __gcry_burn_stack (unsigned int size);
void __gcry_burn_stack_dummy (void);
void _gcry_bug( const char *file, int line, const char *func );
void
_gcry_fast_wipememory (void *ptr, grub_size_t len);
void
_gcry_fast_wipememory2 (void *ptr, int set, grub_size_t len);
unsigned int
_gcry_ct_memequal (const void *b1, const void *b2, grub_size_t len);
unsigned int
_gcry_ct_not_memequal (const void *b1, const void *b2, grub_size_t len);


static inline unsigned int _gcry_get_hw_features(void)
{
  return 0;
}

void *_gcry_malloc(grub_size_t n);
void *_gcry_malloc_secure(grub_size_t n);
void *_gcry_xmalloc(grub_size_t n);
void *_gcry_xmalloc_secure(grub_size_t n);
void _gcry_free (void *p);
void *_gcry_xrealloc (void *a, grub_size_t n);
int _gcry_is_secure (const void *a);
void *_gcry_xcalloc (grub_size_t n, grub_size_t m);
void *_gcry_xcalloc_secure (grub_size_t n, grub_size_t m);
void _gcry_divide_by_zero (void);

#ifdef GRUB_UTIL
void grub_gcry_init_all (void);
void grub_gcry_fini_all (void);

int
grub_get_random (void *out, grub_size_t len);

#define GRUB_UTIL_MODNAME(x) .modname = x,
#else
#define GRUB_UTIL_MODNAME(x)
#endif

#define GRUB_BLAKE2B_BLOCK_SIZE 128
#define GRUB_BLAKE2S_BLOCK_SIZE 64

typedef struct _gpgrt_b64state *gpgrt_b64state_t;
gpgrt_b64state_t gpgrt_b64dec_start (const char *title);
gpg_error_t      gpgrt_b64dec_proc (gpgrt_b64state_t state,
				    void *buffer, grub_size_t length,
                                    grub_size_t *r_nbytes);
gpg_error_t      gpgrt_b64dec_finish (gpgrt_b64state_t state);
const char *gpg_strerror (gpg_error_t err);

gcry_err_code_t blake2b_vl_hash (const void *in, grub_size_t inlen,
                                 grub_size_t outputlen, void *output);
#endif
