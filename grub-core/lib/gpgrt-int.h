#include <grub/crypto.h>

struct _gpgrt_b64state
{
  int idx;
  int quad_count;
  char *title;
  unsigned char radbuf[4];
  unsigned int crc;
  gpg_err_code_t lasterr;
  unsigned int flags;
  unsigned int stop_seen:1;
  unsigned int invalid_encoding:1;
  unsigned int using_decoder:1;
};

#define _gpgrt_b64dec_start gpgrt_b64dec_start
#define xtrystrdup grub_strdup
#define xtrycalloc grub_calloc
#define xfree grub_free
#define _gpgrt_b64dec_finish gpgrt_b64dec_finish
#define gpgrt_assert(expr) ((expr)? (void)0 \
         : _gcry_assert_failed (#expr, __FILE__, __LINE__, __FUNCTION__))
#define _gpgrt_b64dec_proc gpgrt_b64dec_proc
