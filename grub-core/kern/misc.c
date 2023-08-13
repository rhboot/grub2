/* misc.c - definitions of misc functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <stdarg.h>
#include <grub/term.h>
#include <grub/env.h>
#include <grub/i18n.h>
#include <grub/types.h>
#include <grub/charset.h>

union printf_arg
{
  /* Yes, type is also part of union as the moment we fill the value
     we don't need to store its type anymore (when we'll need it, we'll
     have format spec again. So save some space.  */
  enum
    {
      INT, LONG, LONGLONG,
      UNSIGNED_INT = 3, UNSIGNED_LONG, UNSIGNED_LONGLONG,
      STRING,
      GUID
    } type;
  long long ll;
};

struct printf_args
{
  union printf_arg prealloc[32];
  union printf_arg *ptr;
  grub_size_t count;
};

static void
parse_printf_args (const char *fmt0, struct printf_args *args,
		   va_list args_in);
static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0,
		     struct printf_args *args);

static void
free_printf_args (struct printf_args *args)
{
  if (args->ptr != args->prealloc)
    grub_free (args->ptr);
}

static int
grub_iswordseparator (int c)
{
  return (grub_isspace (c) || c == ',' || c == ';' || c == '|' || c == '&');
}

/* grub_gettext_dummy is not translating anything.  */
static const char *
grub_gettext_dummy (const char *s)
{
  return s;
}

const char* (*grub_gettext) (const char *s) = grub_gettext_dummy;

void *
grub_memmove (void *dest, const void *src, grub_size_t n)
{
  char *d = (char *) dest;
  const char *s = (const char *) src;

  if (d < s)
    while (n--)
      *d++ = *s++;
  else
    {
      d += n;
      s += n;

      while (n--)
	*--d = *--s;
    }

  return dest;
}

char *
grub_strcpy (char *dest, const char *src)
{
  char *p = dest;

  while ((*p++ = *src++) != '\0')
    ;

  return dest;
}

int
grub_printf (const char *fmt, ...)
{
  va_list ap;
  int ret;

#if defined(MM_DEBUG) && !defined(GRUB_UTIL) && !defined (GRUB_MACHINE_EMU)
  /*
   * To prevent infinite recursion when grub_mm_debug is on, disable it
   * when calling grub_vprintf(). One such call loop is:
   *   grub_vprintf() -> parse_printf_args() -> parse_printf_arg_fmt() ->
   *     grub_debug_calloc() -> grub_printf() -> grub_vprintf().
   */
  int grub_mm_debug_save = 0;

  if (grub_mm_debug)
    {
      grub_mm_debug_save = grub_mm_debug;
      grub_mm_debug = 0;
    }
#endif

  va_start (ap, fmt);
  ret = grub_vprintf (fmt, ap);
  va_end (ap);

#if defined(MM_DEBUG) && !defined(GRUB_UTIL) && !defined (GRUB_MACHINE_EMU)
  grub_mm_debug = grub_mm_debug_save;
#endif

  return ret;
}

int
grub_printf_ (const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vprintf (_(fmt), ap);
  va_end (ap);

  return ret;
}

int
grub_puts_ (const char *s)
{
  return grub_puts (_(s));
}

#if defined (__APPLE__) && ! defined (GRUB_UTIL)
int
grub_err_printf (const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start (ap, fmt);
	ret = grub_vprintf (fmt, ap);
	va_end (ap);

	return ret;
}
#endif

#if ! defined (__APPLE__) && ! defined (GRUB_UTIL)
int grub_err_printf (const char *fmt, ...)
__attribute__ ((alias("grub_printf")));
#endif

int
grub_debug_enabled (const char * condition)
{
  const char *debug, *found;
  grub_size_t clen;
  int ret = 0;

  debug = grub_env_get ("debug");
  if (!debug)
    return 0;

  if (grub_strword (debug, "all"))
    {
      if (debug[3] == '\0')
	return 1;
      ret = 1;
    }

  clen = grub_strlen (condition);
  found = debug-1;
  while(1)
    {
      found = grub_strstr (found+1, condition);

      if (found == NULL)
	break;

      /* Found condition is not a whole word, so ignore it. */
      if (*(found + clen) != '\0' && *(found + clen) != ','
	 && !grub_isspace (*(found + clen)))
	continue;

      /*
       * If found condition is at the start of debug or the start is on a word
       * boundary, then enable debug. Else if found condition is prefixed with
       * '-' and the start is on a word boundary, then disable debug. If none
       * of these cases, ignore.
       */
      if (found == debug || *(found - 1) == ',' || grub_isspace (*(found - 1)))
	ret = 1;
      else if (*(found - 1) == '-' && ((found == debug + 1) || (*(found - 2) == ','
			       || grub_isspace (*(found - 2)))))
	ret = 0;
    }

  return ret;
}

void
grub_real_dprintf (const char *file, const int line, const char *condition,
		   const char *fmt, ...)
{
  va_list args;

  if (grub_debug_enabled (condition))
    {
      grub_printf ("%s:%d:%s: ", file, line, condition);
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

#define PREALLOC_SIZE 255

int
grub_vprintf (const char *fmt, va_list ap)
{
  grub_size_t s;
  static char buf[PREALLOC_SIZE + 1];
  char *curbuf = buf;
  struct printf_args args;

  parse_printf_args (fmt, &args, ap);

  s = grub_vsnprintf_real (buf, PREALLOC_SIZE, fmt, &args);
  if (s > PREALLOC_SIZE)
    {
      curbuf = grub_malloc (s + 1);
      if (!curbuf)
	{
	  grub_errno = GRUB_ERR_NONE;
	  buf[PREALLOC_SIZE - 3] = '.';
	  buf[PREALLOC_SIZE - 2] = '.';
	  buf[PREALLOC_SIZE - 1] = '.';
	  buf[PREALLOC_SIZE] = 0;
	  curbuf = buf;
	}
      else
	s = grub_vsnprintf_real (curbuf, s, fmt, &args);
    }

  free_printf_args (&args);

  grub_xputs (curbuf);

  if (curbuf != buf)
    grub_free (curbuf);

  return s;
}

int
grub_memcmp (const void *s1, const void *s2, grub_size_t n)
{
  const grub_uint8_t *t1 = s1;
  const grub_uint8_t *t2 = s2;

  while (n--)
    {
      if (*t1 != *t2)
	return (int) *t1 - (int) *t2;

      t1++;
      t2++;
    }

  return 0;
}

int
grub_strcmp (const char *s1, const char *s2)
{
  while (*s1 && *s2)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) (grub_uint8_t) *s1 - (int) (grub_uint8_t) *s2;
}

int
grub_strncmp (const char *s1, const char *s2, grub_size_t n)
{
  if (n == 0)
    return 0;

  while (*s1 && *s2 && --n)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) (grub_uint8_t) *s1 - (int) (grub_uint8_t)  *s2;
}

char *
grub_strchr (const char *s, int c)
{
  do
    {
      if (*s == c)
	return (char *) s;
    }
  while (*s++);

  return 0;
}

char *
grub_strrchr (const char *s, int c)
{
  char *p = NULL;

  do
    {
      if (*s == c)
	p = (char *) s;
    }
  while (*s++);

  return p;
}

int
grub_strword (const char *haystack, const char *needle)
{
  const char *n_pos = needle;

  while (grub_iswordseparator (*haystack))
    haystack++;

  while (*haystack)
    {
      /* Crawl both the needle and the haystack word we're on.  */
      while(*haystack && !grub_iswordseparator (*haystack)
            && *haystack == *n_pos)
        {
          haystack++;
          n_pos++;
        }

      /* If we reached the end of both words at the same time, the word
      is found. If not, eat everything in the haystack that isn't the
      next word (or the end of string) and "reset" the needle.  */
      if ( (!*haystack || grub_iswordseparator (*haystack))
         && (!*n_pos || grub_iswordseparator (*n_pos)))
        return 1;
      else
        {
          n_pos = needle;
          while (*haystack && !grub_iswordseparator (*haystack))
            haystack++;
          while (grub_iswordseparator (*haystack))
            haystack++;
        }
    }

  return 0;
}

int
grub_isspace (int c)
{
  return (c == '\n' || c == '\r' || c == ' ' || c == '\t');
}

unsigned long
grub_strtoul (const char * restrict str, const char ** const restrict end,
	      int base)
{
  unsigned long long num;

  num = grub_strtoull (str, end, base);
#if GRUB_CPU_SIZEOF_LONG != 8
  if (num > ~0UL)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("overflow is detected"));
      return ~0UL;
    }
#endif

  return (unsigned long) num;
}

unsigned long long
grub_strtoull (const char * restrict str, const char ** const restrict end,
	       int base)
{
  unsigned long long num = 0;
  int found = 0;

  /* Skip white spaces.  */
  /* grub_isspace checks that *str != '\0'.  */
  while (grub_isspace (*str))
    str++;

  /* Guess the base, if not specified. The prefix `0x' means 16, and
     the prefix `0' means 8.  */
  if (str[0] == '0')
    {
      if (str[1] == 'x')
	{
	  if (base == 0 || base == 16)
	    {
	      base = 16;
	      str += 2;
	    }
	}
      else if (base == 0 && str[1] >= '0' && str[1] <= '7')
	base = 8;
    }

  if (base == 0)
    base = 10;

  while (*str)
    {
      unsigned long digit;

      digit = grub_tolower (*str) - '0';
      if (digit >= 'a' - '0')
	digit += '0' - 'a' + 10;
      else if (digit > 9)
	break;

      if (digit >= (unsigned long) base)
	break;

      found = 1;

      /* NUM * BASE + DIGIT > ~0ULL */
      if (num > grub_divmod64 (~0ULL - digit, base, 0))
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE,
		      N_("overflow is detected"));

          if (end)
            *end = (char *) str;

	  return ~0ULL;
	}

      num = num * base + digit;
      str++;
    }

  if (! found)
    {
      grub_error (GRUB_ERR_BAD_NUMBER,
		  N_("unrecognized number"));

      if (end)
        *end = (char *) str;

      return 0;
    }

  if (end)
    *end = (char *) str;

  return num;
}

char *
grub_strdup (const char *s)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s) + 1;
  p = (char *) grub_malloc (len);
  if (! p)
    return 0;

  return grub_memcpy (p, s, len);
}

char *
grub_strndup (const char *s, grub_size_t n)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s);
  if (len > n)
    len = n;
  p = (char *) grub_malloc (len + 1);
  if (! p)
    return 0;

  grub_memcpy (p, s, len);
  p[len] = '\0';
  return p;
}

/* clang detects that we're implementing here a memset so it decides to
   optimise and calls memset resulting in infinite recursion. With volatile
   we make it not optimise in this way.  */
#ifdef __clang__
#define VOLATILE_CLANG volatile
#else
#define VOLATILE_CLANG
#endif

void *
grub_memset (void *s, int c, grub_size_t len)
{
  void *p = s;
  grub_uint8_t pattern8 = c;

  if (len >= 3 * sizeof (unsigned long))
    {
      unsigned long patternl = 0;
      grub_size_t i;

      for (i = 0; i < sizeof (unsigned long); i++)
	patternl |= ((unsigned long) pattern8) << (8 * i);

      while (len > 0 && (((grub_addr_t) p) & (sizeof (unsigned long) - 1)))
	{
	  *(VOLATILE_CLANG grub_uint8_t *) p = pattern8;
	  p = (grub_uint8_t *) p + 1;
	  len--;
	}
      while (len >= sizeof (unsigned long))
	{
	  *(VOLATILE_CLANG unsigned long *) p = patternl;
	  p = (unsigned long *) p + 1;
	  len -= sizeof (unsigned long);
	}
    }

  while (len > 0)
    {
      *(VOLATILE_CLANG grub_uint8_t *) p = pattern8;
      p = (grub_uint8_t *) p + 1;
      len--;
    }

  return s;
}

grub_size_t
grub_strlen (const char *s)
{
  const char *p = s;

  while (*p)
    p++;

  return p - s;
}

static inline void
grub_reverse (char *str)
{
  char *p = str + grub_strlen (str) - 1;

  while (str < p)
    {
      char tmp;

      tmp = *str;
      *str = *p;
      *p = tmp;
      str++;
      p--;
    }
}

/* Divide N by D, return the quotient, and store the remainder in *R.  */
grub_uint64_t
grub_divmod64 (grub_uint64_t n, grub_uint64_t d, grub_uint64_t *r)
{
  /* This algorithm is typically implemented by hardware. The idea
     is to get the highest bit in N, 64 times, by keeping
     upper(N * 2^i) = (Q * D + M), where upper
     represents the high 64 bits in 128-bits space.  */
  unsigned bits = 64;
  grub_uint64_t q = 0;
  grub_uint64_t m = 0;

  /* ARM and IA64 don't have a fast 32-bit division.
     Using that code would just make us use software division routines, calling
     ourselves indirectly and hence getting infinite recursion.
  */
#if !GRUB_DIVISION_IN_SOFTWARE
  /* Skip the slow computation if 32-bit arithmetic is possible.  */
  if (n < 0xffffffff && d < 0xffffffff)
    {
      if (r)
	*r = ((grub_uint32_t) n) % (grub_uint32_t) d;

      return ((grub_uint32_t) n) / (grub_uint32_t) d;
    }
#endif

  while (bits--)
    {
      m <<= 1;

      if (n & (1ULL << 63))
	m |= 1;

      q <<= 1;
      n <<= 1;

      if (m >= d)
	{
	  q |= 1;
	  m -= d;
	}
    }

  if (r)
    *r = m;

  return q;
}

/* Convert a long long value to a string. This function avoids 64-bit
   modular arithmetic or divisions.  */
static inline char *
grub_lltoa (char *str, int c, unsigned long long n)
{
  unsigned base = ((c == 'x') || (c == 'X')) ? 16 : ((c == 'o') ? 8 : 10);
  char *p;

  if ((long long) n < 0 && c == 'd')
    {
      n = (unsigned long long) (-((long long) n));
      *str++ = '-';
    }

  p = str;

  if (base == 16)
    do
      {
	unsigned d = (unsigned) (n & 0xf);
	*p++ = (d > 9) ? (d + ((c == 'x') ? 'a' : 'A') - 10) : d + '0';
      }
    while (n >>= 4);
  else if (base == 8)
    do
      {
	*p++ = ((unsigned) (n & 0x7)) + '0';
      }
    while (n >>= 3);
  else
    /* BASE == 10 */
    do
      {
	grub_uint64_t m;

	n = grub_divmod64 (n, 10, &m);
	*p++ = m + '0';
      }
    while (n);

  *p = 0;

  grub_reverse (str);
  return p;
}

/*
 * Parse printf() fmt0 string into args arguments.
 *
 * The parsed arguments are either used by a printf() function to format the fmt0
 * string or they are used to compare a format string from an untrusted source
 * against a format string with expected arguments.
 *
 * When the fmt_check is set to !0, e.g. 1, then this function is executed in
 * printf() format check mode. This enforces stricter rules for parsing the
 * fmt0 to limit exposure to possible errors in printf() handling. It also
 * disables positional parameters, "$", because some formats, e.g "%s%1$d",
 * cannot be validated with the current implementation.
 *
 * The max_args allows to set a maximum number of accepted arguments. If the fmt0
 * string defines more arguments than the max_args then the parse_printf_arg_fmt()
 * function returns an error. This is currently used for format check only.
 */
static grub_err_t
parse_printf_arg_fmt (const char *fmt0, struct printf_args *args,
		      int fmt_check, grub_size_t max_args)
{
  const char *fmt;
  char c;
  grub_size_t n = 0;

  args->count = 0;

  COMPILE_TIME_ASSERT (sizeof (int) == sizeof (grub_uint32_t));
  COMPILE_TIME_ASSERT (sizeof (int) <= sizeof (long long));
  COMPILE_TIME_ASSERT (sizeof (long) <= sizeof (long long));
  COMPILE_TIME_ASSERT (sizeof (long long) == sizeof (void *)
		       || sizeof (int) == sizeof (void *));

  fmt = fmt0;
  while ((c = *fmt++) != 0)
    {
      if (c != '%')
	continue;

      if (*fmt =='-')
	fmt++;

      while (grub_isdigit (*fmt))
	fmt++;

      if (*fmt == '$')
	{
	  if (fmt_check)
	    return grub_error (GRUB_ERR_BAD_ARGUMENT,
			       "positional arguments are not supported");
	  fmt++;
	}

      if (*fmt =='-')
	fmt++;

      while (grub_isdigit (*fmt))
	fmt++;

      if (*fmt =='.')
	fmt++;

      while (grub_isdigit (*fmt))
	fmt++;

      c = *fmt++;
      if (c == 'l')
	c = *fmt++;
      if (c == 'l')
	c = *fmt++;

      switch (c)
	{
	case 'p':
	  if (*(fmt) == 'G')
	    ++fmt;
	  /* Fall through. */
	case 'x':
	case 'X':
	case 'u':
	case 'd':
	case 'o':
	case 'c':
	case 'C':
	case 's':
	  args->count++;
	  break;
	case '%':
	  /* "%%" is the escape sequence to output "%". */
	  break;
	default:
	  if (fmt_check)
	    return grub_error (GRUB_ERR_BAD_ARGUMENT, "unexpected format");
	  break;
	}
    }

  if (fmt_check && args->count > max_args)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "too many arguments");

  if (args->count <= ARRAY_SIZE (args->prealloc))
    args->ptr = args->prealloc;
  else
    {
      args->ptr = grub_calloc (args->count, sizeof (args->ptr[0]));
      if (!args->ptr)
	{
	  if (fmt_check)
	    return grub_errno;

	  grub_errno = GRUB_ERR_NONE;
	  args->ptr = args->prealloc;
	  args->count = ARRAY_SIZE (args->prealloc);
	}
    }

  grub_memset (args->ptr, 0, args->count * sizeof (args->ptr[0]));

  fmt = fmt0;
  n = 0;
  while ((c = *fmt++) != 0)
    {
      int longfmt = 0;
      grub_size_t curn;
      const char *p;

      if (c != '%')
	continue;

      curn = n++;

      if (*fmt =='-')
	fmt++;

      p = fmt;

      while (grub_isdigit (*fmt))
	fmt++;

      if (*fmt == '$')
	{
	  curn = grub_strtoull (p, 0, 10) - 1;
	  fmt++;
	}

      if (*fmt =='-')
	fmt++;

      while (grub_isdigit (*fmt))
	fmt++;

      if (*fmt =='.')
	fmt++;

      while (grub_isdigit (*fmt))
	fmt++;

      c = *fmt++;
      if (c == '%')
	{
	  n--;
	  continue;
	}

      if (c == 'l')
	{
	  c = *fmt++;
	  longfmt = 1;
	}
      if (c == 'l')
	{
	  c = *fmt++;
	  longfmt = 2;
	}
      if (curn >= args->count)
	continue;
      switch (c)
	{
	case 'x':
	case 'X':
	case 'o':
	case 'u':
	  args->ptr[curn].type = UNSIGNED_INT + longfmt;
	  break;
	case 'd':
	  args->ptr[curn].type = INT + longfmt;
	  break;
	case 'p':
	  if (sizeof (void *) == sizeof (long long))
	    args->ptr[curn].type = UNSIGNED_LONGLONG;
	  else
	    args->ptr[curn].type = UNSIGNED_INT;
	  if (*(fmt) == 'G') {
	    args->ptr[curn].type = GUID;
	    ++fmt;
	  }
	  break;
	case 's':
	  args->ptr[curn].type = STRING;
	  break;
	case 'C':
	case 'c':
	  args->ptr[curn].type = INT;
	  break;
	}
    }

  return GRUB_ERR_NONE;
}

static void
parse_printf_args (const char *fmt0, struct printf_args *args, va_list args_in)
{
  grub_size_t n;

  parse_printf_arg_fmt (fmt0, args, 0, 0);

  for (n = 0; n < args->count; n++)
    switch (args->ptr[n].type)
      {
      case INT:
	args->ptr[n].ll = va_arg (args_in, int);
	break;
      case LONG:
	args->ptr[n].ll = va_arg (args_in, long);
	break;
      case UNSIGNED_INT:
	args->ptr[n].ll = va_arg (args_in, unsigned int);
	break;
      case UNSIGNED_LONG:
	args->ptr[n].ll = va_arg (args_in, unsigned long);
	break;
      case LONGLONG:
      case UNSIGNED_LONGLONG:
	args->ptr[n].ll = va_arg (args_in, long long);
	break;
      case STRING:
      case GUID:
	if (sizeof (void *) == sizeof (long long))
	  args->ptr[n].ll = va_arg (args_in, long long);
	else
	  args->ptr[n].ll = va_arg (args_in, unsigned int);
	break;
      }
}

static inline void __attribute__ ((always_inline))
write_char (char *str, grub_size_t *count, grub_size_t max_len, unsigned char ch)
{
  if (*count < max_len)
    str[*count] = ch;

  (*count)++;
}

static void
write_number (char *str, grub_size_t *count, grub_size_t max_len, grub_size_t format1,
	     char rightfill, char zerofill, char c, long long value)
{
  char tmp[32];
  const char *p = tmp;
  grub_size_t len;
  grub_size_t fill;

  len = grub_lltoa (tmp, c, value) - tmp;
  fill = len < format1 ? format1 - len : 0;
  if (! rightfill)
    while (fill--)
      write_char (str, count, max_len, zerofill);
  while (*p)
    write_char (str, count, max_len, *p++);
  if (rightfill)
    while (fill--)
      write_char (str, count, max_len, zerofill);
}

static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0,
		     struct printf_args *args)
{
  char c;
  grub_size_t n = 0;
  grub_size_t count = 0;
  const char *fmt;

  fmt = fmt0;

  while ((c = *fmt++) != 0)
    {
      unsigned int format1 = 0;
      unsigned int format2 = ~ 0U;
      char zerofill = ' ';
      char rightfill = 0;
      grub_size_t curn;

      if (c != '%')
	{
	  write_char (str, &count, max_len, c);
	  continue;
	}

      curn = n++;

    rescan:;

      if (*fmt =='-')
	{
	  rightfill = 1;
	  fmt++;
	}

      /* Read formatting parameters.  */
      if (grub_isdigit (*fmt))
	{
	  if (fmt[0] == '0')
	    zerofill = '0';
	  format1 = grub_strtoul (fmt, &fmt, 10);
	}

      if (*fmt == '.')
	fmt++;

      if (grub_isdigit (*fmt))
	format2 = grub_strtoul (fmt, &fmt, 10);

      if (*fmt == '$')
	{
	  curn = format1 - 1;
	  fmt++;
	  format1 = 0;
	  format2 = ~ 0U;
	  zerofill = ' ';
	  rightfill = 0;

	  goto rescan;
	}

      c = *fmt++;
      if (c == 'l')
	c = *fmt++;
      if (c == 'l')
	c = *fmt++;

      if (c == '%')
	{
	  write_char (str, &count, max_len, c);
	  n--;
	  continue;
	}

      if (curn >= args->count)
	continue;

      long long curarg = args->ptr[curn].ll;

      switch (c)
	{
	case 'p':
	  if (*(fmt) == 'G')
	    {
	      ++fmt;
	      grub_packed_guid_t *guid = (grub_packed_guid_t *)(grub_addr_t) curarg;
	      write_number (str, &count, max_len, 8, 0, '0', 'x', guid->data1);
	      write_char (str, &count, max_len, '-');
	      write_number (str, &count, max_len, 4, 0, '0', 'x', guid->data2);
	      write_char (str, &count, max_len, '-');
	      write_number (str, &count, max_len, 4, 0, '0', 'x', guid->data3);
	      write_char (str, &count, max_len, '-');
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[0]);
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[1]);
	      write_char (str, &count, max_len, '-');
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[2]);
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[3]);
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[4]);
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[5]);
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[6]);
	      write_number (str, &count, max_len, 2, 0, '0', 'x', guid->data4[7]);
	      break;
	    }
	  else
	    {
	      write_char (str, &count, max_len, '0');
	      write_char (str, &count, max_len, 'x');
	      c = 'x';
	    }
	  /* Fall through. */
	case 'x':
	case 'X':
	case 'u':
	case 'd':
	case 'o':
	  write_number (str, &count, max_len, format1, rightfill, zerofill, c, curarg);
	  break;

	case 'c':
	  write_char (str, &count, max_len, curarg & 0xff);
	  break;

	case 'C':
	  {
	    grub_uint32_t code = curarg;
	    int shift;
	    unsigned mask;

	    if (code <= 0x7f)
	      {
		shift = 0;
		mask = 0;
	      }
	    else if (code <= 0x7ff)
	      {
		shift = 6;
		mask = 0xc0;
	      }
	    else if (code <= 0xffff)
	      {
		shift = 12;
		mask = 0xe0;
	      }
	    else if (code <= 0x10ffff)
	      {
		shift = 18;
		mask = 0xf0;
	      }
	    else
	      {
		code = '?';
		shift = 0;
		mask = 0;
	      }

	    write_char (str, &count, max_len, mask | (code >> shift));

	    for (shift -= 6; shift >= 0; shift -= 6)
	      write_char (str, &count, max_len, 0x80 | (0x3f & (code >> shift)));
	  }
	  break;

	case 's':
	  {
	    grub_size_t len = 0;
	    grub_size_t fill;
	    const char *p = ((char *) (grub_addr_t) curarg) ? : "(null)";
	    grub_size_t i;

	    while (len < format2 && p[len])
	      len++;

	    fill = len < format1 ? format1 - len : 0;

	    if (!rightfill)
	      while (fill--)
		write_char (str, &count, max_len, zerofill);

	    for (i = 0; i < len; i++)
	      write_char (str, &count, max_len, *p++);

	    if (rightfill)
	      while (fill--)
		write_char (str, &count, max_len, zerofill);
	  }

	  break;

	default:
	  write_char (str, &count, max_len, c);
	  break;
	}
    }

  if (count < max_len)
    str[count] = '\0';
  else
    str[max_len] = '\0';
  return count;
}

int
grub_vsnprintf (char *str, grub_size_t n, const char *fmt, va_list ap)
{
  grub_size_t ret;
  struct printf_args args;

  if (!n)
    return 0;

  n--;

  parse_printf_args (fmt, &args, ap);

  ret = grub_vsnprintf_real (str, n, fmt, &args);

  free_printf_args (&args);

  return ret;
}

int
grub_snprintf (char *str, grub_size_t n, const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vsnprintf (str, n, fmt, ap);
  va_end (ap);

  return ret;
}

char *
grub_xvasprintf (const char *fmt, va_list ap)
{
  grub_size_t s, as = PREALLOC_SIZE;
  char *ret;
  struct printf_args args;

  parse_printf_args (fmt, &args, ap);

  while (1)
    {
      ret = grub_malloc (as + 1);
      if (!ret)
	{
	  free_printf_args (&args);
	  return NULL;
	}

      s = grub_vsnprintf_real (ret, as, fmt, &args);

      if (s <= as)
	{
	  free_printf_args (&args);
	  return ret;
	}

      grub_free (ret);
      as = s;
    }
}

char *
grub_xasprintf (const char *fmt, ...)
{
  va_list ap;
  char *ret;

  va_start (ap, fmt);
  ret = grub_xvasprintf (fmt, ap);
  va_end (ap);

  return ret;
}

grub_err_t
grub_printf_fmt_check (const char *fmt, const char *fmt_expected)
{
  struct printf_args args_expected, args_fmt;
  grub_err_t ret;
  grub_size_t n;

  if (fmt == NULL || fmt_expected == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid format");

  ret = parse_printf_arg_fmt (fmt_expected, &args_expected, 1, GRUB_SIZE_MAX);
  if (ret != GRUB_ERR_NONE)
    return ret;

  /* Limit parsing to the number of expected arguments. */
  ret = parse_printf_arg_fmt (fmt, &args_fmt, 1, args_expected.count);
  if (ret != GRUB_ERR_NONE)
    {
      free_printf_args (&args_expected);
      return ret;
    }

  for (n = 0; n < args_fmt.count; n++)
    if (args_fmt.ptr[n].type != args_expected.ptr[n].type)
     {
	ret = grub_error (GRUB_ERR_BAD_ARGUMENT, "arguments types do not match");
	break;
     }

  free_printf_args (&args_expected);
  free_printf_args (&args_fmt);

  return ret;
}


/* Abort GRUB. This function does not return.  */
void __attribute__ ((noreturn))
grub_abort (void)
{
  grub_printf ("\nAborted.");

#ifndef GRUB_UTIL
  if (grub_term_inputs)
#endif
    {
      grub_printf (" Press any key to exit.");
      grub_getkey ();
    }

  grub_exit ();
}

void
grub_fatal (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  grub_vprintf (_(fmt), ap);
  va_end (ap);

  grub_refresh ();

  grub_abort ();
}

grub_ssize_t
grub_utf8_to_utf16_alloc (const char *str8, grub_uint16_t **utf16_msg, grub_uint16_t **last_position)
{
  grub_size_t len;
  grub_size_t len16;

  len = grub_strlen (str8);

  /* Check for integer overflow */
  if (len > GRUB_SSIZE_MAX / GRUB_MAX_UTF16_PER_UTF8 - 1)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("string too long"));
      *utf16_msg = NULL;
      return -1;
    }

  len16 = len * GRUB_MAX_UTF16_PER_UTF8;

  *utf16_msg = grub_calloc (len16 + 1, sizeof (*utf16_msg[0]));
  if (*utf16_msg == NULL)
    return -1;

  len16 = grub_utf8_to_utf16 (*utf16_msg, len16, (grub_uint8_t *) str8, len, NULL);

  if (last_position != NULL)
    *last_position = *utf16_msg + len16;

  return len16;
}


#if BOOT_TIME_STATS

#include <grub/time.h>

struct grub_boot_time *grub_boot_time_head;
static struct grub_boot_time **boot_time_last = &grub_boot_time_head;

void
grub_real_boot_time (const char *file,
		     const int line,
		     const char *fmt, ...)
{
  struct grub_boot_time *n;
  va_list args;

  grub_error_push ();
  n = grub_malloc (sizeof (*n));
  if (!n)
    {
      grub_errno = 0;
      grub_error_pop ();
      return;
    }
  n->file = file;
  n->line = line;
  n->tp = grub_get_time_ms ();
  n->next = 0;

  va_start (args, fmt);
  n->msg = grub_xvasprintf (fmt, args);
  va_end (args);

  *boot_time_last = n;
  boot_time_last = &n->next;

  grub_errno = 0;
  grub_error_pop ();
}
#endif
