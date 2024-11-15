/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024  Free Software Foundation, Inc.
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

#ifndef GRUB_POSIX_C_CTYPE_H
#define GRUB_POSIX_C_CTYPE_H	1

#include <grub/misc.h>

static inline bool
c_isspace (int c)
{
  return !!grub_isspace (c);
}

static inline bool
c_isdigit (int c)
{
  return !!grub_isdigit (c);
}

static inline bool
c_islower (int c)
{
  return !!grub_islower (c);
}

static inline bool
c_isascii (int c)
{
  return !(c & ~0x7f);
}

static inline bool
c_isupper (int c)
{
  return !!grub_isupper (c);
}

static inline bool
c_isxdigit (int c)
{
  return !!grub_isxdigit (c);
}

static inline bool
c_isprint (int c)
{
  return !!grub_isprint (c);
}

static inline bool
c_iscntrl (int c)
{
  return !grub_isprint (c);
}

static inline bool
c_isgraph (int c)
{
  return grub_isprint (c) && !grub_isspace (c);
}

static inline bool
c_isalnum (int c)
{
  return grub_isalpha (c) || grub_isdigit (c);
}

static inline bool
c_ispunct (int c)
{
  return grub_isprint (c) && !grub_isspace (c) && !c_isalnum (c);
}

static inline bool
c_isalpha (int c)
{
  return !!grub_isalpha (c);
}

static inline bool
c_isblank (int c)
{
  return c == ' ' || c == '\t';
}

static inline int
c_tolower (int c)
{
  return grub_tolower (c);
}

static inline int
c_toupper (int c)
{
  return grub_toupper (c);
}

#endif
