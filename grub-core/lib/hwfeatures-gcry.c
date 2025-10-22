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

#include <grub/dl.h>

#include <grub/hwfeatures-gcry.h>

GRUB_MOD_LICENSE ("GPLv3+");

static bool __gcry_use_hwf = false;

bool
grub_gcry_hwf_enabled (void)
{
  return __gcry_use_hwf;
}

void
grub_enable_gcry_hwf (void)
{
  __gcry_use_hwf = true;
}

void
grub_reset_gcry_hwf (void)
{
  __gcry_use_hwf = false;
}
