/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2015  Free Software Foundation, Inc.
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

#ifndef GRUB_TDX_HEADER
#define GRUB_TDX_HEADER 1

#if defined (GRUB_MACHINE_EFI)
grub_err_t grub_tdx_log_event(unsigned char *buf, grub_size_t size,
			      grub_uint8_t pcr, const char *description);
#else
static inline grub_err_t grub_tdx_log_event(
	unsigned char *buf __attribute__ ((unused)),
	grub_size_t size __attribute__ ((unused)),
	grub_uint8_t pcr __attribute__ ((unused)),
	const char *description __attribute__ ((unused)))
{
	return 0;
};
#endif

#endif
