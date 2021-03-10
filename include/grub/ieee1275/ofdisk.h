/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2007  Free Software Foundation, Inc.
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

#ifndef GRUB_OFDISK_HEADER
#define GRUB_OFDISK_HEADER	1

extern void grub_ofdisk_init (void);
extern void grub_ofdisk_fini (void);

#define MAX_RETRIES 20


#define RETRY_IEEE1275_OFDISK_OPEN(device, last_ihandle) unsigned retry_i=0;for(retry_i=0; retry_i < MAX_RETRIES; retry_i++){ \
						if(!grub_ieee1275_open(device, last_ihandle)) \
						break; \
						grub_dprintf("ofdisk","Opening disk %s failed. Retrying...\n",device); }

#endif /* ! GRUB_INIT_HEADER */
