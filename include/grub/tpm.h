/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2018  Free Software Foundation, Inc.
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

#ifndef GRUB_TPM_HEADER
#define GRUB_TPM_HEADER 1

#define GRUB_STRING_PCR 8
#define GRUB_BINARY_PCR 9

#define SHA1_DIGEST_SIZE 20

#define TPM_BASE     0x0
#define TPM_SUCCESS  TPM_BASE
#define TPM_AUTHFAIL (TPM_BASE + 0x1)
#define TPM_BADINDEX (TPM_BASE + 0x2)

#define TPM_TAG_RQU_COMMAND 0x00C1
#define TPM_ORD_Extend 0x14

#define EV_IPL 0x0d

grub_err_t grub_tpm_measure (unsigned char *buf, grub_size_t size,
			     grub_uint8_t pcr, const char *description);
int grub_tpm_present (void);
#endif
