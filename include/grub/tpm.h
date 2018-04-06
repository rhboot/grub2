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

#ifndef GRUB_TPM_HEADER
#define GRUB_TPM_HEADER 1

#define SHA1_DIGEST_SIZE 20

#define TPM_BASE 0x0
#define TPM_SUCCESS TPM_BASE
#define TPM_AUTHFAIL (TPM_BASE + 0x1)
#define TPM_BADINDEX (TPM_BASE + 0x2)

#define GRUB_ASCII_PCR 8
#define GRUB_BINARY_PCR 9

#define TPM_TAG_RQU_COMMAND 0x00C1
#define TPM_ORD_Extend 0x14

#define EV_IPL 0x0d

/* TCG_PassThroughToTPM Input Parameter Block */
typedef struct {
        grub_uint16_t IPBLength;
        grub_uint16_t Reserved1;
        grub_uint16_t OPBLength;
        grub_uint16_t Reserved2;
        grub_uint8_t TPMOperandIn[1];
} GRUB_PACKED PassThroughToTPM_InputParamBlock;

/* TCG_PassThroughToTPM Output Parameter Block */
typedef struct {
        grub_uint16_t OPBLength;
        grub_uint16_t Reserved;
        grub_uint8_t TPMOperandOut[1];
} GRUB_PACKED PassThroughToTPM_OutputParamBlock;

typedef struct {
        grub_uint16_t tag;
        grub_uint32_t paramSize;
        grub_uint32_t ordinal;
        grub_uint32_t pcrNum;
        grub_uint8_t inDigest[SHA1_DIGEST_SIZE];                /* The 160 bit value representing the event to be recorded. */
} GRUB_PACKED ExtendIncoming;

/* TPM_Extend Outgoing Operand */
typedef struct {
        grub_uint16_t tag;
        grub_uint32_t paramSize;
        grub_uint32_t returnCode;
        grub_uint8_t outDigest[SHA1_DIGEST_SIZE];               /* The PCR value after execution of the command. */
} GRUB_PACKED ExtendOutgoing;

grub_err_t EXPORT_FUNC(grub_tpm_measure) (unsigned char *buf, grub_size_t size,
					  grub_uint8_t pcr, const char *kind,
					  const char *description);
#if defined (GRUB_MACHINE_EFI) || defined (GRUB_MACHINE_PCBIOS)
grub_err_t grub_tpm_execute(PassThroughToTPM_InputParamBlock *inbuf,
			    PassThroughToTPM_OutputParamBlock *outbuf);
grub_err_t grub_tpm_log_event(unsigned char *buf, grub_size_t size,
			      grub_uint8_t pcr, const char *description);
#else
static inline grub_err_t grub_tpm_execute(
	PassThroughToTPM_InputParamBlock *inbuf __attribute__ ((unused)),
	PassThroughToTPM_OutputParamBlock *outbuf __attribute__ ((unused)))
{
	return 0;
};
static inline grub_err_t grub_tpm_log_event(
	unsigned char *buf __attribute__ ((unused)),
	grub_size_t size __attribute__ ((unused)),
	grub_uint8_t pcr __attribute__ ((unused)),
	const char *description __attribute__ ((unused)))
{
	return 0;
};
#endif

#endif
