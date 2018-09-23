#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/misc.h>
#include <grub/i386/pc/int.h>

#define TCPA_MAGIC 0x41504354
#define TCG_StatusCheck 0xbb00 /* (AH)=bbh, (AL)=00h */
#define TCG_PassThroughToTPM 0xbb02 /* (AH)=bbh, (AL)=02h */
#define TCG_CompactHashLogExtendEvent 0xbb07 /* (AH)=bbh, (AL)=07h */

static int tpm_presence = -1;

int tpm_present(void);

int tpm_present(void)
{
  struct grub_bios_int_registers regs;

  if (tpm_presence != -1)
    return tpm_presence;

  regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
  regs.eax = TCG_PassThroughToTPM;
  regs.ebx = TCPA_MAGIC;
  grub_bios_interrupt (0x1a, &regs);

  if (regs.eax == 0)
    tpm_presence = 1;
  else
    tpm_presence = 0;

  return tpm_presence;
}

grub_err_t
grub_tpm_execute(PassThroughToTPM_InputParamBlock *inbuf,
		 PassThroughToTPM_OutputParamBlock *outbuf)
{
  struct grub_bios_int_registers regs;
  grub_addr_t inaddr, outaddr;

  if (!tpm_present())
    return 0;

  inaddr = (grub_addr_t) inbuf;
  outaddr = (grub_addr_t) outbuf;
  regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
  regs.eax = TCG_PassThroughToTPM;
  regs.ebx = TCPA_MAGIC;
  regs.ecx = 0;
  regs.edx = 0;
  regs.es = (inaddr & 0xffff0000) >> 4;
  regs.edi = inaddr & 0xffff;
  regs.ds = outaddr >> 4;
  regs.esi = outaddr & 0xf;

  grub_bios_interrupt (0x1a, &regs);

  if (regs.eax)
    {
	tpm_presence = 0;
	return grub_error (GRUB_ERR_IO, N_("TPM error %x, disabling TPM"), regs.eax);
    }

  return 0;
}

grub_err_t
grub_tpm_log_event(unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		   const char *description UNUSED)
{
	struct grub_bios_int_registers regs;

	if (!tpm_present())
		return 0;

	regs.flags = GRUB_CPU_INT_FLAGS_DEFAULT;
	regs.eax = TCG_CompactHashLogExtendEvent;
	regs.ebx = TCPA_MAGIC;
	regs.ecx = size;
	regs.edx = pcr;
	regs.es = (((grub_addr_t) buf) & 0xffff0000) >> 4;
	regs.edi = ((grub_addr_t) buf) & 0xffff;
	regs.esi = 0;

	grub_bios_interrupt (0x1a, &regs);

	if (regs.eax)
	  {
		tpm_presence = 0;
		return grub_error (GRUB_ERR_IO, N_("TPM error %x, disabling TPM"), regs.eax);
	  }

	return 0;
}
