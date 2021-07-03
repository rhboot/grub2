#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/tpm.h>
#include <grub/efi/tdx.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/tdx.h>

static grub_efi_guid_t tdx_guid = EFI_TDX_GUID;

static inline grub_err_t grub_tdx_dprintf(grub_efi_status_t status)
{
  switch (status) {
  case GRUB_EFI_SUCCESS:
    return 0;
  case GRUB_EFI_DEVICE_ERROR:
    grub_dprintf ("tdx", "Command failed: 0x%"PRIxGRUB_EFI_STATUS"\n",
                  status);
    return GRUB_ERR_IO;
  case GRUB_EFI_INVALID_PARAMETER:
    grub_dprintf ("tdx", "Invalid parameter: 0x%"PRIxGRUB_EFI_STATUS"\n",
                  status);
    return GRUB_ERR_BAD_ARGUMENT;
  case GRUB_EFI_VOLUME_FULL:
    grub_dprintf ("tdx", "Volume is full: 0x%"PRIxGRUB_EFI_STATUS"\n",
                  status);
    return GRUB_ERR_BAD_ARGUMENT;
  case GRUB_EFI_UNSUPPORTED:
    grub_dprintf ("tdx", "TDX unavailable: 0x%"PRIxGRUB_EFI_STATUS"\n",
                  status);
    return GRUB_ERR_UNKNOWN_DEVICE;
  default:
    grub_dprintf ("tdx", "Unknown TDX error: 0x%"PRIxGRUB_EFI_STATUS"\n",
                  status);
    return GRUB_ERR_UNKNOWN_DEVICE;
  }
}

grub_err_t
grub_tdx_log_event(unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		   const char *description)
{
  EFI_TCG2_EVENT *event;
  grub_efi_status_t status;
  grub_efi_tdx_protocol_t *tdx;

  tdx = grub_efi_locate_protocol (&tdx_guid, NULL);

  if (!tdx)
    return 0;

  event = grub_zalloc(sizeof (EFI_TCG2_EVENT) + grub_strlen(description) + 1);
  if (!event)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("cannot allocate TCG2 event buffer"));

  event->Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER);
  event->Header.HeaderVersion = 1;
  event->Header.PCRIndex = pcr;
  event->Header.EventType = EV_IPL;
  event->Size = sizeof(*event) - sizeof(event->Event) + grub_strlen(description) + 1;
  grub_memcpy(event->Event, description, grub_strlen(description) + 1);

  status = efi_call_5 (tdx->hash_log_extend_event, tdx, 0, (unsigned long) buf,
		       (grub_uint64_t) size, event);

  return grub_tdx_dprintf(status);
}