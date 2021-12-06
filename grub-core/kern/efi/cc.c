#include <grub/efi/api.h>
#include <grub/efi/cc.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/cc.h>

static grub_efi_guid_t cc_measurement_guid = EFI_CC_MEASUREMENT_PROTOCOL_GUID;

static inline grub_err_t
grub_cc_dprintf (grub_efi_status_t status)
{
  switch (status)
    {
    case GRUB_EFI_SUCCESS:
      return 0;
    case GRUB_EFI_DEVICE_ERROR:
      grub_dprintf ("cc", "Command failed: 0x%" PRIxGRUB_EFI_STATUS "\n",
                    status);
      return GRUB_ERR_IO;
    case GRUB_EFI_INVALID_PARAMETER:
      grub_dprintf ("cc", "Invalid parameter: 0x%" PRIxGRUB_EFI_STATUS "\n",
                    status);
      return GRUB_ERR_BAD_ARGUMENT;
    case GRUB_EFI_VOLUME_FULL:
      grub_dprintf ("cc", "Volume is full: 0x%" PRIxGRUB_EFI_STATUS "\n",
                    status);
      return GRUB_ERR_BAD_ARGUMENT;
    case GRUB_EFI_UNSUPPORTED:
      grub_dprintf ("cc", "CC unavailable: 0x%" PRIxGRUB_EFI_STATUS "\n",
                    status);
      return GRUB_ERR_UNKNOWN_DEVICE;
    default:
      grub_dprintf ("cc",
                    "Unknown MEASUREMENT error: 0x%" PRIxGRUB_EFI_STATUS "\n",
                    status);
      return GRUB_ERR_UNKNOWN_DEVICE;
    }
}

grub_err_t
grub_cc_log_event (unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
                   const char *description)
{
  EFI_CC_EVENT *event;
  grub_efi_status_t status;
  grub_efi_cc_protocol_t *cc;
  EFI_CC_MR_INDEX mr;

  cc = grub_efi_locate_protocol (&cc_measurement_guid, NULL);

  if (!cc)
    return 0;

  status = efi_call_3 (cc->map_pcr_to_mr_index, cc, pcr, &mr);
  if (status != GRUB_EFI_SUCCESS)
    return grub_cc_dprintf (status);

  event = grub_zalloc (sizeof (EFI_CC_EVENT) + grub_strlen (description) + 1);
  if (!event)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       N_ ("cannot allocate CC event buffer"));

  event->Header.HeaderSize = sizeof (EFI_CC_EVENT_HEADER);
  event->Header.HeaderVersion = EFI_CC_EVENT_HEADER_VERSION;
  event->Header.MrIndex = mr;
  event->Header.EventType = EV_IPL;
  event->Size = sizeof (*event) - sizeof (event->Event)
                + grub_strlen (description) + 1;
  grub_memcpy (event->Event, description, grub_strlen (description) + 1);

  status = efi_call_5 (cc->hash_log_extend_event, cc, 0, (unsigned long)buf,
                       (grub_uint64_t)size, event);

  return grub_cc_dprintf (status);
}
