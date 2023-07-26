/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022  Free Software Foundation, Inc.
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

#if !defined(GRUB_MACHINE_IEEE1275) && !defined(GRUB_MACHINE_QEMU)

#include <grub/misc.h>
#include <grub/serial.h>
#include <grub/ns8250.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/acpi.h>

struct grub_serial_port *
grub_ns8250_spcr_init (void)
{
  struct grub_acpi_spcr *spcr;
  struct grub_serial_config config;

  spcr = grub_acpi_find_table (GRUB_ACPI_SPCR_SIGNATURE);
  if (spcr == NULL)
    return NULL;
  if (spcr->hdr.revision < 2)
    grub_dprintf ("serial", "SPCR table revision %d < 2, continuing anyway\n",
		  (int) spcr->hdr.revision);
  if (spcr->intf_type != GRUB_ACPI_SPCR_INTF_TYPE_16550 &&
      spcr->intf_type != GRUB_ACPI_SPCR_INTF_TYPE_16550X)
    return NULL;
  /* For now, we only support byte accesses. */
  if (spcr->base_addr.access_size != GRUB_ACPI_GENADDR_SIZE_BYTE &&
      spcr->base_addr.access_size != GRUB_ACPI_GENADDR_SIZE_LGCY)
    return NULL;
  config.word_len = 8;
  config.parity = GRUB_SERIAL_PARITY_NONE;
  config.stop_bits = GRUB_SERIAL_STOP_BITS_1;
  config.base_clock = UART_DEFAULT_BASE_CLOCK;
  if (spcr->flow_control & GRUB_ACPI_SPCR_FC_RTSCTS)
    config.rtscts = 1;
  else
    config.rtscts = 0;
  switch (spcr->baud_rate)
    {
      case GRUB_ACPI_SPCR_BAUD_9600:
        config.speed = 9600;
        break;
      case GRUB_ACPI_SPCR_BAUD_19200:
        config.speed = 19200;
        break;
      case GRUB_ACPI_SPCR_BAUD_57600:
        config.speed = 57600;
        break;
      case GRUB_ACPI_SPCR_BAUD_115200:
        config.speed = 115200;
        break;
      case GRUB_ACPI_SPCR_BAUD_CURRENT:
      default:
       /*
        * We don't (yet) have a way to read the currently
        * configured speed in HW, so let's use a sane default.
        */
        config.speed = 115200;
        break;
    };
  switch (spcr->base_addr.space_id)
    {
      case GRUB_ACPI_GENADDR_MEM_SPACE:
        return grub_serial_ns8250_add_mmio (spcr->base_addr.addr,
                                            spcr->base_addr.access_size, &config);
      case GRUB_ACPI_GENADDR_IO_SPACE:
        return grub_serial_ns8250_add_port (spcr->base_addr.addr, &config);
      default:
        return NULL;
    };
}

#endif
