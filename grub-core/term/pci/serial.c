/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2023  Free Software Foundation, Inc.
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

#include <grub/serial.h>
#include <grub/term.h>
#include <grub/types.h>
#include <grub/pci.h>
#include <grub/mm.h>
#include <grub/misc.h>

static int
find_pciserial (grub_pci_device_t dev, grub_pci_id_t pciid __attribute__ ((unused)), void *data __attribute__ ((unused)))
{
  grub_pci_address_t cmd_addr, class_addr, bar_addr;
  struct grub_serial_port *port;
  grub_uint32_t class, bar;
  grub_uint16_t cmdreg;
  grub_err_t err;

  cmd_addr = grub_pci_make_address (dev, GRUB_PCI_REG_COMMAND);
  cmdreg = grub_pci_read (cmd_addr);

  class_addr = grub_pci_make_address (dev, GRUB_PCI_REG_REVISION);
  class = grub_pci_read (class_addr);

  bar_addr = grub_pci_make_address (dev, GRUB_PCI_REG_ADDRESS_REG0);
  bar = grub_pci_read (bar_addr);

  /* 16550 compatible MODEM or SERIAL. */
  if (((class >> 16) != GRUB_PCI_CLASS_COMMUNICATION_MODEM &&
       (class >> 16) != GRUB_PCI_CLASS_COMMUNICATION_SERIAL) ||
      ((class >> 8) & 0xff) != GRUB_PCI_SERIAL_16550_COMPATIBLE)
    return 0;

  if ((bar & GRUB_PCI_ADDR_SPACE_MASK) != GRUB_PCI_ADDR_SPACE_IO)
    return 0;

  port = grub_zalloc (sizeof (*port));
  if (port == NULL)
    return 0;

  port->name = grub_xasprintf ("pci,%02x:%02x.%x",
			       grub_pci_get_bus (dev),
			       grub_pci_get_device (dev),
			       grub_pci_get_function (dev));
  if (port->name == NULL)
    goto fail;

  grub_pci_write (cmd_addr, cmdreg | GRUB_PCI_COMMAND_IO_ENABLED);

  port->driver = &grub_ns8250_driver;
  port->port = bar & GRUB_PCI_ADDR_IO_MASK;
  err = grub_serial_config_defaults (port);
  if (err != GRUB_ERR_NONE)
    {
      grub_print_error ();
      goto fail;
    }

  err = grub_serial_register (port);
  if (err != GRUB_ERR_NONE)
    goto fail;

  return 0;

 fail:
  grub_free (port->name);
  grub_free (port);
  return 0;
}

void
grub_pciserial_init (void)
{
  grub_pci_iterate (find_pciserial, NULL);
}
