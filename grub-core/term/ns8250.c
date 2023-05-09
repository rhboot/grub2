/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000,2001,2002,2003,2004,2005,2007,2008,2009,2010  Free Software Foundation, Inc.
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
#include <grub/ns8250.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/cpu/io.h>
#include <grub/mm.h>
#include <grub/time.h>
#include <grub/i18n.h>

#ifdef GRUB_MACHINE_PCBIOS
#include <grub/machine/memory.h>
#define GRUB_SERIAL_PORT_NUM 4
#else
#include <grub/machine/serial.h>
static const grub_port_t serial_hw_io_addr[] = GRUB_MACHINE_SERIAL_PORTS;
#define GRUB_SERIAL_PORT_NUM (ARRAY_SIZE(serial_hw_io_addr))
#endif

static int dead_ports = 0;

static grub_uint8_t
ns8250_reg_read (struct grub_serial_port *port, grub_addr_t reg)
{
  asm volatile("" : : : "memory");
  if (port->use_mmio == true)
    {
      /*
       * Note: we assume MMIO UARTs are little endian. This is not true of all
       * embedded platforms but will do for now.
       */
      switch(port->mmio.access_size)
        {
        default:
          /* ACPI tables occasionally uses "0" (legacy) as equivalent to "1" (byte). */
        case 1:
          return *((volatile grub_uint8_t *) (port->mmio.base + reg));
        case 2:
          return grub_le_to_cpu16 (*((volatile grub_uint16_t *) (port->mmio.base + (reg << 1))));
        case 3:
          return grub_le_to_cpu32 (*((volatile grub_uint32_t *) (port->mmio.base + (reg << 2))));
        case 4:
          /*
           * This will only work properly on 64-bit systems since 64-bit
           * accessors aren't atomic on 32-bit hardware. Thankfully the
           * case of a UART with a 64-bit register spacing on 32-bit
           * also probably doesn't exist.
           */
          return grub_le_to_cpu64 (*((volatile grub_uint64_t *) (port->mmio.base + (reg << 3))));
        }
    }
  return grub_inb (port->port + reg);
}

static void
ns8250_reg_write (struct grub_serial_port *port, grub_uint8_t value, grub_addr_t reg)
{
  asm volatile("" : : : "memory");
  if (port->use_mmio == true)
    {
      switch(port->mmio.access_size)
        {
        default:
          /* ACPI tables occasionally uses "0" (legacy) as equivalent to "1" (byte). */
        case 1:
          *((volatile grub_uint8_t *) (port->mmio.base + reg)) = value;
          break;
        case 2:
          *((volatile grub_uint16_t *) (port->mmio.base + (reg << 1))) = grub_cpu_to_le16 (value);
          break;
        case 3:
          *((volatile grub_uint32_t *) (port->mmio.base + (reg << 2))) = grub_cpu_to_le32 (value);
          break;
        case 4:
          /* See commment in ns8250_reg_read(). */
          *((volatile grub_uint64_t *) (port->mmio.base + (reg << 3))) = grub_cpu_to_le64 (value);
          break;
        }
    }
  else
    grub_outb (value, port->port + reg);
}

/* Convert speed to divisor.  */
static unsigned short
serial_get_divisor (const struct grub_serial_port *port __attribute__ ((unused)),
		    const struct grub_serial_config *config)
{
  grub_uint32_t base_clock;
  grub_uint32_t divisor;
  grub_uint32_t actual_speed, error;

  /* Get the UART input clock frequency. */
  base_clock = config->base_clock ? config->base_clock : UART_DEFAULT_BASE_CLOCK;

  /*
   * The UART uses 16 times oversampling for the BRG, so adjust the value
   * accordingly to calculate the divisor.
   */
  base_clock >>= 4;

  divisor = (base_clock + (config->speed / 2)) / config->speed;
  if (config->speed == 0)
    return 0;
  if (divisor > 0xffff || divisor == 0)
    return 0;
  actual_speed = base_clock / divisor;
  error = actual_speed > config->speed ? (actual_speed - config->speed)
    : (config->speed - actual_speed);
  if (error > (config->speed / 30 + 1))
    return 0;
  return divisor;
}

static void
do_real_config (struct grub_serial_port *port)
{
  int divisor;
  unsigned char status = 0;
  grub_uint64_t endtime;

  const unsigned char parities[] = {
    [GRUB_SERIAL_PARITY_NONE] = UART_NO_PARITY,
    [GRUB_SERIAL_PARITY_ODD] = UART_ODD_PARITY,
    [GRUB_SERIAL_PARITY_EVEN] = UART_EVEN_PARITY
  };
  const unsigned char stop_bits[] = {
    [GRUB_SERIAL_STOP_BITS_1] = UART_1_STOP_BIT,
    [GRUB_SERIAL_STOP_BITS_2] = UART_2_STOP_BITS,
  };

  if (port->configured)
    return;

  port->broken = 0;

  divisor = serial_get_divisor (port, &port->config);

  /* Turn off the interrupt.  */
  ns8250_reg_write (port, 0, UART_IER);

  /* Set DLAB.  */
  ns8250_reg_write (port, UART_DLAB, UART_LCR);

  ns8250_reg_write (port, divisor & 0xFF, UART_DLL);
  ns8250_reg_write (port, divisor >> 8, UART_DLH);

  /* Set the line status.  */
  status |= (parities[port->config.parity]
	     | (port->config.word_len - 5)
	     | stop_bits[port->config.stop_bits]);
  ns8250_reg_write (port, status, UART_LCR);

  if (port->config.rtscts)
    {
      /* Enable the FIFO.  */
      ns8250_reg_write (port, UART_ENABLE_FIFO_TRIGGER1, UART_FCR);

      /* Turn on DTR and RTS.  */
      ns8250_reg_write (port, UART_ENABLE_DTRRTS, UART_MCR);
    }
  else
    {
      /* Enable the FIFO.  */
      ns8250_reg_write (port, UART_ENABLE_FIFO_TRIGGER14, UART_FCR);

      /* Turn on DTR, RTS, and OUT2.  */
      ns8250_reg_write (port, UART_ENABLE_DTRRTS | UART_ENABLE_OUT2, UART_MCR);
    }

  /* Drain the input buffer.  */
  endtime = grub_get_time_ms () + 1000;
  while (ns8250_reg_read (port, UART_LSR) & UART_DATA_READY)
    {
      ns8250_reg_read (port, UART_RX);
      if (grub_get_time_ms () > endtime)
	{
	  port->broken = 1;
	  break;
	}
    }

  port->configured = 1;
}

/* Fetch a key.  */
static int
serial_hw_fetch (struct grub_serial_port *port)
{
  do_real_config (port);
  if (ns8250_reg_read (port, UART_LSR) & UART_DATA_READY)
    return ns8250_reg_read (port, UART_RX);

  return -1;
}

/* Put a character.  */
static void
serial_hw_put (struct grub_serial_port *port, const int c)
{
  grub_uint64_t endtime;

  do_real_config (port);

  if (port->broken > 5)
    endtime = grub_get_time_ms ();
  else if (port->broken > 1)
    endtime = grub_get_time_ms () + 50;
  else
    endtime = grub_get_time_ms () + 200;
  /* Wait until the transmitter holding register is empty.  */
  while ((ns8250_reg_read (port, UART_LSR) & UART_EMPTY_TRANSMITTER) == 0)
    {
      if (grub_get_time_ms () > endtime)
	{
	  port->broken++;
	  /* There is something wrong. But what can I do?  */
	  return;
	}
    }

  if (port->broken)
    port->broken--;

  ns8250_reg_write (port, c, UART_TX);
}

/* Initialize a serial device. PORT is the port number for a serial device.
   SPEED is a DTE-DTE speed which must be one of these: 2400, 4800, 9600,
   19200, 38400, 57600 and 115200. WORD_LEN is the word length to be used
   for the device. Likewise, PARITY is the type of the parity and
   STOP_BIT_LEN is the length of the stop bit. The possible values for
   WORD_LEN, PARITY and STOP_BIT_LEN are defined in the header file as
   macros.  */
static grub_err_t
serial_hw_configure (struct grub_serial_port *port,
		     struct grub_serial_config *config)
{
  unsigned short divisor;

  divisor = serial_get_divisor (port, config);
  if (divisor == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unsupported serial port speed"));

  if (config->parity != GRUB_SERIAL_PARITY_NONE
      && config->parity != GRUB_SERIAL_PARITY_ODD
      && config->parity != GRUB_SERIAL_PARITY_EVEN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unsupported serial port parity"));

  if (config->stop_bits != GRUB_SERIAL_STOP_BITS_1
      && config->stop_bits != GRUB_SERIAL_STOP_BITS_2)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unsupported serial port stop bits number"));

  if (config->word_len < 5 || config->word_len > 8)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unsupported serial port word length"));

  port->config = *config;
  port->configured = 0;

  /*  FIXME: should check if the serial terminal was found.  */

  return GRUB_ERR_NONE;
}

struct grub_serial_driver grub_ns8250_driver =
  {
    .configure = serial_hw_configure,
    .fetch = serial_hw_fetch,
    .put = serial_hw_put
  };

static char com_names[GRUB_SERIAL_PORT_NUM][20];
static struct grub_serial_port com_ports[GRUB_SERIAL_PORT_NUM];

void
grub_ns8250_init (void)
{
#ifdef GRUB_MACHINE_PCBIOS
  const unsigned short *serial_hw_io_addr = (const unsigned short *) grub_absolute_pointer (GRUB_MEMORY_MACHINE_BIOS_DATA_AREA_ADDR);
#endif
  unsigned i;
  for (i = 0; i < GRUB_SERIAL_PORT_NUM; i++)
    if (serial_hw_io_addr[i])
      {
	grub_err_t err;

	grub_outb (0x5a, serial_hw_io_addr[i] + UART_SR);
	if (grub_inb (serial_hw_io_addr[i] + UART_SR) != 0x5a)
	  {
	    dead_ports |= (1 << i);
	    continue;
	  }
	grub_outb (0xa5, serial_hw_io_addr[i] + UART_SR);
	if (grub_inb (serial_hw_io_addr[i] + UART_SR) != 0xa5)
	  {
	    dead_ports |= (1 << i);
	    continue;
	  }

	grub_snprintf (com_names[i], sizeof (com_names[i]), "com%d", i);
	com_ports[i].name = com_names[i];
	com_ports[i].driver = &grub_ns8250_driver;
	com_ports[i].port = serial_hw_io_addr[i];
	com_ports[i].use_mmio = false;
	err = grub_serial_config_defaults (&com_ports[i]);
	if (err)
	  grub_print_error ();

	grub_serial_register (&com_ports[i]);
      }
}

/* Return the port number for the UNITth serial device.  */
grub_port_t
grub_ns8250_hw_get_port (const unsigned int unit)
{
#ifdef GRUB_MACHINE_PCBIOS
  const unsigned short *serial_hw_io_addr = (const unsigned short *) grub_absolute_pointer (GRUB_MEMORY_MACHINE_BIOS_DATA_AREA_ADDR);
#endif
  if (unit < GRUB_SERIAL_PORT_NUM
      && !(dead_ports & (1 << unit)))
    return serial_hw_io_addr[unit];
  else
    return 0;
}

struct grub_serial_port *
grub_serial_ns8250_add_port (grub_port_t port, struct grub_serial_config *config)
{
  struct grub_serial_port *p;
  unsigned i;

  for (i = 0; i < GRUB_SERIAL_PORT_NUM; i++)
    if (com_ports[i].port == port)
      {
	if (dead_ports & (1 << i))
	  return NULL;
	/* Give the opportunity for SPCR to configure a default com port. */
	if (config != NULL)
	  grub_serial_port_configure (&com_ports[i], config);
	return &com_ports[i];
      }

  FOR_SERIAL_PORTS (p)
    if (p->use_mmio == false && p->port == port)
      {
        if (config != NULL)
          grub_serial_port_configure (p, config);
        return p;
      }

  grub_outb (0x5a, port + UART_SR);
  if (grub_inb (port + UART_SR) != 0x5a)
    return NULL;

  grub_outb (0xa5, port + UART_SR);
  if (grub_inb (port + UART_SR) != 0xa5)
    return NULL;

  p = grub_malloc (sizeof (*p));
  if (p == NULL)
    return NULL;
  p->name = grub_xasprintf ("port%lx", (unsigned long) port);
  if (p->name == NULL)
    {
      grub_free (p);
      return NULL;
    }
  p->driver = &grub_ns8250_driver;
  p->use_mmio = false;
  p->port = port;
  if (config != NULL)
    grub_serial_port_configure (p, config);
  else
    grub_serial_config_defaults (p);
  grub_serial_register (p);

  return p;
}

struct grub_serial_port *
grub_serial_ns8250_add_mmio (grub_addr_t addr, unsigned int acc_size,
                             struct grub_serial_config *config)
{
  struct grub_serial_port *p;
  unsigned i;

  for (i = 0; i < GRUB_SERIAL_PORT_NUM; i++)
    if (com_ports[i].use_mmio == true && com_ports[i].mmio.base == addr)
      {
        if (config != NULL)
          grub_serial_port_configure (&com_ports[i], config);
        return &com_ports[i];
      }

  FOR_SERIAL_PORTS (p)
    if (p->use_mmio == true && p->mmio.base == addr)
      {
        if (config != NULL)
          grub_serial_port_configure (p, config);
        return p;
      }

  p = grub_malloc (sizeof (*p));
  if (p == NULL)
    return NULL;
  p->name = grub_xasprintf ("mmio,%llx", (unsigned long long) addr);
  if (p->name == NULL)
    {
      grub_free (p);
      return NULL;
    }
  p->driver = &grub_ns8250_driver;
  p->use_mmio = true;
  p->mmio.base = addr;
  p->mmio.access_size = acc_size;
  if (config != NULL)
    grub_serial_port_configure (p, config);
  else
    grub_serial_config_defaults (p);
  grub_serial_register (p);

  return p;
}
