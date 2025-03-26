/* of.c - Access the Open Firmware client interface.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2007,2008,2009  Free Software Foundation, Inc.
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
#include <grub/ieee1275/ieee1275.h>
#include <grub/powerpc/ieee1275/ieee1275.h>
#include <grub/misc.h>

#define IEEE1275_CELL_INVALID ((grub_ieee1275_cell_t) - 1)

int
grub_ieee1275_test (const char *name, grub_ieee1275_cell_t *missing)
{
  struct test_args
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t name;
    grub_ieee1275_cell_t missing;
  } args;

  INIT_IEEE1275_COMMON (&args.common, "test", 1, 1);
  args.name = (grub_ieee1275_cell_t) name;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.missing == IEEE1275_CELL_INVALID)
    return -1;

  *missing = args.missing;

  return 0;
}

int
grub_ieee1275_pks_max_object_size (grub_size_t *result)
{
  struct mos_args
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t size;
  } args;

  INIT_IEEE1275_COMMON (&args.common, "pks-max-object-size", 0, 1);

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.size == IEEE1275_CELL_INVALID)
    return -1;

  *result = args.size;

  return 0;
}

int
grub_ieee1275_pks_read_object (grub_uint8_t consumer, grub_uint8_t *label,
                               grub_size_t label_len, grub_uint8_t *buffer,
                               grub_size_t buffer_len, grub_size_t *data_len,
                               grub_uint32_t *policies)
{
  struct pks_read_args
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t consumer;
    grub_ieee1275_cell_t label;
    grub_ieee1275_cell_t label_len;
    grub_ieee1275_cell_t buffer;
    grub_ieee1275_cell_t buffer_len;
    grub_ieee1275_cell_t data_len;
    grub_ieee1275_cell_t policies;
    grub_ieee1275_cell_t rc;
  } args;

  INIT_IEEE1275_COMMON (&args.common, "pks-read-object", 5, 3);
  args.consumer = (grub_ieee1275_cell_t) consumer;
  args.label = (grub_ieee1275_cell_t) label;
  args.label_len = (grub_ieee1275_cell_t) label_len;
  args.buffer = (grub_ieee1275_cell_t) buffer;
  args.buffer_len = (grub_ieee1275_cell_t) buffer_len;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.data_len == IEEE1275_CELL_INVALID)
    return -1;

  *data_len = args.data_len;
  *policies = args.policies;

  return (int) args.rc;
}

int
grub_ieee1275_pks_read_sbvar (grub_uint8_t sbvarflags, grub_uint8_t sbvartype,
                              grub_uint8_t *buffer, grub_size_t buffer_len,
                              grub_size_t *data_len)
{
  struct pks_read_sbvar_args
  {
    struct grub_ieee1275_common_hdr common;
    grub_ieee1275_cell_t sbvarflags;
    grub_ieee1275_cell_t sbvartype;
    grub_ieee1275_cell_t buffer;
    grub_ieee1275_cell_t buffer_len;
    grub_ieee1275_cell_t data_len;
    grub_ieee1275_cell_t rc;
  } args;

  INIT_IEEE1275_COMMON (&args.common, "pks-read-sbvar", 4, 2);
  args.sbvarflags = (grub_ieee1275_cell_t) sbvarflags;
  args.sbvartype = (grub_ieee1275_cell_t) sbvartype;
  args.buffer = (grub_ieee1275_cell_t) buffer;
  args.buffer_len = (grub_ieee1275_cell_t) buffer_len;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.data_len == IEEE1275_CELL_INVALID)
    return -1;

  *data_len = args.data_len;

  return (int) args.rc;
}
