/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025  Free Software Foundation, Inc.
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

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/efi/api.h>
#include <grub/efi/pci.h>
#include <grub/efi/efi.h>
#include <grub/command.h>
#include <grub/err.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

grub_efi_status_t
grub_efi_connect_controller (grub_efi_handle_t controller_handle,
			     grub_efi_handle_t *driver_image_handle,
			     grub_efi_device_path_protocol_t *remaining_device_path,
			     grub_efi_boolean_t recursive)
{
  grub_efi_boot_services_t *b;

  b = grub_efi_system_table->boot_services;
  return efi_call_4 (b->connect_controller, controller_handle,
		     driver_image_handle, remaining_device_path, recursive);
}

struct grub_efi_handle_list
{
  struct grub_efi_handle_list *next;
  struct grub_efi_handle_list **prev;
  grub_efi_handle_t handle;
};

typedef struct grub_efi_handle_list grub_efi_handle_list_t;

static bool
is_in_list (grub_efi_handle_t handle, grub_efi_handle_list_t *handles)
{
  grub_efi_handle_list_t *e;

  FOR_LIST_ELEMENTS (e, handles)
    if (e->handle == handle)
      return true;

  return false;
}

static void
free_handle_list (grub_efi_handle_list_t **handles_p)
{
  grub_efi_handle_list_t *e;

  while ((e = *handles_p) != NULL)
    {
      *handles_p = e->next;
      grub_free (e);
    }
}

enum searched_item_flag
{
  SEARCHED_ITEM_FLAG_LOOP = 1,
  SEARCHED_ITEM_FLAG_RECURSIVE = 2
};

typedef enum searched_item_flag searched_item_flag_t;

struct searched_item
{
  grub_efi_guid_t guid;
  const char *name;
  searched_item_flag_t flags;
};

typedef struct searched_item searched_item_t;

static grub_err_t
grub_cmd_connectefi (grub_command_t cmd __attribute__ ((unused)),
		     int argc, char **args)
{
  int s;
  searched_item_t pciroot_items[] =
    {
      { GRUB_EFI_PCI_ROOT_IO_GUID, "PCI root", SEARCHED_ITEM_FLAG_RECURSIVE }
    };
  searched_item_t disk_items[] =
    {
      { GRUB_EFI_PCI_ROOT_IO_GUID, "PCI root", 0 },
      { GRUB_EFI_PCI_IO_GUID, "PCI", SEARCHED_ITEM_FLAG_LOOP },
      { GRUB_EFI_SCSI_IO_PROTOCOL_GUID, "SCSI I/O", SEARCHED_ITEM_FLAG_RECURSIVE },
      { GRUB_EFI_DISK_IO_PROTOCOL_GUID, "DISK I/O", SEARCHED_ITEM_FLAG_RECURSIVE }
    };
  searched_item_t *items = NULL;
  int nitems = 0;
  grub_err_t grub_err = GRUB_ERR_NONE;
  bool connected_devices = false;
  grub_efi_handle_list_t *already_handled = NULL;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("one argument expected"));

  if (grub_strcmp (args[0], "pciroot") == 0)
    {
      items = pciroot_items;
      nitems = ARRAY_SIZE (pciroot_items);
    }
  else if ((grub_strcmp (args[0], "disk") == 0) ||
	   (grub_strcmp (args[0], "scsi") == 0))
    {
      items = disk_items;
      nitems = ARRAY_SIZE (disk_items);
    }
  else if (grub_strcmp (args[0], "all") == 0)
    {
      items = NULL;
      nitems = 1;
    }
  else
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unexpected argument: `%s'"), args[0]);

  for (s = 0; s < nitems; s++)
    {
      grub_efi_handle_t *handles;
      grub_efi_uintn_t num_handles;
      int i, loop = 0;
      bool connected = false;

loop:
      loop++;
      if (items != NULL)
	{
	  grub_dprintf ("efi", "step '%s' loop %d:\n", items[s].name, loop);
	  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL,
					    &items[s].guid, 0, &num_handles);
	}
      else
	handles = grub_efi_locate_handle (GRUB_EFI_ALL_HANDLES,
					  NULL, NULL, &num_handles);

      if (!handles)
	continue;

      for (i = 0; i < num_handles; i++)
	{
	  grub_efi_handle_t handle = handles[i];
	  grub_efi_status_t status;
	  int j;

	  /* Skip already handled handles  */
	  if (is_in_list (handle, already_handled))
	    {
	      grub_dprintf ("efi", "  handle %p: already processed\n",
				   handle);
	      continue;
	    }

	  status = grub_efi_connect_controller (handle, NULL, NULL,
			!items || items[s].flags & SEARCHED_ITEM_FLAG_RECURSIVE ? 1 : 0);
	  if (status == GRUB_EFI_SUCCESS)
	    {
	      connected = true;
	      connected_devices = true;
	      grub_dprintf ("efi", "  handle %p: connected\n", handle);
	    }
	  else
	    grub_dprintf ("efi", "  handle %p: failed to connect ("
			  PRIuGRUB_EFI_UINTN_T ")\n", handle, status);

	  grub_efi_handle_list_t *item;
	  item = grub_malloc (sizeof (*item));
	  if (item == NULL)
	    break; /* fatal  */
	  grub_list_push (GRUB_AS_LIST_P (&already_handled), GRUB_AS_LIST (item));
	  item->handle = handle;
	}

      grub_free (handles);
      if (grub_err != GRUB_ERR_NONE)
	break; /* fatal  */

      if (items && items[s].flags & SEARCHED_ITEM_FLAG_LOOP && connected)
	{
	  connected = false;
	  goto loop;
	}

      free_handle_list (&already_handled);
    }

  free_handle_list (&already_handled);

  if (connected_devices)
    grub_efidisk_reenumerate_disks ();

  return grub_err;
}

static grub_command_t cmd;

GRUB_MOD_INIT(connectefi)
{
  cmd = grub_register_command ("connectefi", grub_cmd_connectefi,
			       "pciroot|disk|scsi|all",
			       N_("Connect EFI handles."
				  " If 'pciroot' is specified, connect PCI"
				  " root EFI handles recursively."
				  " If 'disk' or 'scsi' is specified, connect"
				  " SCSI and DISK I/O EFI handles recursively."
				  " If 'all' is specified, connect all"
				  " EFI handles recursively."));
}

GRUB_MOD_FINI(connectefi)
{
  grub_unregister_command (cmd);
}
