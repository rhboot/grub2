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

struct grub_efi_already_handled
{
  struct grub_efi_already_handled *next;
  struct grub_efi_already_handled **prev;
  grub_efi_handle_t handle;
};

static struct grub_efi_already_handled *already_handled;

static struct grub_efi_already_handled *
is_in_list (grub_efi_handle_t handle)
{
  struct grub_efi_already_handled *e;

  FOR_LIST_ELEMENTS (e, already_handled)
    if (e->handle == handle)
      return e;

  return NULL;
}

static void
free_handle_list (void)
{
  struct grub_efi_already_handled *e;
  while ((e = already_handled) != NULL)
    {
      already_handled = already_handled->next;
      grub_free (e);
    }
}

typedef enum searched_item_flag
{
  SEARCHED_ITEM_FLAG_LOOP = 1,
  SEARCHED_ITEM_FLAG_RECURSIVE = 2
} searched_item_flags;

typedef struct searched_item
{
  grub_efi_guid_t guid;
  const char *name;
  searched_item_flags flags;
} searched_items;

static grub_err_t
grub_cmd_eficonnect (grub_command_t cmd __attribute__ ((unused)),
		     int argc, char **args)
{
  unsigned s;
  searched_items pciroot_items[] =
    {
      { GRUB_EFI_PCI_ROOT_IO_GUID, "PCI root", SEARCHED_ITEM_FLAG_RECURSIVE }
    };
  searched_items scsi_items[] =
    {
      { GRUB_EFI_PCI_ROOT_IO_GUID, "PCI root", 0 },
      { GRUB_EFI_PCI_IO_GUID, "PCI", SEARCHED_ITEM_FLAG_LOOP },
      { GRUB_EFI_SCSI_IO_PROTOCOL_GUID, "SCSI I/O", SEARCHED_ITEM_FLAG_RECURSIVE }
    };
  searched_items *items = NULL;
  unsigned nitems = 0;
  grub_err_t grub_err = GRUB_ERR_NONE;
  unsigned total_connected = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("one argument expected"));

  if (grub_strcmp(args[0], "pciroot") == 0)
    {
      items = pciroot_items;
      nitems = ARRAY_SIZE (pciroot_items);
    }
  else if (grub_strcmp(args[0], "scsi") == 0)
    {
      items = scsi_items;
      nitems = ARRAY_SIZE (scsi_items);
    }
  else if (grub_strcmp(args[0], N_("all")) == 0)
    {
      items = NULL;
      nitems = 1;
    }
  else
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("unexpected argument `%s'"), args[0]);

  for (s = 0; s < nitems; s++)
    {
      grub_efi_handle_t *handles;
      grub_efi_uintn_t num_handles;
      unsigned i, connected = 0, loop = 0;

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
	  unsigned j;

	  /* Skip already handled handles  */
	  if (is_in_list (handle) != NULL)
	    {
	      grub_dprintf ("efi", "  handle %p: already processed\n",
				   handle);
	      continue;
	    }

	  status = grub_efi_connect_controller(handle, NULL, NULL,
			!items || items[s].flags & SEARCHED_ITEM_FLAG_RECURSIVE ? 1 : 0);
	  if (status == GRUB_EFI_SUCCESS)
	    {
	      connected++;
	      total_connected++;
	      grub_dprintf ("efi", "  handle %p: connected\n", handle);
	    }
	  else
	    grub_dprintf ("efi", "  handle %p: failed to connect (%d)\n",
				 handle, (grub_efi_int8_t) status);

	  struct grub_efi_already_handled *item = grub_malloc(sizeof (*item));
	  if (!item)
	    break; /* fatal  */
	  grub_list_push (GRUB_AS_LIST_P (&already_handled), GRUB_AS_LIST (item));
	  item->handle = handle;
	}

      grub_free (handles);
      if (grub_err != GRUB_ERR_NONE)
	break; /* fatal  */

      if (items && items[s].flags & SEARCHED_ITEM_FLAG_LOOP && connected)
	{
	  connected = 0;
	  goto loop;
	}

      free_handle_list ();
    }

  free_handle_list ();

  if (total_connected)
    grub_efidisk_reenumerate_disks ();

  return grub_err;
}

static grub_command_t cmd;

GRUB_MOD_INIT(eficonnect)
{
  cmd = grub_register_command ("eficonnect", grub_cmd_eficonnect,
			       /* TRANSLATORS: only translate 'all' keyword */
			       N_("pciroot|scsi|all"),
			       N_("Connect EFI handles."
				  " If 'pciroot' is specified, connect PCI"
				  " root EFI handles recursively."
				  " If 'scsi' is specified, connect SCSI"
				  " I/O EFI handles recursively."
				  " If 'all' is specified, connect all"
				  " EFI handles recursively."));
}

GRUB_MOD_FINI(eficonnect)
{
  grub_unregister_command (cmd);
}
