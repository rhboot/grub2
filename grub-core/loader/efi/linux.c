/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2014 Free Software Foundation, Inc.
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

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/cpu/linux.h>
#include <grub/efi/efi.h>
#include <grub/efi/pe32.h>
#include <grub/efi/linux.h>

#define SHIM_LOCK_GUID \
 { 0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} }

struct grub_efi_shim_lock
{
  grub_efi_status_t (*verify) (void *buffer, grub_uint32_t size);
};
typedef struct grub_efi_shim_lock grub_efi_shim_lock_t;

// Returns 1 on success, -1 on error, 0 when not available
int
grub_linuxefi_secure_validate (void *data, grub_uint32_t size)
{
  grub_efi_guid_t guid = SHIM_LOCK_GUID;
  grub_efi_shim_lock_t *shim_lock;
  grub_efi_status_t status;

  shim_lock = grub_efi_locate_protocol(&guid, NULL);
  grub_dprintf ("secureboot", "shim_lock: %p\n", shim_lock);
  if (!shim_lock)
    {
      grub_dprintf ("secureboot", "shim not available\n");
      return 0;
    }

  grub_dprintf ("secureboot", "Asking shim to verify kernel signature\n");
  status = shim_lock->verify (data, size);
  grub_dprintf ("secureboot", "shim_lock->verify(): %ld\n", (long int)status);
  if (status == GRUB_EFI_SUCCESS)
    {
      grub_dprintf ("secureboot", "Kernel signature verification passed\n");
      return 1;
    }

  grub_dprintf ("secureboot", "Kernel signature verification failed (0x%lx)\n",
		(unsigned long) status);

  return -1;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

grub_err_t
grub_efi_check_nx_image_support (grub_addr_t kernel_addr,
				 grub_size_t kernel_size,
				 int *nx_supported)
{
  struct grub_dos_header *doshdr;
  grub_size_t sz = sizeof (*doshdr);

  struct grub_pe32_header_32 *pe32;
  struct grub_pe32_header_64 *pe64;

  int image_is_compatible = 0;
  int is_64_bit;

  if (kernel_size < sz)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

  doshdr = (void *)kernel_addr;

  if ((doshdr->magic & 0xffff) != GRUB_DOS_MAGIC)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel DOS magic is invalid"));

  sz = doshdr->lfanew + sizeof (*pe32);
  if (kernel_size < sz)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

  pe32 = (struct grub_pe32_header_32 *)(kernel_addr + doshdr->lfanew);
  pe64 = (struct grub_pe32_header_64 *)pe32;

  if (grub_memcmp (pe32->signature, GRUB_PE32_SIGNATURE,
		   GRUB_PE32_SIGNATURE_SIZE) != 0)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel PE magic is invalid"));

  switch (pe32->coff_header.machine)
    {
    case GRUB_PE32_MACHINE_ARMTHUMB_MIXED:
    case GRUB_PE32_MACHINE_I386:
    case GRUB_PE32_MACHINE_RISCV32:
      is_64_bit = 0;
      break;
    case GRUB_PE32_MACHINE_ARM64:
    case GRUB_PE32_MACHINE_IA64:
    case GRUB_PE32_MACHINE_RISCV64:
    case GRUB_PE32_MACHINE_X86_64:
      is_64_bit = 1;
      break;
    default:
      return grub_error (GRUB_ERR_BAD_OS, N_("PE machine type 0x%04hx unknown"),
			 pe32->coff_header.machine);
    }

  if (is_64_bit)
    {
      sz = doshdr->lfanew + sizeof (*pe64);
      if (kernel_size < sz)
	return grub_error (GRUB_ERR_BAD_OS, N_("kernel is too small"));

      if (pe64->optional_header.dll_characteristics & GRUB_PE32_NX_COMPAT)
	image_is_compatible = 1;
    }
  else
    {
      if (pe32->optional_header.dll_characteristics & GRUB_PE32_NX_COMPAT)
	image_is_compatible = 1;
    }

  *nx_supported = image_is_compatible;
  return GRUB_ERR_NONE;
}

grub_err_t
grub_efi_check_nx_required (int *nx_required)
{
  grub_efi_status_t status;
  grub_efi_guid_t guid = GRUB_EFI_SHIM_LOCK_GUID;
  grub_size_t mok_policy_sz = 0;
  char *mok_policy = NULL;
  grub_uint32_t mok_policy_attrs = 0;

  status = grub_efi_get_variable_with_attributes ("MokPolicy", &guid,
						  &mok_policy_sz,
						  (void **)&mok_policy,
						  &mok_policy_attrs);
  if (status == GRUB_EFI_NOT_FOUND ||
      mok_policy_sz == 0 ||
      mok_policy == NULL)
    {
      *nx_required = 0;
      return GRUB_ERR_NONE;
    }

  *nx_required = 0;
  if (mok_policy_sz < 1 ||
      mok_policy_attrs != (GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS |
			   GRUB_EFI_VARIABLE_RUNTIME_ACCESS) ||
      (mok_policy[mok_policy_sz-1] & GRUB_MOK_POLICY_NX_REQUIRED))
    *nx_required = 1;

  return GRUB_ERR_NONE;
}

typedef void (*handover_func) (void *, grub_efi_system_table_t *, void *);

grub_err_t
grub_efi_linux_boot (grub_addr_t kernel_addr, grub_size_t kernel_size,
		     grub_off_t handover_offset, void *kernel_params,
		     int nx_supported)
{
  grub_efi_loaded_image_t *loaded_image = NULL;
  handover_func hf;
  int offset = 0;
  grub_uint64_t stack_set_attrs = GRUB_MEM_ATTR_R |
				  GRUB_MEM_ATTR_W |
				  GRUB_MEM_ATTR_X;
  grub_uint64_t stack_clear_attrs = 0;
  grub_uint64_t kernel_set_attrs = stack_set_attrs;
  grub_uint64_t kernel_clear_attrs = stack_clear_attrs;
  grub_uint64_t attrs;
  int nx_required = 0;

#ifdef __x86_64__
  offset = 512;
#endif

  /*
   * Since the EFI loader is not calling the LoadImage() and StartImage()
   * services for loading the kernel and booting respectively, it has to
   * set the Loaded Image base address.
   */
  loaded_image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (loaded_image)
    loaded_image->image_base = (void *)kernel_addr;
  else
    grub_dprintf ("linux", "Loaded Image base address could not be set\n");

  grub_dprintf ("linux", "kernel_addr: %p handover_offset: %p params: %p\n",
		(void *)kernel_addr, (void *)handover_offset, kernel_params);


  if (nx_required && !nx_supported)
    return grub_error (GRUB_ERR_BAD_OS, N_("kernel does not support NX loading required by policy"));

  if (nx_supported)
    {
      kernel_set_attrs &= ~GRUB_MEM_ATTR_W;
      kernel_clear_attrs |= GRUB_MEM_ATTR_W;
      stack_set_attrs &= ~GRUB_MEM_ATTR_X;
      stack_clear_attrs |= GRUB_MEM_ATTR_X;
    }

  grub_dprintf ("nx", "Setting attributes for 0x%"PRIxGRUB_ADDR"-0x%"PRIxGRUB_ADDR" to r%cx\n",
		    kernel_addr, kernel_addr + kernel_size - 1,
		    (kernel_set_attrs & GRUB_MEM_ATTR_W) ? 'w' : '-');
  grub_update_mem_attrs (kernel_addr, kernel_size,
			 kernel_set_attrs, kernel_clear_attrs);

  grub_get_mem_attrs (kernel_addr, 4096, &attrs);
  grub_dprintf ("nx", "permissions for 0x%"PRIxGRUB_ADDR" are %s%s%s\n",
		(grub_addr_t)kernel_addr,
		(attrs & GRUB_MEM_ATTR_R) ? "r" : "-",
		(attrs & GRUB_MEM_ATTR_W) ? "w" : "-",
		(attrs & GRUB_MEM_ATTR_X) ? "x" : "-");
  if (grub_stack_addr != (grub_addr_t)-1ll)
    {
      grub_dprintf ("nx", "Setting attributes for stack at 0x%"PRIxGRUB_ADDR"-0x%"PRIxGRUB_ADDR" to rw%c\n",
		    grub_stack_addr, grub_stack_addr + grub_stack_size - 1,
		    (stack_set_attrs & GRUB_MEM_ATTR_X) ? 'x' : '-');
      grub_update_mem_attrs (grub_stack_addr, grub_stack_size,
			     stack_set_attrs, stack_clear_attrs);

      grub_get_mem_attrs (grub_stack_addr, 4096, &attrs);
      grub_dprintf ("nx", "permissions for 0x%"PRIxGRUB_ADDR" are %s%s%s\n",
		    grub_stack_addr,
		    (attrs & GRUB_MEM_ATTR_R) ? "r" : "-",
		    (attrs & GRUB_MEM_ATTR_W) ? "w" : "-",
		    (attrs & GRUB_MEM_ATTR_X) ? "x" : "-");
    }

#if defined(__i386__) || defined(__x86_64__)
  asm volatile ("cli");
#endif

  hf = (handover_func)((char *)kernel_addr + handover_offset + offset);
  hf (grub_efi_image_handle, grub_efi_system_table, kernel_params);

  return GRUB_ERR_BUG;
}

#pragma GCC diagnostic pop
