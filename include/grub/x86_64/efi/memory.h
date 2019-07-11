#ifndef GRUB_MEMORY_CPU_HEADER
#include <grub/efi/memory.h>

#if defined (__code_model_large__)
#define GRUB_EFI_MAX_USABLE_ADDRESS __UINTPTR_MAX__
#define GRUB_EFI_MAX_ALLOCATION_ADDRESS 0x7fffffff
#else
#define GRUB_EFI_MAX_USABLE_ADDRESS 0x7fffffff
#define GRUB_EFI_MAX_ALLOCATION_ADDRESS GRUB_EFI_MAX_USABLE_ADDRESS
#endif

#endif /* ! GRUB_MEMORY_CPU_HEADER */
