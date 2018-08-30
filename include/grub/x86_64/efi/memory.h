#ifndef GRUB_MEMORY_CPU_HEADER
#include <grub/efi/memory.h>

#if defined (__code_model_large__)
#define GRUB_EFI_MAX_USABLE_ADDRESS __UINTPTR_MAX__
#else
#define GRUB_EFI_MAX_USABLE_ADDRESS __INTPTR_MAX__
#endif

#endif /* ! GRUB_MEMORY_CPU_HEADER */
