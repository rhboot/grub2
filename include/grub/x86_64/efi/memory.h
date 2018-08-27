#ifndef GRUB_MEMORY_CPU_HEADER
#include <grub/efi/memory.h>

#if defined (__code_model_large__)
#define GRUB_EFI_MAX_USABLE_ADDRESS 0xffffffffffffffffULL
#else
#define GRUB_EFI_MAX_USABLE_ADDRESS 0x7fffffffffffffffULL
#endif

#endif /* ! GRUB_MEMORY_CPU_HEADER */
