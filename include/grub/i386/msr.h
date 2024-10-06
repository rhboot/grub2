/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2019  Free Software Foundation, Inc.
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

#ifndef GRUB_I386_MSR_H
#define GRUB_I386_MSR_H 1

#include <grub/err.h>
#include <grub/i386/cpuid.h>
#include <grub/types.h>

static inline grub_err_t
grub_cpu_is_msr_supported (void)
{
  grub_uint32_t eax, ebx, ecx, edx;

  /*
   * The CPUID instruction should be used to determine whether MSRs
   * are supported, CPUID.01H:EDX[5] = 1.
   */
  if (!grub_cpu_is_cpuid_supported ())
    return GRUB_ERR_BAD_DEVICE;

  grub_cpuid (0, eax, ebx, ecx, edx);

  if (eax < 1)
    return GRUB_ERR_BAD_DEVICE;

  grub_cpuid (1, eax, ebx, ecx, edx);

  if (!(edx & (1 << 5)))
    return GRUB_ERR_BAD_DEVICE;

  return GRUB_ERR_NONE;
}

/*
 * TODO: Add a general protection exception handler.
 *       Accessing a reserved or unimplemented MSR address results in a GP#.
 */

static inline grub_uint64_t
grub_rdmsr (grub_uint32_t msr_id)
{
  grub_uint32_t low, high;

  asm volatile ("rdmsr" : "=a" (low), "=d" (high) : "c" (msr_id));

  return ((grub_uint64_t) high << 32) | low;
}

static inline void
grub_wrmsr (grub_uint32_t msr_id, grub_uint64_t msr_value)
{
  grub_uint32_t low = msr_value, high = msr_value >> 32;

  asm volatile ("wrmsr" : : "c" (msr_id), "a" (low), "d" (high));
}

#endif /* GRUB_I386_MSR_H */
