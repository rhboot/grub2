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
#include <grub/x86_64/efi/hwfeatures-gcry.h>
#include <grub/x86_64/cpuid.h>
#include <grub/misc.h>

/*
 * Older versions of GCC may reorder the inline asm, which can lead to
 * unexpected behavior when reading the Control Registers. The __FORCE_ORDER
 * macro is used to prevent this.
 *
 * Ref: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa5cacdc29d76a005cbbee018a47faa6e724dd2d
 */
#define __FORCE_ORDER "m"(*(unsigned int *) 0x1000UL)

#define HW_FEATURE_X86_64_SSE (1 << 0)
#define HW_FEATURE_X86_64_AVX (1 << 1)

static grub_uint32_t hw_features = 0;
static grub_uint64_t old_cr0, old_cr4, old_xcr0;

static grub_uint64_t
read_cr0 (void)
{
  grub_uint64_t val;

  asm volatile ("mov %%cr0, %0" : "=r" (val) : __FORCE_ORDER);
  return val;
}

static grub_uint64_t
read_cr4 (void)
{
  grub_uint64_t val;

  asm volatile ("mov %%cr4,%0" : "=r" (val) : __FORCE_ORDER);
  return val;
}

static void
write_cr0 (grub_uint64_t val)
{
  asm volatile ("mov %0,%%cr4": "+r" (val) : : "memory");
}

static void
write_cr4 (grub_uint64_t val)
{
  asm volatile ("mov %0,%%cr4": "+r" (val) : : "memory");
}

static grub_uint32_t
get_cpuid_ecx (void)
{
  grub_uint32_t eax, ebx, ecx, edx;

  grub_cpuid (1, eax, ebx, ecx, edx);

  return ecx;
}

static grub_uint32_t
get_cpuid_edx (void)
{
  grub_uint32_t eax, ebx, ecx, edx;

  grub_cpuid (1, eax, ebx, ecx, edx);

  return edx;
}

static bool
enable_sse (void)
{
  grub_uint64_t cr0, cr4;
  grub_uint32_t edx;

  edx = get_cpuid_edx ();

  /* Check CPUID.01H:EDX.FXSR[bit 24] and CPUID.01H:EDX.SSE[bit 25] */
  if ((edx & (3 << 24)) != (3 << 24))
    return false;

  cr0 = old_cr0 = read_cr0 ();
  cr4 = old_cr4 = read_cr4 ();

  /* clear CR0.EM[bit 2] */
  if ((cr0 & (1 << 2)) != 0)
    cr0 &= ~(1 << 2);

  /* Set CR0.MP[bit 1] */
  if ((cr0 & (1 << 1)) == 0)
    cr0 |= (1 << 1);

  grub_dprintf ("hwfeatures", "CR0: 0x%"PRIxGRUB_UINT64_T" 0x%"PRIxGRUB_UINT64_T"\n", old_cr0, cr0);
  if (old_cr0 != cr0)
    write_cr0 (cr0);

  /* Set CR4.OSFXSR[bit 9] and CR4.OSXMMEXCPT[bit 10] */
  if ((cr4 & (3 << 9)) != (3 << 9))
    cr4 |= (3 << 9);

  grub_dprintf ("hwfeatures", "CR4: 0x%"PRIxGRUB_UINT64_T" 0x%"PRIxGRUB_UINT64_T"\n", old_cr4, cr4);
  if (old_cr4 != cr4)
    write_cr4 (cr4);

  return true;
}

static grub_uint64_t
xgetbv (grub_uint32_t index)
{
  grub_uint32_t eax, edx;

  asm volatile ("xgetbv" : "=a" (eax), "=d" (edx) : "c" (index));

  return eax + ((grub_uint64_t)edx << 32);
}

static void
xsetbv (grub_uint32_t index, grub_uint64_t value)
{
  grub_uint32_t eax = (grub_uint32_t)value;
  grub_uint32_t edx = (grub_uint32_t)(value >> 32);

  asm volatile ("xsetbv" :: "a" (eax), "d" (edx), "c" (index));
}

static bool
enable_avx (void)
{
  grub_uint64_t cr4;
  grub_uint32_t ecx;
  grub_uint64_t sse_avx_mask = (1 << 2) | (1 << 1);
  grub_uint64_t xcr0;

  ecx = get_cpuid_ecx ();

  /* Check the following two bits
   * -  CPUID.01H:ECX.XSAVE[bit 26]
   *    If XSAVE is not supported, setting CR4.OSXSAVE will cause
   *    general-protection fault (#GP).
   * - CPUID.01H:ECX.AVX[bit 28]
   */
  grub_dprintf ("hwfeatures", "Check CPUID.01H:ECX 0x%"PRIuGRUB_UINT32_T"\n", ecx);
  if ((ecx & (5 << 26)) != (5 << 26))
    return false;

  cr4 = read_cr4 ();

  /* Set CR4.OSXSAVE[bit 18] */
  if ((cr4 & (1 << 18)) == 0)
    {
      grub_dprintf ("hwfeatures", "Set CR4.OSXSAVE\n");
      cr4 |= 1 << 18;
      write_cr4 (cr4);
    }

  ecx = get_cpuid_ecx ();

  /* Check CPUID.01H:ECX.OSXSAVE[bit 27] */
  if ((ecx & (1 << 27)) == 0)
    return false;

  xcr0 = old_xcr0 = xgetbv (0);

  /* Set XCR0[bit 1] and XCR0[bit 2] to enable SSE/AVX */
  if ((xcr0 & sse_avx_mask) != sse_avx_mask)
    {
      grub_dprintf ("hwfeatures", "Set XCR0[2:1] to 11b\n");
      xcr0 |= sse_avx_mask;
      xsetbv (0, xcr0);
    }

  return true;
}

void
grub_enable_gcry_hwf_x86_64_efi (void)
{
  if (enable_sse () == true)
    hw_features |= HW_FEATURE_X86_64_SSE;

  if (enable_avx () == true)
    hw_features |= HW_FEATURE_X86_64_AVX;
}

void
grub_reset_gcry_hwf_x86_64_efi (void)
{
  grub_uint64_t cr0, cr4, xcr0;

  if ((hw_features & HW_FEATURE_X86_64_AVX) != 0)
    {
      xcr0 = xgetbv (0);
      if (xcr0 != old_xcr0)
	{
	  /*
	   * Reset the AVX state with 'vzeroupper' before clearing XCR0[bit 2].
	   *
	   * Ref: Intel 64 and IA-32 Architectures Software Developer's Manual
	   *      - 13.3 ENABLING THE XSAVE FEATURE SET AND XSAVE-ENABLED FEATURES
	   *
	   * "As noted in Section 13.1, the processor will preserve AVX state
	   *  unmodified if software clears XCR0[2]. However, clearing XCR0[2]
	   *  while AVX state is not in its initial configuration may cause SSE
	   *  instructions to incur a power and performance penalty."
	   */
	  asm volatile ("vzeroupper" ::: "memory");
	  xsetbv (0, old_xcr0);
	}
    }

  if ((hw_features & HW_FEATURE_X86_64_AVX) != 0 || (hw_features & HW_FEATURE_X86_64_SSE) != 0)
    {
      cr4 = read_cr4 ();
      if (cr4 != old_cr4)
	write_cr4 (old_cr4);
    }

  if ((hw_features & HW_FEATURE_X86_64_SSE) != 0)
    {
      cr0 = read_cr0 ();
      if (cr0 != old_cr0)
	write_cr0 (old_cr0);
    }

  hw_features = 0;
}
