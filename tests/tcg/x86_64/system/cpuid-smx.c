/*
 * The SMX CPUID bit on the max CPU model
 *
 * TCG emulates SMX, so the max model can offer it, but no AMD processor
 * has it. Built with EXPECT_SMX for the runs where the bit belongs: an
 * Intel vendor, or +smx asked for on the command line.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <minilib.h>

#define CPUID_1_ECX_SMX         (1 << 6)

#ifdef EXPECT_SMX
#define EXPECTED                CPUID_1_ECX_SMX
#else
#define EXPECTED                0
#endif

int main(void)
{
    uint32_t eax = 1, ebx, ecx = 0, edx;

    asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    if ((ecx & CPUID_1_ECX_SMX) != EXPECTED) {
        ml_printf("FAIL: CPUID.1:ECX is 0x%x, SMX should be %s\n", ecx,
                  EXPECTED ? "set" : "clear");
        return 1;
    }
    ml_printf("ok: SMX is %s\n", EXPECTED ? "set" : "clear");
    return 0;
}
