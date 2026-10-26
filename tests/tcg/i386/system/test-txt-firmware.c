/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * txt-firmware=on with txt-vmx-compat=on: SeaBIOS boots this kernel
 * without touching the locked IA32_FEATURE_CONTROL, which holds the
 * TXT bits and the VMX-outside-SMX bit a VMX CPU's firmware sets.
 */
#include <stdint.h>

#define MSR_IA32_FEATURE_CONTROL    0x3a
/* Locked, VMXON inside and outside SMX, every SENTER enable */
#define FEATURE_CONTROL_EXPECTED    0xff07u

static void fail(int code)
{
    asm volatile("out %%eax, $0xf4" : : "a"(code));
    for (;;) {
        asm volatile("hlt");
    }
}

int main(void)
{
    uint32_t lo, hi;

    asm volatile("rdmsr" : "=a"(lo), "=d"(hi)
                 : "c"(MSR_IA32_FEATURE_CONTROL));
    if (lo != FEATURE_CONTROL_EXPECTED || hi) {
        fail(1);
    }
    asm volatile("out %%ax, %%dx" : : "a"(0x2000), "d"(0x604));
    for (;;) {
        asm volatile("hlt");
    }
}
