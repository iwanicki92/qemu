/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SENTER parks an AP that is not halted as well as a halted one, and a
 * launch that fails its checks must resume it. The AP executes a real-mode SIPI
 * trampoline that increments a byte in RAM forever.
 */
#include <stdint.h>

#define LAPIC_BASE 0xfee00000u
#define TXT_BASE   0xfed30000u
#define TXT_STS    0x000u
#define TXT_ERROR  0x030u
#define CR4_SMXE   (1u << 14)
#define TXT_APS_UNSUPPORTED 0x80070001u

static void fail(int code)
{
    asm volatile("out %%eax, $0xf4" : : "a"(code));
    for (;;) {
        asm volatile("hlt");
    }
}

int main(void)
{
    static const uint8_t spin[] = {
        0xfe, 0x06, 0x00, 0x90, /* incb 0x9000 (real-mode DS base 0) */
        0xeb, 0xfa,             /* jmp back to incb */
    };
    /* Volatile: SIPI fetches these instruction bytes from guest RAM. */
    volatile uint8_t *code = (volatile uint8_t *)0x8000;
    /* Volatile: the AP updates this word concurrently with the BSP. */
    volatile uint8_t *counter = (volatile uint8_t *)0x9000;
    /* Volatile: the local APIC interrupt command is guest MMIO. */
    volatile uint32_t *icr_high = (volatile uint32_t *)(LAPIC_BASE + 0x310);
    /* Volatile: the local APIC interrupt command is guest MMIO. */
    volatile uint32_t *icr_low = (volatile uint32_t *)(LAPIC_BASE + 0x300);
    /* Volatile: TXT status and error code are guest MMIO. */
    volatile uint32_t *sts = (volatile uint32_t *)(TXT_BASE + TXT_STS);
    /* Volatile: TXT status and error code are guest MMIO. */
    volatile uint32_t *error = (volatile uint32_t *)(TXT_BASE + TXT_ERROR);
    uint32_t cr4;
    unsigned i;
    uint8_t before;

    for (i = 0; i < sizeof(spin); i++) {
        code[i] = spin[i];
    }
    *counter = 0;
    *icr_high = 1u << 24; /* target APIC ID 1 */
    *icr_low = 0x4500; /* INIT, level assert */
    for (i = 0; i < 100000; i++) {
        asm volatile("pause" : : : "memory");
    }
    *icr_low = 0x4608; /* SIPI, vector 8 -> physical 0x8000 */
    for (i = 0; i < 10000000 && !*counter; i++) {
        asm volatile("pause" : : : "memory");
    }
    if (!*counter) {
        fail(1);
    }

    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= CR4_SMXE;
    asm volatile("mov %0, %%cr4" : : "r"(cr4));
    asm volatile(".byte 0x0f, 0x37" : : "a"(4), "b"(0), "c"(0), "d"(0)
                 : "memory");
    /* No ACM: the launch fails its checks, not the AP rendezvous */
    if ((*sts & 1u) || *error == 0 || *error == TXT_APS_UNSUPPORTED) {
        fail(2);
    }
    before = *counter;
    for (i = 0; i < 10000000 && *counter == before; i++) {
        asm volatile("pause" : : : "memory");
    }
    if (*counter == before) {
        fail(3);
    }
    asm volatile("out %%ax, %%dx" : : "a"(0x2000), "d"(0x604));
    for (;;) {
        asm volatile("hlt");
    }
}
