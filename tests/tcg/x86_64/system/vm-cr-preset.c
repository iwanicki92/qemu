/*
 * AMD VM_CR preset through the vm-cr CPU property
 *
 * Runs with -cpu max,vm-cr=0x18, LOCK and SVMDIS, as firmware that
 * disables SVM leaves the register. Checks the value is there at reset
 * and that the lock it carries holds. The register's own behaviour is
 * skinit.c's business.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <minilib.h>

#define MSR_VM_CR               0xc0010114
#define MSR_VM_CR_DPD           (1 << 0)
#define MSR_VM_CR_LOCK          (1 << 3)
#define MSR_VM_CR_SVMDIS        (1 << 4)

#define PRESET                  (MSR_VM_CR_LOCK | MSR_VM_CR_SVMDIS)

static int failures;

#define check(cond, ...)                                    \
    do {                                                    \
        if (cond) {                                         \
            ml_printf("ok: " __VA_ARGS__);                  \
        } else {                                            \
            ml_printf("FAIL: " __VA_ARGS__);                \
            failures++;                                     \
        }                                                   \
        ml_printf("\n");                                    \
    } while (0)

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;

    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val)
{
    asm volatile("wrmsr" : : "c"(msr), "a"((uint32_t)val),
                 "d"((uint32_t)(val >> 32)) : "memory");
}

int main(void)
{
    uint64_t val = rdmsr(MSR_VM_CR);

    check(val == PRESET, "VM_CR reads the preset at reset: 0x%llx", val);

    wrmsr(MSR_VM_CR, 0);
    val = rdmsr(MSR_VM_CR);
    check(val == PRESET, "the preset LOCK holds itself and SVMDIS: 0x%llx",
          val);

    wrmsr(MSR_VM_CR, MSR_VM_CR_DPD);
    val = rdmsr(MSR_VM_CR);
    check(val == (PRESET | MSR_VM_CR_DPD),
          "while the other bits stay writable: 0x%llx", val);

    ml_printf("%d failures\n", failures);
    return failures ? 1 : 0;
}
