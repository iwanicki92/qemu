/*
 * MSR_AMD64_MMIO_CONF_BASE maps MMCONFIG on q35
 *
 * Programs the MSR the way AMD firmware does and looks for the host
 * bridge's ID at the mapped base. Runs with -machine q35.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <minilib.h>

#define MSR_AMD64_MMIO_CONF_BASE    0xc0010058
#define MMIO_CONF_ENABLE            (1 << 0)
#define MMIO_CONF_BUS_RANGE(n)      ((uint64_t)(n) << 2)

/* Two bases in the PCI hole, the second small enough not to reach 4 GiB */
#define BASE_A                      0xe0000000ULL
#define BASE_B                      0xd0000000ULL
#define BUS_1                       (1 << 20)

/* The Q35 MCH, vendor 8086 device 29c0, at 00:00.0 */
#define MCH_ID                      0x29c08086

/* Memory that the exception handler writes behind the compiler */
typedef volatile uint32_t vu32;

struct idt_entry {
    uint16_t offset0;
    uint16_t selector;
    uint8_t ist;
    uint8_t type;
    uint16_t offset1;
    uint32_t offset2;
    uint32_t reserved;
} __attribute__((packed));

static struct idt_entry idt[32];
static int failures;
vu32 gp_count;

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
                 "d"((uint32_t)(val >> 32)));
}

static inline uint32_t readl(uint64_t addr)
{
    return *(vu32 *)addr;
}

/* Counts the fault and resumes after the two-byte wrmsr */
static void __attribute__((naked)) gp_handler(void)
{
    asm volatile("incl gp_count(%rip)\n\t"
                 "addq $8, %rsp\n\t"
                 "addq $2, (%rsp)\n\t"
                 "iretq");
}

static void setup_idt(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr = { sizeof(idt) - 1, (uint64_t)idt };
    uint64_t addr = (uint64_t)gp_handler;

    idt[13].offset0 = addr;
    idt[13].selector = 0x08;
    idt[13].type = 0x8e;
    idt[13].offset1 = addr >> 16;
    idt[13].offset2 = addr >> 32;
    asm volatile("lidt %0" : : "m"(idtr));
}

int main(void)
{
    uint64_t val;

    setup_idt();

    check(rdmsr(MSR_AMD64_MMIO_CONF_BASE) == 0, "the MSR reads zero at reset");
    check(readl(BASE_A) != MCH_ID, "nothing at the base before the write");

    /* 256 buses at BASE_A, the layout firmware uses */
    val = BASE_A | MMIO_CONF_BUS_RANGE(8) | MMIO_CONF_ENABLE;
    wrmsr(MSR_AMD64_MMIO_CONF_BASE, val);
    check(rdmsr(MSR_AMD64_MMIO_CONF_BASE) == val, "the MSR reads back");
    check(readl(BASE_A) == MCH_ID, "the MCH answers at the base");
    check(readl(BASE_A + BUS_1) == 0xffffffff, "bus 1 is decoded and empty");

    /* One bus at BASE_B, so bus 1 falls outside the window */
    val = BASE_B | MMIO_CONF_BUS_RANGE(0) | MMIO_CONF_ENABLE;
    wrmsr(MSR_AMD64_MMIO_CONF_BASE, val);
    check(readl(BASE_A) != MCH_ID, "the old base is gone");
    check(readl(BASE_B) == MCH_ID, "the MCH answers at the new base");
    check(readl(BASE_B + BUS_1) != 0xffffffff, "bus 1 is not decoded");

    /* A reserved bus range faults and leaves the mapping alone */
    gp_count = 0;
    wrmsr(MSR_AMD64_MMIO_CONF_BASE, BASE_A | MMIO_CONF_BUS_RANGE(9) |
          MMIO_CONF_ENABLE);
    check(gp_count == 1, "a reserved bus range raises #GP");
    check(rdmsr(MSR_AMD64_MMIO_CONF_BASE) == val, "the MSR is unchanged");
    check(readl(BASE_B) == MCH_ID, "the mapping is unchanged");

    /* Clearing the enable bit unmaps */
    wrmsr(MSR_AMD64_MMIO_CONF_BASE, BASE_B);
    check(readl(BASE_B) != MCH_ID, "disabled, the base is empty again");

    ml_printf("%d failures\n", failures);
    return failures ? 1 : 0;
}
