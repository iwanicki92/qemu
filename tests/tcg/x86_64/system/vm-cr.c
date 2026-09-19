/*
 * AMD VM_CR MSR test
 *
 * Reads and writes the MSR, checks LOCK against SVMDIS, SVMDIS against
 * EFER.SVME, and that DIS_A20M forces the A20 line on while remembering
 * the gate written through port 0x92 for when the bit clears.
 *
 * The kernel runs at 1 MiB, which an A20 mask aliases away, so the probe
 * that runs with A20 masked is copied to 0x210000 and walks page tables at
 * 0x200000, addresses with bit 20 clear. Its markers at 4 MiB and 5 MiB
 * alias each other under the mask.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <minilib.h>

#define MSR_EFER                0xc0000080
#define MSR_EFER_SVME           (1 << 12)
#define MSR_VM_CR               0xc0010114
#define MSR_VM_CR_DPD           (1 << 0)
#define MSR_VM_CR_R_INIT        (1 << 1)
#define MSR_VM_CR_DIS_A20M      (1 << 2)
#define MSR_VM_CR_LOCK          (1 << 3)
#define MSR_VM_CR_SVMDIS        (1 << 4)

#define LOW_PML4                0x200000
#define LOW_PDP                 0x201000
#define LOW_PD                  0x202000
#define A20_PROBE_CODE          0x210000
#define A20_PROBE_RESULTS       0x211000
#define A20_MARK_LOW            0x400000
#define A20_MARK_HIGH           0x500000
#define A20_MARK_LOW_VAL        0x4a20a20a
#define A20_MARK_HIGH_VAL       0x5a20a20a

/* Code copied elsewhere is copied by this much, its tail included */
#define BLOB_SIZE               256

/* Memory that exception handlers or copied code write behind the compiler */
typedef volatile uint32_t vu32;

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

static inline void write_cr3(uint64_t val)
{
    asm volatile("mov %0, %%cr3" : : "r"(val) : "memory");
}

static inline uint64_t read_cr3(void)
{
    uint64_t val;

    asm volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static void copy(void *to, const void *from, unsigned len)
{
    char *dst = to;
    const char *src = from;

    while (len--) {
        *dst++ = *src++;
    }
}

/*
 * Exceptions: a #GP or #UD handler counts the fault and resumes at
 * gp_resume, which the faulting sequence sets to its own end.
 */
uint64_t gp_resume;
vu32 gp_count;
vu32 ud_count;

static void __attribute__((naked)) gp_handler(void)
{
    asm volatile("incl gp_count(%rip)\n\t"
                 "addq $8, %rsp\n\t"
                 "pushq %rax\n\t"
                 "movq gp_resume(%rip), %rax\n\t"
                 "movq %rax, 8(%rsp)\n\t"
                 "popq %rax\n\t"
                 "iretq");
}

static void __attribute__((naked)) ud_handler(void)
{
    asm volatile("incl ud_count(%rip)\n\t"
                 "pushq %rax\n\t"
                 "movq gp_resume(%rip), %rax\n\t"
                 "movq %rax, 8(%rsp)\n\t"
                 "popq %rax\n\t"
                 "iretq");
}

struct idt_entry {
    uint16_t offset0;
    uint16_t selector;
    uint8_t ist;
    uint8_t type;
    uint16_t offset1;
    uint32_t offset2;
    uint32_t reserved;
} __attribute__((packed));

static struct idt_entry idt[32] __attribute__((aligned(16)));

static void set_gate(int vector, void (*handler)(void))
{
    uint64_t addr = (uint64_t)handler;

    idt[vector].offset0 = addr;
    idt[vector].selector = 0x08;
    idt[vector].ist = 0;
    idt[vector].type = 0x8e;
    idt[vector].offset1 = addr >> 16;
    idt[vector].offset2 = addr >> 32;
}

static void setup_idt(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr = { sizeof(idt) - 1, (uint64_t)idt };

    set_gate(6, ud_handler);
    set_gate(13, gp_handler);
    asm volatile("lidt %0" : : "m"(idtr));
}

/* Returns the number of #GP the write raised, 0 or 1 */
static int wrmsr_faults(uint32_t msr, uint64_t val)
{
    gp_count = 0;
    asm volatile("leaq 1f(%%rip), %%r8\n\t"
                 "movq %%r8, gp_resume(%%rip)\n\t"
                 "wrmsr\n\t"
                 "1:\n\t"
                 : : "c"(msr), "a"((uint32_t)val), "d"((uint32_t)(val >> 32))
                 : "r8", "memory");
    return gp_count;
}

/*
 * The A20 probe. Runs from its copy at A20_PROBE_CODE, so it must not
 * touch the stack or anything else with bit 20 set while the line is
 * masked. rdi is the results area, rsi the VM_CR value clearing DIS_A20M.
 */
static void __attribute__((naked)) a20_probe(vu32 *results, uint64_t vm_cr)
{
    asm volatile(/* Gate off through port 0x92 while DIS_A20M is set */
                 "inb $0x92, %al\n\t"
                 "andb $0xfd, %al\n\t"
                 "outb %al, $0x92\n\t"
                 "movl 0x500000, %eax\n\t"
                 "movl %eax, 0(%rdi)\n\t"
                 /* Clear DIS_A20M: the gate is remembered, 5 MiB aliases */
                 "movl $0xc0010114, %ecx\n\t"
                 "movq %rsi, %rdx\n\t"
                 "shrq $32, %rdx\n\t"
                 "movl %esi, %eax\n\t"
                 "wrmsr\n\t"
                 "movl 0x500000, %eax\n\t"
                 "movl %eax, 4(%rdi)\n\t"
                 /* Gate on again */
                 "inb $0x92, %al\n\t"
                 "orb $0x02, %al\n\t"
                 "outb %al, $0x92\n\t"
                 "movl 0x500000, %eax\n\t"
                 "movl %eax, 8(%rdi)\n\t"
                 "ret");
}

static void build_low_page_tables(void)
{
    uint64_t *pml4 = (uint64_t *)LOW_PML4;
    uint64_t *pdp = (uint64_t *)LOW_PDP;
    uint64_t *pd = (uint64_t *)LOW_PD;
    int i;

    for (i = 0; i < 512; i++) {
        pml4[i] = 0;
        pdp[i] = 0;
        pd[i] = ((uint64_t)i << 21) | 0x83;
    }
    pdp[0] = LOW_PD | 0x3;
    pml4[0] = LOW_PDP | 0x3;
}

static void test_dis_a20m(void)
{
    vu32 *results = (vu32 *)A20_PROBE_RESULTS;
    void (*probe)(vu32 *, uint64_t) = (void *)A20_PROBE_CODE;
    uint64_t saved_cr3 = read_cr3();
    uint64_t vm_cr = rdmsr(MSR_VM_CR);

    copy((void *)A20_PROBE_CODE, a20_probe, BLOB_SIZE);
    build_low_page_tables();
    *(vu32 *)A20_MARK_LOW = A20_MARK_LOW_VAL;
    *(vu32 *)A20_MARK_HIGH = A20_MARK_HIGH_VAL;

    wrmsr(MSR_VM_CR, vm_cr | MSR_VM_CR_DIS_A20M);
    check(*(vu32 *)A20_MARK_HIGH == A20_MARK_HIGH_VAL,
          "A20 on with DIS_A20M set and the gate open");

    write_cr3(LOW_PML4);
    probe(results, vm_cr);
    write_cr3(saved_cr3);

    check(results[0] == A20_MARK_HIGH_VAL,
          "A20 stays on with DIS_A20M set and the gate closed: 0x%x",
          results[0]);
    check(results[1] == A20_MARK_LOW_VAL,
          "the closed gate applies once DIS_A20M clears: 0x%x", results[1]);
    check(results[2] == A20_MARK_HIGH_VAL,
          "opening the gate lifts the mask again: 0x%x", results[2]);
    check(rdmsr(MSR_VM_CR) == vm_cr, "VM_CR is back to 0x%llx", vm_cr);
}

static void test_vm_cr(void)
{
    uint64_t efer = rdmsr(MSR_EFER);
    uint64_t val;

    check(rdmsr(MSR_VM_CR) == 0, "VM_CR reads zero at reset");

    wrmsr(MSR_VM_CR, MSR_VM_CR_DPD | MSR_VM_CR_R_INIT);
    val = rdmsr(MSR_VM_CR);
    check(val == (MSR_VM_CR_DPD | MSR_VM_CR_R_INIT),
          "DPD and R_INIT read back: 0x%llx", val);

    check(wrmsr_faults(MSR_VM_CR, 1 << 5) == 1, "a reserved bit faults");
    check(rdmsr(MSR_VM_CR) == (MSR_VM_CR_DPD | MSR_VM_CR_R_INIT),
          "and leaves the register alone");

    check(wrmsr_faults(MSR_EFER, efer | MSR_EFER_SVME) == 0,
          "EFER.SVME can be set while SVMDIS is clear");
    check(wrmsr_faults(MSR_VM_CR, MSR_VM_CR_SVMDIS) == 1,
          "SVMDIS faults while EFER.SVME is set");
    wrmsr(MSR_EFER, efer);
    check(wrmsr_faults(MSR_VM_CR, MSR_VM_CR_SVMDIS) == 0,
          "SVMDIS can be set once EFER.SVME is clear");
    check(wrmsr_faults(MSR_EFER, efer | MSR_EFER_SVME) == 1,
          "EFER.SVME faults while SVMDIS is set");
    check(!(rdmsr(MSR_EFER) & MSR_EFER_SVME), "and EFER.SVME stays clear");

    wrmsr(MSR_VM_CR, MSR_VM_CR_LOCK | MSR_VM_CR_SVMDIS);
    wrmsr(MSR_VM_CR, 0);
    val = rdmsr(MSR_VM_CR);
    check(val == (MSR_VM_CR_LOCK | MSR_VM_CR_SVMDIS),
          "LOCK keeps itself and SVMDIS: 0x%llx", val);
    wrmsr(MSR_VM_CR, MSR_VM_CR_DPD);
    val = rdmsr(MSR_VM_CR);
    check(val == (MSR_VM_CR_LOCK | MSR_VM_CR_SVMDIS | MSR_VM_CR_DPD),
          "while the other bits stay writable: 0x%llx", val);
}

int main(void)
{
    setup_idt();
    test_vm_cr();
    test_dis_a20m();

    ml_printf("%d failures\n", failures);
    return failures ? 1 : 0;
}
