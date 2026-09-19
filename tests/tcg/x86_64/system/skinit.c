/*
 * AMD VM_CR and SKINIT test
 *
 * Reads and writes VM_CR, checks LOCK against SVMDIS, SVMDIS against
 * EFER.SVME, and that DIS_A20M forces the A20 line on while remembering
 * the gate written through port 0x92 for when the bit clears. Then it
 * parks the second CPU, leaves an interrupt pending, and executes SKINIT
 * on a 64 KiB SLB whose 32-bit stub records the entry state and jumps back
 * to boot.S, which re-enters main in long mode for the checks: the entry
 * state, the interrupt held back until STGI, and the AP arriving from its
 * SIPI with the VM_CR bits set.
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
#define MSR_VM_CR_SL_ENTRY      (MSR_VM_CR_DPD | MSR_VM_CR_R_INIT | \
                                 MSR_VM_CR_DIS_A20M)

#define CR0_PE                  (1 << 0)
#define CR0_PG                  (1u << 31)

#define LOW_PML4                0x200000
#define LOW_PDP                 0x201000
#define LOW_PD                  0x202000
#define A20_PROBE_CODE          0x210000
#define A20_PROBE_RESULTS       0x211000
#define A20_MARK_LOW            0x400000
#define A20_MARK_HIGH           0x500000
#define A20_MARK_LOW_VAL        0x4a20a20a
#define A20_MARK_HIGH_VAL       0x5a20a20a

#define APIC_BASE               0xfee00000
#define APIC_EOI                0xb0
#define APIC_SVR                0xf0
#define APIC_ICR                0x300
#define APIC_ICR_INIT           0x500
#define APIC_ICR_STARTUP        0x600
#define APIC_ICR_SELF           (1 << 18)
#define APIC_ICR_ALL_BUT_SELF   (3 << 18)
#define IRQ_VECTOR              0x20

/* The AP trampoline, at a page below 1 MiB a SIPI vector can name */
#define AP_CODE                 0x8000
#define AP_VM_CR                0x8100
#define AP_DONE                 0x8104

/*
 * The SLB: header, then the jump target the stub takes, the stub at the
 * entry offset, and the recorded entry state in the unmeasured tail.
 */
#define SLB_BASE                0x20000
#define SLB_JUMP                0x10
#define SLB_ENTRY               0x200
#define SLB_STATE               0x8000

/* Code copied elsewhere is copied by this much, its tail included */
#define BLOB_SIZE               256

#define STR_(x)                 #x
#define STR(x)                  STR_(x)

/* Memory that exception handlers or copied code write behind the compiler */
typedef volatile uint32_t vu32;

struct sl_state {
    uint32_t eax, edx, esp, ebx, ecx, esi, edi, ebp;
    uint32_t eflags;
    uint16_t cs, ss, ds, es, fs, gs;
    uint32_t cr0;
    uint32_t efer_lo, efer_hi;
    uint32_t vm_cr_lo, vm_cr_hi;
};

static int failures;
static vu32 launched;

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

static inline uint32_t cpuid_eax(uint32_t leaf)
{
    uint32_t eax, ebx, ecx, edx;

    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                 : "a"(leaf), "c"(0));
    return eax;
}

static inline void outb(uint16_t port, uint8_t val)
{
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;

    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void apic_write(uint32_t reg, uint32_t val)
{
    *(vu32 *)(uint64_t)(APIC_BASE + reg) = val;
}

static void spin(uint32_t loops)
{
    while (loops--) {
        asm volatile("pause" : : : "memory");
    }
}

/* Long enough for the other CPU's thread to act on an IPI */
static void wait_for_ap(void)
{
    uint64_t start = rdtsc();

    while (rdtsc() - start < 1000000000ULL) {
        asm volatile("pause" : : : "memory");
    }
}

/* The firmware left the PIT ticking through the PIC, and vector 8 is empty */
static void mask_pics(void)
{
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
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
 * gp_resume, which the faulting sequence sets to its own end. The
 * interrupt handler only counts.
 */
uint64_t gp_resume;
vu32 gp_count;
vu32 ud_count;
vu32 irq_count;

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

static void __attribute__((naked)) irq_handler(void)
{
    asm volatile("incl irq_count(%rip)\n\t"
                 "pushq %rax\n\t"
                 "movq $" STR(APIC_BASE + APIC_EOI) ", %rax\n\t"
                 "movl $0, (%rax)\n\t"
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

static struct idt_entry idt[IRQ_VECTOR + 1] __attribute__((aligned(16)));

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
    set_gate(IRQ_VECTOR, irq_handler);
    asm volatile("lidt %0" : : "m"(idtr));
}

/* Where a fault lands when nothing expects one: report it and stop */
static void fault_trap(void)
{
    ml_printf("FAIL: unexpected fault, #GP %d #UD %d\n", gp_count, ud_count);
    asm volatile("outw %w0, $0xf4" : : "a"(1));
    for (;;) {
        asm volatile("hlt");
    }
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
    gp_resume = (uint64_t)fault_trap;
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

/*
 * The secure loader stub, entered by SKINIT in flat 32-bit protected mode
 * with EAX at the SLB base. It records the entry state in the SLB's
 * unmeasured tail through SS, the one usable data segment, loads a flat
 * GDT of its own and jumps to boot.S, which brings main back up.
 */
#define SL_STATE(off)   STR(SLB_STATE) "+" #off
#define SL_LABEL(l)     STR(SLB_ENTRY) "+" #l "-sl_stub"

static void __attribute__((naked)) sl_stub(void)
{
    asm volatile(".code32\n\t"
                 "movl %eax, %ss:" SL_STATE(0) "(%eax)\n\t"
                 "movl %edx, %ss:" SL_STATE(4) "(%eax)\n\t"
                 "movl %esp, %ss:" SL_STATE(8) "(%eax)\n\t"
                 "movl %ebx, %ss:" SL_STATE(12) "(%eax)\n\t"
                 "movl %ecx, %ss:" SL_STATE(16) "(%eax)\n\t"
                 "movl %esi, %ss:" SL_STATE(20) "(%eax)\n\t"
                 "movl %edi, %ss:" SL_STATE(24) "(%eax)\n\t"
                 "movl %ebp, %ss:" SL_STATE(28) "(%eax)\n\t"
                 "pushfl\n\t"
                 "popl %ebx\n\t"
                 "movl %ebx, %ss:" SL_STATE(32) "(%eax)\n\t"
                 "movw %cs, %ss:" SL_STATE(36) "(%eax)\n\t"
                 "movw %ss, %ss:" SL_STATE(38) "(%eax)\n\t"
                 "movw %ds, %ss:" SL_STATE(40) "(%eax)\n\t"
                 "movw %es, %ss:" SL_STATE(42) "(%eax)\n\t"
                 "movw %fs, %ss:" SL_STATE(44) "(%eax)\n\t"
                 "movw %gs, %ss:" SL_STATE(46) "(%eax)\n\t"
                 "movl %cr0, %ebx\n\t"
                 "movl %ebx, %ss:" SL_STATE(48) "(%eax)\n\t"
                 "movl %eax, %ebp\n\t"
                 "movl $" STR(MSR_EFER) ", %ecx\n\t"
                 "rdmsr\n\t"
                 "movl %eax, %ss:" SL_STATE(52) "(%ebp)\n\t"
                 "movl %edx, %ss:" SL_STATE(56) "(%ebp)\n\t"
                 "movl $" STR(MSR_VM_CR) ", %ecx\n\t"
                 "rdmsr\n\t"
                 "movl %eax, %ss:" SL_STATE(60) "(%ebp)\n\t"
                 "movl %edx, %ss:" SL_STATE(64) "(%ebp)\n\t"
                 /* A flat GDT from the SLB, its base patched in here */
                 "leal " SL_LABEL(sl_gdt) "(%ebp), %ebx\n\t"
                 "movl %ebx, %ss:" SL_LABEL(sl_gdt_desc) "+2(%ebp)\n\t"
                 "lgdtl %ss:" SL_LABEL(sl_gdt_desc) "(%ebp)\n\t"
                 "movw $0x10, %bx\n\t"
                 "movw %bx, %ds\n\t"
                 "movw %bx, %es\n\t"
                 "movw %bx, %ss\n\t"
                 "movl %ss:" STR(SLB_JUMP) "(%ebp), %ebx\n\t"
                 "jmp *%ebx\n\t"
                 ".balign 8\n\t"
                 "sl_gdt:\n\t"
                 ".quad 0\n\t"
                 ".quad 0x00cf9b000000ffff\n\t"
                 ".quad 0x00cf93000000ffff\n\t"
                 "sl_gdt_desc:\n\t"
                 ".word sl_gdt_desc - sl_gdt - 1\n\t"
                 ".long 0\n\t"
                 ".code64");
}

/* The AP: record VM_CR where the BSP looks, flag it and stop */
static void __attribute__((naked)) ap_stub(void)
{
    asm volatile(".code16\n\t"
                 "movl $" STR(MSR_VM_CR) ", %ecx\n\t"
                 "rdmsr\n\t"
                 "movl %eax, " STR(AP_VM_CR) "\n\t"
                 "movl $1, " STR(AP_DONE) "\n\t"
                 "1: hlt\n\t"
                 "jmp 1b\n\t"
                 ".code64");
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

/*
 * Park the AP, leave a self-IPI pending behind the clear IF, and launch.
 * If SKINIT comes back, it did not launch: report why and fail.
 */
static void launch(void)
{
    volatile uint16_t *header = (volatile uint16_t *)SLB_BASE; /* the SLB */
    uint64_t start;

    /* boot.S's entry, where the stub jumps to bring main back up */
    asm("leaq _start(%%rip), %0" : "=r"(start));
    copy((void *)AP_CODE, ap_stub, BLOB_SIZE);
    *(vu32 *)AP_DONE = 0;
    apic_write(APIC_SVR, 0x1ff);
    apic_write(APIC_ICR, APIC_ICR_ALL_BUT_SELF | APIC_ICR_INIT);
    wait_for_ap();
    apic_write(APIC_ICR, APIC_ICR_SELF | IRQ_VECTOR);

    header[0] = SLB_ENTRY;
    header[1] = SLB_ENTRY + BLOB_SIZE;
    *(vu32 *)(SLB_BASE + SLB_JUMP) = start;
    copy((void *)(SLB_BASE + SLB_ENTRY), sl_stub, BLOB_SIZE);

    launched = 1;
    ud_count = 0;
    gp_count = 0;
    asm volatile("leaq 1f(%%rip), %%r8\n\t"
                 "movq %%r8, gp_resume(%%rip)\n\t"
                 ".byte 0x0f, 0x01, 0xde\n\t"     /* skinit */
                 "1:\n\t"
                 : : "a"(SLB_BASE) : "r8", "memory");
    launched = 0;
    gp_resume = (uint64_t)fault_trap;
    check(0, "SKINIT returned, #UD %d #GP %d", ud_count, gp_count);
}

static void check_entry_state(void)
{
    struct sl_state *st = (struct sl_state *)(SLB_BASE + SLB_STATE);
    uint64_t efer = ((uint64_t)st->efer_hi << 32) | st->efer_lo;
    uint64_t vm_cr = ((uint64_t)st->vm_cr_hi << 32) | st->vm_cr_lo;

    check(st->cs == 0x08 && st->ss == 0x10, "CS 0x%x SS 0x%x",
          st->cs, st->ss);
    check(!st->ds && !st->es && !st->fs && !st->gs,
          "DS 0x%x ES 0x%x FS 0x%x GS 0x%x", st->ds, st->es, st->fs, st->gs);
    check(st->eax == SLB_BASE, "EAX 0x%x", st->eax);
    check(st->edx == cpuid_eax(1), "EDX 0x%x", st->edx);
    check(st->esp == SLB_BASE + 0x10000, "ESP 0x%x", st->esp);
    check(!st->ebx && !st->ecx && !st->esi && !st->edi && !st->ebp,
          "EBX 0x%x ECX 0x%x ESI 0x%x EDI 0x%x EBP 0x%x",
          st->ebx, st->ecx, st->esi, st->edi, st->ebp);
    check(st->eflags == 0x2, "EFLAGS 0x%x", st->eflags);
    check((st->cr0 & (CR0_PE | CR0_PG)) == CR0_PE, "CR0 0x%x", st->cr0);
    check(efer == 0, "EFER 0x%llx", efer);
    check(vm_cr == (MSR_VM_CR_LOCK | MSR_VM_CR_SVMDIS | MSR_VM_CR_SL_ENTRY),
          "VM_CR 0x%llx", vm_cr);
}

/* The self-IPI sent before the launch waits for STGI, not for IF */
static void check_gif(void)
{
    uint64_t vm_cr = rdmsr(MSR_VM_CR);

    asm volatile("sti" : : : "memory");
    spin(100000);
    check(irq_count == 0, "no interrupt with GIF clear: %d", irq_count);

    wrmsr(MSR_VM_CR, vm_cr & ~MSR_VM_CR_SL_ENTRY);
    asm volatile(".byte 0x0f, 0x01, 0xdc" : : : "memory");   /* stgi */
    spin(100000);
    asm volatile("cli" : : : "memory");
    check(irq_count == 1, "the interrupt arrives after STGI: %d", irq_count);
}

static void check_ap(void)
{
    vu32 *done = (vu32 *)AP_DONE;
    uint32_t vm_cr = 0;
    int i;

    apic_write(APIC_ICR, APIC_ICR_ALL_BUT_SELF | APIC_ICR_STARTUP |
               (AP_CODE >> 12));
    for (i = 0; i < 1000 && !*done; i++) {
        spin(10000);
    }
    check(*done, "the AP answered its SIPI");
    if (*done) {
        vm_cr = *(vu32 *)AP_VM_CR;
    }
    check(vm_cr == MSR_VM_CR_SL_ENTRY, "AP VM_CR 0x%x", vm_cr);
}

int main(void)
{
    setup_idt();
    mask_pics();
    gp_resume = (uint64_t)fault_trap;
    if (!launched) {
        test_vm_cr();
        test_dis_a20m();
        launch();
    } else {
        ml_printf("back from the SLB\n");
        check_entry_state();
        check_gif();
        check_ap();
    }

    ml_printf("%d failures\n", failures);
    return failures ? 1 : 0;
}
