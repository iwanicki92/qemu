/*
 * QEMU Intel TXT (Trusted Execution Technology)
 *
 * TCG guest test for the GETSEC (SMX) CPU interface (milestone M2:
 * decode + static semantics).
 *
 * Required QEMU command line (see meson.build in this directory):
 *
 *   qemu-system-i386 -cpu qemu32,smx \
 *       -display none -device isa-debugcon,chardev=stdio \
 *       -device isa-debug-exit,iobase=0xf4,iosize=0x4 \
 *       -kernel <this test binary>
 *
 * The test runs on the plain machine (no -machine txt=on, no TPM
 * backend), at CPL0 in 32-bit protected mode (see boot.S).  Without
 * the intel-txt chipset device the chipset-present capability bit
 * (bit 0) must be clear; the other leaf capability bits are static.
 *
 * Copyright (c) 2026 Michał Kopeć <michal@nozomi.space>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <stdint.h>
#include <minilib.h>

#define CR4_SMXE_MASK            (1U << 14)

#define GETSEC_LEAF_CAPABILITIES 0
#define GETSEC_LEAF_SENTER       4
#define GETSEC_LEAF_PARAMETERS   6

/* GETSEC[CAPABILITIES] leaf bitmap bits. */
#define GETSEC_CAP_CHIPSET_PRESENT (1U << 0)
#define GETSEC_CAP_EXITAC          (1U << 3)
#define GETSEC_CAP_SENTER          (1U << 4)
#define GETSEC_CAP_SEXIT           (1U << 5)
#define GETSEC_CAP_PARAMETERS      (1U << 6)
#define GETSEC_CAP_SMCTRL          (1U << 7)
#define GETSEC_CAP_WAKEUP          (1U << 8)
#define GETSEC_CAP_STATIC          (GETSEC_CAP_EXITAC | GETSEC_CAP_SENTER | \
                                     GETSEC_CAP_SEXIT | GETSEC_CAP_PARAMETERS | \
                                     GETSEC_CAP_SMCTRL | GETSEC_CAP_WAKEUP)

/* GETSEC[PARAMETERS] entry types (low five bits of EAX). */
#define GETSEC_PARAM_TYPE_MASK     0x1f
#define GETSEC_PARAM_ACM_VERSIONS  1
#define GETSEC_PARAM_MAX_ACM_SIZE  2
#define GETSEC_PARAM_ACM_MEM_TYPES 3
#define GETSEC_PARAM_SENTER_CTRL   4
#define GETSEC_PARAM_TXT_EXT       5

static uint32_t read_cr4(void)
{
    uint32_t v;
    asm volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

static void write_cr4(uint32_t v)
{
    asm volatile("mov %0, %%cr4" :: "r"(v));
}

static uint32_t getsec_capabilities(uint32_t index)
{
    uint32_t eax;
    asm volatile(".byte 0x0f, 0x37"
                 : "=a"(eax)
                 : "0"(GETSEC_LEAF_CAPABILITIES), "b"(index));
    return eax;
}

static void getsec_parameters(uint32_t index, uint32_t *eax, uint32_t *ebx,
                              uint32_t *ecx)
{
    asm volatile(".byte 0x0f, 0x37"
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx)
                 : "0"(GETSEC_LEAF_PARAMETERS), "1"(index));
}

/*
 * The IDT installed by boot.S only carries fixed-up gates that point
 * at address 0, so install our own for #UD; the #GP path is not
 * exercised here (it requires dropping to CPL3).
 */
struct idt_desc {
    uint16_t off_lo;
    uint16_t sel;
    uint16_t access; /* access word: P/DPL/type, little-endian */
    uint16_t off_hi;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

static struct idt_desc idt[32];
static struct idt_ptr idtr;

static int ud_count;

/*
 * The handler is referenced by name from the asm gate below; keep it
 * non-static so the symbol survives in the object.
 */
void ud_handler(void)
{
    ud_count++;
}

__attribute__((naked))
static void ud_gate(void)
{
    /*
     * #UD pushes no error code, so on entry the frame is
     * [EIP][CS][EFLAGS].  Save the caller's registers, count the
     * fault, then step over the 2-byte GETSEC (0F 37) before
     * returning, otherwise iret re-executes it forever.
     */
    asm volatile(
        "pushal\n"
        "call ud_handler\n"
        "popal\n"
        "addl $2, (%esp)\n"
        "iret\n"
    );
}

static void idt_install(void)
{
    int i;

    for (i = 0; i < 32; i++) {
        idt[i] = (struct idt_desc) {
            .sel = 0x08, /* kernel code segment from boot.S */
        };
    }
    {
        uint32_t a = (uint32_t)(uintptr_t)ud_gate;
        idt[6].off_lo = (uint16_t)(a & 0xffff);
        idt[6].off_hi = (uint16_t)((a >> 16) & 0xffff);
        /* 386 interrupt gate, DPL 0, present: 32-bit exception frame. */
        idt[6].access = 0x8e00;
    }
    idtr.limit = sizeof(idt) - 1;
    idtr.base = (uint32_t)(uintptr_t)idt;
    asm volatile("lidt %0" :: "m"(idtr));
}

static int main_fail;

static void fail_msg(const char *msg, int bit)
{
    ml_printf("FAIL: %s\n", msg);
    main_fail |= bit;
}

int main(void)
{
    uint32_t cr4;
    uint32_t caps;
    uint32_t eax = 0, ebx = 0, ecx = 0;
    uint32_t type;
    int index;

    ml_printf("smx: start\n");
    idt_install();
    ml_printf("smx: idt installed\n");

    /* 1. With CR4.SMXE clear, GETSEC raises #UD. */
    cr4 = read_cr4();
    write_cr4(cr4 & ~CR4_SMXE_MASK);

    ud_count = 0;
    ml_printf("smx: GETSEC with SMXE=0 ...\n");
    getsec_capabilities(0);
    ml_printf("smx: back, ud_count=%d\n", ud_count);
    if (ud_count != 1) {
        fail_msg("GETSEC with CR4.SMXE=0 did not raise #UD", 1);
    } else {
        ml_printf("PASS: GETSEC raises #UD with CR4.SMXE=0\n");
    }

    ml_printf("smx: enabling SMXE ...\n");
    write_cr4(cr4 | CR4_SMXE_MASK);
    ml_printf("smx: SMXE enabled, cr4=0x%x\n", read_cr4());

    /*
     * 2. GETSEC[CAPABILITIES]: the static leaf bits are set; without
     *    the intel-txt chipset device the chipset-present bit is
     *    clear, and ENTERACCS / extended leaves are not advertised.
     */
    ml_printf("smx: GETSEC[CAPABILITIES] ...\n");
    caps = getsec_capabilities(0);
    ml_printf("smx: caps=0x%x\n", caps);
    if (caps != GETSEC_CAP_STATIC) {
        ml_printf("FAIL: GETSEC[CAPABILITIES] = 0x%x, expected 0x%x\n",
                  caps, GETSEC_CAP_STATIC);
        main_fail |= 2;
    } else {
        ml_printf("PASS: GETSEC[CAPABILITIES] = 0x%x\n", caps);
    }

    /*
     * 3. GETSEC[PARAMETERS]: walk the table until the type-0 entry and
     *    check the decoded values of the reported parameters.
     */
    type = 1;
    for (index = 0; index < 16 && type; index++) {
        getsec_parameters(index, &eax, &ebx, &ecx);
        type = eax & GETSEC_PARAM_TYPE_MASK;

        switch (index) {
        case 0: /* ACM versions: EBX = version mask, ECX = version */
            if (type != GETSEC_PARAM_ACM_VERSIONS ||
                ebx != 0xffffffff || ecx != 0) {
                fail_msg("PARAMETERS index 0 (ACM versions) mismatch", 4);
            }
            break;
        case 1: /* max ACM size: value in 32-byte units, * 0x20 */
            if (type != GETSEC_PARAM_MAX_ACM_SIZE ||
                (eax & ~GETSEC_PARAM_TYPE_MASK) * 0x20 != 0x8000) {
                fail_msg("PARAMETERS index 1 (max ACM size) mismatch", 4);
            }
            break;
        case 2: /* ACM memory types: UC */
            if (type != GETSEC_PARAM_ACM_MEM_TYPES ||
                (eax & ~GETSEC_PARAM_TYPE_MASK) != 0x100) {
                fail_msg("PARAMETERS index 2 (ACM memory types) mismatch", 4);
            }
            break;
        case 3: /* SENTER controls: none */
            if (type != GETSEC_PARAM_SENTER_CTRL ||
                (eax & 0x7f00) != 0) {
                fail_msg("PARAMETERS index 3 (SENTER controls) mismatch", 4);
            }
            break;
        case 4: /* TXT extensions: processor-based SCRTM */
            if (type != GETSEC_PARAM_TXT_EXT ||
                (eax & 0x60) != 0x20) {
                fail_msg("PARAMETERS index 4 (TXT extensions) mismatch", 4);
            }
            break;
        }
    }
    if (type != 0) {
        fail_msg("PARAMETERS table did not terminate with type 0", 4);
    } else {
        ml_printf("PASS: GETSEC[PARAMETERS] walk terminated "
                  "after %d entries\n", index);
    }

    /* 4. GETSEC[SENTER] is an M2 stub: #UD at CPL0 with SMXE set. */
    ud_count = 0;
    asm volatile(".byte 0x0f, 0x37" :: "a"(GETSEC_LEAF_SENTER));
    if (ud_count != 1) {
        fail_msg("GETSEC[SENTER] stub did not raise #UD", 8);
    } else {
        ml_printf("PASS: GETSEC[SENTER] stub raises #UD\n");
    }

    if (!main_fail) {
        ml_printf("test-smx-getsec: all tests passed\n");
    }
    return main_fail;
}
