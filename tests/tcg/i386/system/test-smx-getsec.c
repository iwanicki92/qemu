/*
 * QEMU Intel TXT (Trusted Execution Technology)
 *
 * TCG guest test for the GETSEC (SMX) CPU interface: M2 decode +
 * static semantics, and the M3 staged GETSEC[SENTER] measured launch
 * (see docs/specs/intel-txt.rst, "Semantic measured launch").
 *
 * Required QEMU command line (see meson.build in this directory):
 *
 *   qemu-system-i386 -machine q35,txt=on -cpu qemu32,smx \
 *       -display none -device isa-debugcon,chardev=stdio \
 *       -chardev stdio,id=stdio \
 *       -device isa-debug-exit,iobase=0xf4,iosize=0x4 \
 *       -chardev socket,id=tpm0,path=<swtpm socket> \
 *       -tpmdev emulator,id=tpm0,chardev=tpm0 \
 *       -device tpm-tis,tpmdev=tpm0 \
 *       -kernel <this test binary>
 *
 * The test needs the intel-txt chipset device and a TPM backend, so
 * it runs on q35 with txt=on and a swtpm-backed emulator backend.
 * The meson wrapper run-swtpm-test.sh starts swtpm and substitutes
 * the socket path before exec'ing QEMU.
 *
 * The test runs at CPL0 in 32-bit protected mode, unpaged (see
 * boot.S), so all physical addresses are directly addressable.
 *
 * Copyright (c) 2026 Michał Kopeć <michal@nozomi.space>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <stdint.h>
#include <minilib.h>

#define CR4_SMXE_MASK            (1U << 14)
/*
 * The TXT register space only answers 8-byte accesses, which 32-bit
 * code issues by staging through an XMM register (txt_read64 /
 * txt_write64).  Executing any SSE instruction needs CR4.OSFXSR set:
 * advertising SSE in CPUID is not enough, enabling it is the OS's job.
 * Without this the first movq raises #UD, and the #UD gate below --
 * which hardcodes the 2-byte length of GETSEC (0F 37) -- would step
 * EIP into the middle of the 4-byte movq and derail the test.
 */
#define CR4_OSFXSR_MASK          (1U << 9)
#define CR4_OSXMMEXCPT_MASK      (1U << 10)

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

/*
 * TXT public configuration space (see docs/specs/intel-txt.rst,
 * "TXT public config space").  All registers are 64-bit and must be
 * accessed with aligned quadword moves.
 */
#define TXT_PUBLIC_BASE        0xFED30000U
#define TXT_OFF_STS            0x000
#define TXT_OFF_ERRORCODE      0x030
#define TXT_OFF_SINIT_BASE     0x270
#define TXT_OFF_SINIT_SIZE     0x278
#define TXT_OFF_HEAP_BASE      0x300
#define TXT_OFF_HEAP_SIZE      0x308
#define TXT_OFF_DPR            0x330

#define TXT_STS_SENTER_DONE    (1ULL << 0)

/* TXT.DPR layout: bit 0 LOCK, bits [11:4] SIZE in 1 MiB blocks,
   bits [31:20] TOP. */
#define TXT_DPR_LOCK           (1ULL << 0)
#define TXT_DPR_SIZE(n)        (((uint64_t)(n) & 0xff) << 4)
/*
 * TOP is address bits [31:20], so the argument is a full address and
 * the field is extracted from it.  Masking the address with 0xfff
 * before the shift would silently truncate anything >= 1 MiB -- e.g.
 * a 16 MiB top (0x1000000) would become 0, yielding an empty range.
 */
#define TXT_DPR_TOP(top)       ((((uint64_t)(top) >> 20) & 0xfff) << 20)

/*
 * TXT.ERRORCODE values for the staged SENTER path (ACMERROR layout:
 * bit 31 VALID, bit 30 EXTERNAL = 0, [23:16] PROGRESS_CODE, TYPE_CODE
 * = 1 (SINIT); see include/hw/i386/intel_txt.h and the table in
 * docs/specs/intel-txt.rst).
 */
#define TXT_ERR_SINIT_REGION_INVALID 0x80010001ULL
#define TXT_ERR_LAUNCH_INCOMPLETE    0x80040001ULL

/*
 * Launch inputs for the SENTER cases: an 8 KiB SINIT ACM region at
 * 0xE10000 and a 4 KiB heap at 0xE20000, both inside the DPR range
 * [0xE00000, 0x1000000) selected below.
 */
#define TEST_SINIT_BASE        0xE10000ULL
#define TEST_SINIT_SIZE        0x2000ULL
#define TEST_HEAP_BASE         0xE20000ULL
/*
 * Step-c inputs, all inside the same DPR range: a 3-page MLE page
 * table (PDPT/PD/PT) and an 8 KiB MLE image mapped flat at linear 0.
 * The MLE header sits at linear offset 0x100, i.e. inside the measured
 * image, exactly as a real MLE carries it.
 */
#define TEST_MLE_PTAB          0xE30000ULL
#define TEST_MLE_BASE          0xE40000ULL
#define TEST_MLE_SIZE          0x2000ULL
#define TEST_MLE_HDR_OFF       0x100ULL
#define TEST_HEAP_SIZE         0x1000ULL
#define TEST_DPR               (TXT_DPR_TOP(0x1000000) | TXT_DPR_SIZE(2) | \
                                 TXT_DPR_LOCK)

/*
 * TPM TIS decode area (locality 0; see include/hw/acpi/tpm.h).  The
 * emulator backend the TXT device measures through reuses this same
 * frontend for its locality-4 DRTM commands.
 */
#define TPM_TIS_BASE           0xFED40000U
#define TIS_OFF_ACCESS         0x00
#define TIS_OFF_STS            0x18
#define TIS_OFF_DATA_FIFO      0x24

#define TIS_ACCESS_REQUEST_USE     (1U << 1)
#define TIS_ACCESS_ACTIVE_LOCALITY (1U << 5)

#define TIS_STS_COMMAND_READY      (1U << 6)
#define TIS_STS_TPM_GO             (1U << 5)
#define TIS_STS_DATA_AVAILABLE     (1U << 4)

/*
 * Each TIS locality has its own 4 KiB decode area; locality N starts
 * at TPM_TIS_BASE + (N << 12) (see include/hw/acpi/tpm.h).
 */
#define TIS_LOCTY_OFF(n)           ((uint32_t)(n) << 12)

static uint64_t txt_read64(uint32_t off)
{
    volatile uint64_t *p = (volatile uint64_t *)(TXT_PUBLIC_BASE + off);
    uint64_t v;

    /*
     * One 8-byte MMIO access: 32-bit mode has no 64-bit general-purpose
     * registers, so the value is staged through an XMM register, which
     * keeps the MMIO access a single aligned 8-byte read as the TXT
     * space requires.
     */
    asm volatile("movq %1, %%xmm0\n\t"
                 "movq %%xmm0, %0"
                 : "=m"(v) : "m"(*p) : "xmm0");
    return v;
}

static void txt_write64(uint32_t off, uint64_t v)
{
    volatile uint64_t *p = (volatile uint64_t *)(TXT_PUBLIC_BASE + off);

    /* One 8-byte MMIO write, staged through an XMM register (see
     * txt_read64). */
    asm volatile("movq %0, %%xmm0\n\t"
                 "movq %%xmm0, %1"
                 : : "m"(v), "m"(*p) : "xmm0");
}

static uint32_t tis_readl(uint32_t off)
{
    volatile uint32_t *p = (volatile uint32_t *)(TPM_TIS_BASE + off);

    return *p;
}

static uint8_t tis_readb(uint32_t off)
{
    volatile uint8_t *p = (volatile uint8_t *)(TPM_TIS_BASE + off);

    return *p;
}

static void tis_writeb(uint32_t off, uint8_t v)
{
    volatile uint8_t *p = (volatile uint8_t *)(TPM_TIS_BASE + off);

    *p = v;
}

static void tis_writel(uint32_t off, uint32_t v)
{
    volatile uint32_t *p = (volatile uint32_t *)(TPM_TIS_BASE + off);

    *p = v;
}

static uint32_t tis_readl_at(uint32_t addr)
{
    return *(volatile uint32_t *)addr;
}

static uint8_t tis_readb_at(uint32_t addr)
{
    return *(volatile uint8_t *)addr;
}

static void tis_writeb_at(uint32_t addr, uint8_t v)
{
    *(volatile uint8_t *)addr = v;
}

static void tis_writel_at(uint32_t addr, uint32_t v)
{
    *(volatile uint32_t *)addr = v;
}

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

static void getsec_senter(void)
{
    /*
     * SENTER is GETSEC[4]: opcode 0F 37 with the leaf index in EAX
     * (0F 34 is SMI, not GETSEC).  At CPL0 with CR4.SMXE set and the
     * chipset present this does not raise an exception in the staging
     * state: the helper validates the launch inputs, issues the DRTM
     * measurement, and returns normally with a defined TXT.ERRORCODE
     * (see target/i386/tcg/smx_helper.c).
     */
    asm volatile(".byte 0x0f, 0x37"
                 :
                 : "a"(GETSEC_LEAF_SENTER));
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

/*
 * TPM2_Startup(CLEAR), in the QEMU TPM wire format: tag 0x8001,
 * 4-byte size, 4-byte command code, then the 2-byte startupType.
 * The emulator backend forwards the bytes to swtpm unchanged and the
 * TIS frontend hands the response back through the data FIFO.  The
 * expected response is the 10-byte header with the 16-bit response
 * code (offset 8) equal to zero; it is the same command and
 * response the in-tree tests/qtest tpm_util_startup() uses.
 */
static const uint8_t tpm2_startup_cmd[12] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00,
    0x01, 0x44, 0x00, 0x00,
};

/*
 * Expected TPM2_Startup response header: tag TPM_ST_NO_SESSIONS,
 * responseSize 10, then the response code.  Only the first six bytes
 * are fixed -- the code itself is checked separately, because two
 * values are both correct here:
 *
 *   TPM_RC_SUCCESS    (0x000) if this really is the first Startup, and
 *   TPM_RC_INITIALIZE (0x100) if the TPM is already started.
 *
 * The second is what actually happens under QEMU: the tpm-tis frontend
 * calls tpm_backend_startup_tpm() during realize, which sends CMD_INIT
 * to swtpm and performs TPM2_Startup(CLEAR) before the guest runs.  A
 * guest-issued Startup is therefore a *second* one and is correctly
 * refused.  Asserting on SUCCESS alone made a healthy TPM look broken.
 */
#define TPM2_RESP_HDR_LEN  6
#define TPM2_RC_SUCCESS    0x00000000U
#define TPM2_RC_INITIALIZE 0x00000100U

static const uint8_t tpm2_startup_resp[10] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00,
    0x00, 0x00,
};

static void tpm2_startup(void)
{
    uint32_t sts;
    uint32_t bcount;
    int i;

    /* Request use of locality 0 and enter the command-ready state. */
    tis_writeb(TIS_OFF_ACCESS, TIS_ACCESS_REQUEST_USE);
    tis_writel(TIS_OFF_STS, TIS_STS_COMMAND_READY);

    sts = tis_readl(TIS_OFF_STS);
    bcount = (sts >> 8) & 0xffff;
    if (bcount < sizeof(tpm2_startup_cmd)) {
        fail_msg("TIS: command buffer too small for TPM2_Startup", 16);
        tis_writeb(TIS_OFF_ACCESS, TIS_ACCESS_ACTIVE_LOCALITY);
        return;
    }

    for (i = 0; i < (int)sizeof(tpm2_startup_cmd); i++) {
        tis_writeb(TIS_OFF_DATA_FIFO, tpm2_startup_cmd[i]);
    }
    tis_writeb(TIS_OFF_STS, TIS_STS_TPM_GO);

    /* Wait for the response (up to ~1 s of polling). */
    for (i = 0; i < 1000000; i++) {
        sts = tis_readl(TIS_OFF_STS);
        if (sts & TIS_STS_DATA_AVAILABLE) {
            break;
        }
    }
    if (!(sts & TIS_STS_DATA_AVAILABLE)) {
        fail_msg("TPM2_Startup: the TPM did not respond", 16);
        tis_writeb(TIS_OFF_ACCESS, TIS_ACCESS_ACTIVE_LOCALITY);
        return;
    }

    sts = tis_readl(TIS_OFF_STS);
    bcount = (sts >> 8) & 0xffff;
    if (bcount < sizeof(tpm2_startup_resp)) {
        fail_msg("TPM2_Startup: truncated response", 16);
        tis_writeb(TIS_OFF_ACCESS, TIS_ACCESS_ACTIVE_LOCALITY);
        return;
    }
    if (bcount > 4096) {
        bcount = 4096; /* bound the FIFO drain */
    }

    /*
     * Drain the whole response first, then compare.  Reporting from a
     * buffer (rather than from the first byte that happens to differ)
     * keeps the diagnostic aligned with the response's real offsets --
     * printing from the mismatch point made a failure at, say, index 5
     * look like a bad byte 0.  minilib's printf has no width or
     * zero-pad support, so "%x" is the only usable conversion here.
     */
    {
        uint8_t r[16] = { 0 };
        uint32_t got = 0;
        int bad = -1;

        uint32_t rc;

        for (i = 0; i < (int)bcount; i++) {
            uint8_t b = tis_readb(TIS_OFF_DATA_FIFO);

            if (got < sizeof(r)) {
                r[got] = b;
            }
            /* Only the fixed header is byte-compared; see above. */
            if (bad < 0 && (uint32_t)i < TPM2_RESP_HDR_LEN &&
                b != tpm2_startup_resp[i]) {
                bad = i;
            }
            got++;
        }

        rc = ((uint32_t)r[6] << 24) | ((uint32_t)r[7] << 16) |
             ((uint32_t)r[8] << 8) | (uint32_t)r[9];

        if (bad >= 0 || bcount != sizeof(tpm2_startup_resp) ||
            (rc != TPM2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE)) {
            uint32_t n;

            ml_printf("smx: TPM2_Startup got %u bytes (want %u):",
                      bcount, (uint32_t)sizeof(tpm2_startup_resp));
            for (n = 0; n < got && n < sizeof(r); n++) {
                ml_printf(" %x", r[n]);
            }
            ml_printf("\n");
            if (bad >= 0) {
                ml_printf("smx: first header mismatch at byte %d: "
                          "got 0x%x, want 0x%x\n", bad, r[bad],
                          tpm2_startup_resp[bad]);
            } else {
                ml_printf("smx: unexpected response code 0x%x\n", rc);
            }
            fail_msg("TPM2_Startup: unexpected response", 16);
        } else {
            ml_printf("smx: TPM2_Startup rc=0x%x (%s)\n", rc,
                      rc == TPM2_RC_SUCCESS ? "success"
                                            : "already started");
        }
    }

    /* Release locality 0. */
    tis_writeb(TIS_OFF_ACCESS, TIS_ACCESS_ACTIVE_LOCALITY);
    ml_printf("smx: TPM2_Startup(CLEAR) accepted\n");
}

/*
 * TPM2_PCR_Read, reading one PCR in the SHA-256 bank.
 *
 *   tag TPM_ST_NO_SESSIONS, commandSize 20, TPM_CC_PCR_Read 0x17e,
 *   then a TPML_PCR_SELECTION of one TPMS_PCR_SELECTION:
 *   hashAlg SHA-256 (0x000b), sizeofSelect 3, and a 3-byte pcrSelect
 *   bitmap that pcr_read() fills in before each transmit (bit n%8 of
 *   byte n/8 selects PCR n, e.g. PCR 17 = 00 00 02).
 *
 * The readback takes the last 32 bytes of the response: with the
 * SHA-1 and SHA-256 banks active that is the SHA-256 digest.
 */

/* MLE_HDR_UUID (tboot include/mle.h) in wire order. */
static const uint8_t mle_hdr_uuid[16] = {
    0x5a, 0xac, 0x82, 0x90, 0x6f, 0x47, 0xa7, 0x74,
    0x0f, 0x5c, 0x55, 0xa2, 0xcb, 0x51, 0xb6, 0x42,
};

static uint8_t tpm2_pcrread_cmd[20] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
    0x01, 0x7e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0b,
    0x03, 0x00, 0x00, 0x00,
};

/*
 * Expected PCR 17 (SHA-256 bank) once the DRTM has been established
 * over the SINIT region, which main() fills with acm[i] = (uint8_t)i.
 * The region is deliberately 8 KiB so the measurement spans more than
 * one PTM_HASH_DATA chunk (the control message carries at most 4096
 * bytes), exercising the backend's chunk loop.
 *
 * _TPM_Hash_Start resets the PCR to zero and _TPM_Hash_End extends it
 * with the hash of the data, so the value is
 *
 *   SHA256( 0x00 * 32 || SHA256(region) )
 *
 * Reproduce with:
 *   python3 -c 'import hashlib;p=bytes(i&0xff for i in range(0x2000));\
 *     print(hashlib.sha256(bytes(32)+hashlib.sha256(p).digest()).hexdigest())'
 */
static const uint8_t pcr17_expected[32] = {
    0x1e, 0x8a, 0xc4, 0x3b, 0xa2, 0x02, 0xd1, 0x11,
    0x99, 0xcf, 0x22, 0xa2, 0x8c, 0xc7, 0x6b, 0xa7,
    0x90, 0xef, 0xa3, 0xa2, 0xe0, 0x5e, 0xfe, 0xe7,
    0x3b, 0x5e, 0x6c, 0xc4, 0xd7, 0x89, 0xc7, 0x41,
};

/*
 * Expected PCR 18 (SHA-256 bank): the MLE hash, extended from zero
 * because _TPM_Hash_Start zeroes PCR 18 as well as PCR 17.  The image
 * is mle[i] = (i ^ 0x5A) with the MLE header overwritten at
 * TEST_MLE_HDR_OFF, so the digest covers the header bytes too -- which
 * is correct: the header lives inside the measured image.
 *
 * Reproduce with:
 *   python3 - <<'EOF'
 *   import hashlib, struct
 *   img = bytearray((i ^ 0x5A) & 0xFF for i in range(0x2000))
 *   uuid = bytes([0x5a,0xac,0x82,0x90,0x6f,0x47,0xa7,0x74,
 *                 0x0f,0x5c,0x55,0xa2,0xcb,0x51,0xb6,0x42])
 *   hdr = uuid + struct.pack('<9I', 0x34, 0x00020001, 0x200, 0,
 *                            0, 0x2000, 0x227, 0, 0)
 *   img[0x100:0x100+len(hdr)] = hdr
 *   print(hashlib.sha256(bytes(32) +
 *         hashlib.sha256(bytes(img)).digest()).hexdigest())
 *   EOF
 */
static const uint8_t pcr18_expected[32] = {
    0x48, 0xf9, 0x98, 0x67, 0x42, 0xb8, 0xc2, 0x73,
    0xae, 0x33, 0x8f, 0xf5, 0xb9, 0x1d, 0xbe, 0x73,
    0x6f, 0xea, 0x75, 0x23, 0x52, 0xe1, 0x2e, 0xbc,
    0x56, 0x5f, 0xf6, 0x6f, 0x13, 0xa0, 0x3f, 0xe7,
};

/*
 * Run one TPM command through the TIS FIFO of the locality whose
 * decode area starts at @tis_base (TPM_TIS_BASE for locality 0) and
 * copy up to @out_len response bytes into @out.  Returns the response
 * length, or 0 on failure.  Shares the sequence tpm2_startup() uses:
 * request the locality, go command-ready, push the command, TPM_GO,
 * poll for dataAvailable, drain.
 */
static uint32_t tis_transmit(uint32_t tis_base, const uint8_t *cmd,
                             uint32_t cmd_len, uint8_t *out,
                             uint32_t out_len)
{
    uint32_t sts;
    uint32_t bcount;
    uint32_t i;

    tis_writeb_at(tis_base + TIS_OFF_ACCESS, TIS_ACCESS_REQUEST_USE);
    tis_writel_at(tis_base + TIS_OFF_STS, TIS_STS_COMMAND_READY);

    sts = tis_readl_at(tis_base + TIS_OFF_STS);
    if (((sts >> 8) & 0xffff) < cmd_len) {
        tis_writeb_at(tis_base + TIS_OFF_ACCESS,
                      TIS_ACCESS_ACTIVE_LOCALITY);
        return 0;
    }
    for (i = 0; i < cmd_len; i++) {
        tis_writeb_at(tis_base + TIS_OFF_DATA_FIFO, cmd[i]);
    }
    tis_writeb_at(tis_base + TIS_OFF_STS, TIS_STS_TPM_GO);

    for (i = 0; i < 1000000; i++) {
        sts = tis_readl_at(tis_base + TIS_OFF_STS);
        if (sts & TIS_STS_DATA_AVAILABLE) {
            break;
        }
    }
    if (!(sts & TIS_STS_DATA_AVAILABLE)) {
        tis_writeb_at(tis_base + TIS_OFF_ACCESS,
                      TIS_ACCESS_ACTIVE_LOCALITY);
        return 0;
    }

    sts = tis_readl_at(tis_base + TIS_OFF_STS);
    bcount = (sts >> 8) & 0xffff;
    if (bcount > 4096) {
        bcount = 4096;
    }
    for (i = 0; i < bcount; i++) {
        uint8_t b = tis_readb_at(tis_base + TIS_OFF_DATA_FIFO);

        if (i < out_len) {
            out[i] = b;
        }
    }
    tis_writeb_at(tis_base + TIS_OFF_ACCESS, TIS_ACCESS_ACTIVE_LOCALITY);

    return bcount;
}

/*
 * Build the step-c launch inputs in guest RAM: an MLE image with its
 * header, a 3-level page table mapping that image flat at linear 0, and
 * a TXT heap whose os_sinit_data points at both.
 *
 * Heap layout, each section preceded by a u64 size that includes the
 * size word itself (tboot include/txt/heap.h):
 *   [bios_data_size=0x10][8 bytes]
 *   [os_mle_data_size=0x10][8 bytes]
 *   [os_sinit_data_size=0x28][version, flags, mle_ptab, mle_size,
 *                             mle_hdr_base]
 */
static void setup_mle(void)
{
    volatile uint8_t *mle = (volatile uint8_t *)(uintptr_t)TEST_MLE_BASE;
    volatile uint64_t *pdpt = (volatile uint64_t *)(uintptr_t)TEST_MLE_PTAB;
    volatile uint64_t *pd =
        (volatile uint64_t *)(uintptr_t)(TEST_MLE_PTAB + 0x1000);
    volatile uint64_t *pt =
        (volatile uint64_t *)(uintptr_t)(TEST_MLE_PTAB + 0x2000);
    volatile uint8_t *heap = (volatile uint8_t *)(uintptr_t)TEST_HEAP_BASE;
    volatile uint64_t *os_sinit;
    volatile uint32_t *hdr;
    uint32_t i;

    /* MLE image: a recognisable pattern, distinct from the ACM's. */
    for (i = 0; i < (uint32_t)TEST_MLE_SIZE; i++) {
        mle[i] = (uint8_t)(i ^ 0x5A);
    }

    /* MLE header at linear TEST_MLE_HDR_OFF, inside the measured image. */
    for (i = 0; i < 16; i++) {
        mle[TEST_MLE_HDR_OFF + i] = mle_hdr_uuid[i];
    }
    hdr = (volatile uint32_t *)(uintptr_t)(TEST_MLE_BASE +
                                           TEST_MLE_HDR_OFF + 16);
    hdr[0] = 0x34;               /* length */
    hdr[1] = 0x00020001;         /* version 2.1 */
    hdr[2] = 0x200;              /* entry_point */
    hdr[3] = 0;                  /* first_valid_page */
    hdr[4] = 0;                  /* mle_start_off */
    hdr[5] = (uint32_t)TEST_MLE_SIZE; /* mle_end_off */
    hdr[6] = 0x00000227;         /* capabilities */
    hdr[7] = 0;                  /* cmdline_start_off */
    hdr[8] = 0;                  /* cmdline_end_off */

    /* Flat mapping: linear 0 -> TEST_MLE_BASE.  Present bit only. */
    for (i = 0; i < 0x200; i++) {
        pdpt[i] = 0;
        pd[i] = 0;
        pt[i] = 0;
    }
    pdpt[0] = (TEST_MLE_PTAB + 0x1000) | 1;
    pd[0] = (TEST_MLE_PTAB + 0x2000) | 1;
    for (i = 0; i < (uint32_t)(TEST_MLE_SIZE / 0x1000); i++) {
        pt[i] = (TEST_MLE_BASE + (uint64_t)i * 0x1000) | 1;
    }

    /* Heap sections. */
    for (i = 0; i < 0x48; i++) {
        heap[i] = 0;
    }
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x00) = 0x10;
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x10) = 0x10;
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x20) = 0x28;

    os_sinit = (volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x28);
    *(volatile uint32_t *)os_sinit = 6;                 /* version */
    *((volatile uint32_t *)os_sinit + 1) = 0;           /* flags */
    os_sinit[1] = TEST_MLE_PTAB;                        /* mle_ptab */
    os_sinit[2] = TEST_MLE_SIZE;                        /* mle_size */
    os_sinit[3] = TEST_MLE_HDR_OFF;                     /* mle_hdr_base */

    ml_printf("smx: MLE image, page table and heap built\n");
}

/*
 * Read one PCR (@pcr) as SHA-256 into @digest.  Returns 1 on success.
 * The TPM2_PCR_Read response tail is the 32-byte digest, so it is
 * taken from the end of the response rather than by walking the
 * structure.
 */
static int pcr_read(int pcr, uint8_t *digest)
{
    uint8_t resp[128];
    uint32_t n;

    /* pcrSelect is a 3-byte bitmap; PCR n is bit n%8 of byte n/8. */
    tpm2_pcrread_cmd[17] = 0;
    tpm2_pcrread_cmd[18] = 0;
    tpm2_pcrread_cmd[19] = 0;
    tpm2_pcrread_cmd[17 + pcr / 8] = (uint8_t)(1u << (pcr % 8));
    n = tis_transmit(TPM_TIS_BASE, tpm2_pcrread_cmd,
                     sizeof(tpm2_pcrread_cmd), resp, sizeof(resp));
    uint32_t rc;
    uint32_t i;

    if (n < 10 + 32) {
        ml_printf("smx: PCR%d_Read returned %u bytes\n", pcr, n);
        return 0;
    }
    rc = ((uint32_t)resp[6] << 24) | ((uint32_t)resp[7] << 16) |
         ((uint32_t)resp[8] << 8) | (uint32_t)resp[9];
    if (rc != 0) {
        ml_printf("smx: PCR%d_Read rc=0x%x\n", pcr, rc);
        return 0;
    }
    for (i = 0; i < 32; i++) {
        digest[i] = resp[n - 32 + i];
    }
    return 1;
}

static int pcr_is(const uint8_t *digest, const uint8_t *want)
{
    int i;

    for (i = 0; i < 32; i++) {
        if (digest[i] != want[i]) {
            return 0;
        }
    }
    return 1;
}

static void pcr_print(const char *what, const uint8_t *d)
{
    int i;

    ml_printf("smx: PCR %s:", what);
    for (i = 0; i < 32; i++) {
        ml_printf(" %x", d[i]);
    }
    ml_printf("\n");
}

/*
 * TPM_RC_LOCALITY (TPM 2.0 Part 1): the command was refused because
 * the current TIS locality does not permit it.  Response codes are
 * big-endian 32-bit values at offset 6 of the QEMU TPM response
 * header (see backends/tpm/tpm_int.h), so 0x907 comes back as
 * 0x00000907.
 */
#define TPM_RC_LOCALITY        0x00000907U

/*
 * TPM2_PCR_Extend in the QEMU/swtpm wire format: tag 0x8002 (one
 * authorization session), 4-byte big-endian length and command code,
 * the PCR handle, an empty TPM_RS_PW auth session, and a
 * TPML_DIGEST_VALUES carrying one SHA-256 digest.  The byte-exact
 * layout (including the 13-byte empty auth session) was verified
 * against swtpm in the M0 locality spike.
 */
static const uint8_t pcrextend_fixed[10] = {
    0x80, 0x02, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x01, 0x82,
};
static const uint8_t pcrextend_mid[19] = {
    /* empty TPM_RS_PW auth session (13 bytes) */
    0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00,
    0x00, 0x00, 0x00,
    /* then TPML_DIGEST_VALUES: one digest, SHA-256 */
    0x00, 0x00, 0x00, 0x01, 0x00, 0x0B,
};
static uint8_t tpm2_pcrextend_cmd[65];

static void copy_bytes(uint8_t *dst, const uint8_t *src, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

static void pcrextend_build(uint32_t pcr, const uint8_t *digest)
{
    copy_bytes(tpm2_pcrextend_cmd, pcrextend_fixed, 10);
    tpm2_pcrextend_cmd[10] = (uint8_t)(pcr >> 24);
    tpm2_pcrextend_cmd[11] = (uint8_t)(pcr >> 16);
    tpm2_pcrextend_cmd[12] = (uint8_t)(pcr >> 8);
    tpm2_pcrextend_cmd[13] = (uint8_t)pcr;
    copy_bytes(tpm2_pcrextend_cmd + 14, pcrextend_mid, 19);
    copy_bytes(tpm2_pcrextend_cmd + 33, digest, 32);
}

/*
 * TPM2_PCR_Reset in the same format: handle plus the empty auth
 * session, no body.
 */
static const uint8_t pcrreset_fixed[10] = {
    0x80, 0x02, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x01, 0x3D,
};
static const uint8_t pcrreset_mid[13] = {
    0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00,
    0x00, 0x00, 0x00,
};
static uint8_t tpm2_pcrreset_cmd[27];

static void pcrreset_build(uint32_t pcr)
{
    copy_bytes(tpm2_pcrreset_cmd, pcrreset_fixed, 10);
    tpm2_pcrreset_cmd[10] = (uint8_t)(pcr >> 24);
    tpm2_pcrreset_cmd[11] = (uint8_t)(pcr >> 16);
    tpm2_pcrreset_cmd[12] = (uint8_t)(pcr >> 8);
    tpm2_pcrreset_cmd[13] = (uint8_t)pcr;
    copy_bytes(tpm2_pcrreset_cmd + 14, pcrreset_mid, 13);
}

/*
 * Send @cmd through the TIS FIFO of the locality at @tis_base and
 * return its 32-bit response code, or 0xFFFF when no usable response
 * came back.  The response code sits at offset 6 of the QEMU TPM
 * response header.
 */
static uint32_t tpm2_cmd_rc(uint32_t tis_base, const uint8_t *cmd,
                            uint32_t cmd_len)
{
    uint8_t resp[128];
    uint32_t n = tis_transmit(tis_base, cmd, cmd_len, resp, sizeof(resp));

    if (n < 10) {
        return 0xFFFF;
    }
    return ((uint32_t)resp[6] << 24) | ((uint32_t)resp[7] << 16) |
         ((uint32_t)resp[8] << 8) | (uint32_t)resp[9];
}

int main(void)
{
    uint32_t cr4;
    uint32_t caps;
    uint32_t eax = 0, ebx = 0, ecx = 0;
    uint32_t type;
    int index;
    int i;

    ml_printf("smx: start\n");
    idt_install();
    ml_printf("smx: idt installed\n");

    /* Enable SSE before any txt_read64()/txt_write64() (see above). */
    write_cr4(read_cr4() | CR4_OSFXSR_MASK | CR4_OSXMMEXCPT_MASK);
    ml_printf("smx: SSE enabled, cr4=0x%x\n", read_cr4());

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
     * 2. GETSEC[CAPABILITIES]: the static leaf bits are set and the
     *    chipset-present bit is set (this test runs with
     *    -machine txt=on).  ENTERACCS / extended leaves are not
     *    advertised.
     */
    ml_printf("smx: GETSEC[CAPABILITIES] ...\n");
    caps = getsec_capabilities(0);
    ml_printf("smx: caps=0x%x\n", caps);
    if (caps != (GETSEC_CAP_STATIC | GETSEC_CAP_CHIPSET_PRESENT)) {
        ml_printf("FAIL: GETSEC[CAPABILITIES] = 0x%x, expected 0x%x\n",
                  caps, GETSEC_CAP_STATIC | GETSEC_CAP_CHIPSET_PRESENT);
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

    /*
     * 4. Fresh chipset state: nothing is latched at boot, so STS,
     *    ERRORCODE and the SINIT/HEAP/DPR registers all read zero.
     */
    if (txt_read64(TXT_OFF_STS) != 0) {
        fail_msg("fresh STS is not zero", 32);
    }
    if (txt_read64(TXT_OFF_ERRORCODE) != 0) {
        fail_msg("fresh ERRORCODE is not zero", 32);
    }
    if (txt_read64(TXT_OFF_SINIT_BASE) != 0 ||
        txt_read64(TXT_OFF_SINIT_SIZE) != 0) {
        fail_msg("fresh SINIT_BASE/SIZE are not zero", 32);
    }
    if (txt_read64(TXT_OFF_HEAP_BASE) != 0 ||
        txt_read64(TXT_OFF_HEAP_SIZE) != 0) {
        fail_msg("fresh HEAP_BASE/SIZE are not zero", 32);
    }
    if (txt_read64(TXT_OFF_DPR) != 0) {
        fail_msg("fresh DPR is not zero", 32);
    } else {
        ml_printf("PASS: fresh chipset state is all zero\n");
    }

    /*
     * 5. Bring the TPM out of its "needs startup" state with a
     *    guest-side TPM2_Startup(CLEAR) over the TIS.  This is only
     *    a prerequisite for the DRTM commands the staged SENTER
     *    issues: verifying the PCR *values* needs a guest-side TPM2
     *    driver over the TIS, which is the next slice -- do not
     *    attempt it here.
     */
    tpm2_startup();

    /*
     * 6. SENTER with the SINIT/HEAP launch inputs unset: the first
     *    precondition (SINIT region) must fail and record
     *    TXT_ERR_SINIT_REGION_INVALID without measuring anything,
     *    and STS.SENTER_DONE must stay clear.  Zero ERRORCODE first
     *    so the readback proves SENTER wrote the code.
     */
    txt_write64(TXT_OFF_ERRORCODE, 0);
    ml_printf("smx: SENTER, SINIT/HEAP unset ...\n");
    getsec_senter();
    {
        uint64_t ec = txt_read64(TXT_OFF_ERRORCODE);
        uint64_t sts = txt_read64(TXT_OFF_STS);

        ml_printf("smx: ERRORCODE=0x%llx STS=0x%llx\n",
                  (unsigned long long)ec, (unsigned long long)sts);
        if (ec != TXT_ERR_SINIT_REGION_INVALID) {
            fail_msg("SENTER without launch inputs: wrong ERRORCODE", 64);
        }
        if (sts & TXT_STS_SENTER_DONE) {
            fail_msg("SENTER without launch inputs: SENTER_DONE set", 64);
        }
        if (ec == TXT_ERR_SINIT_REGION_INVALID &&
            !(sts & TXT_STS_SENTER_DONE)) {
            ml_printf("PASS: SENTER without launch inputs records "
                      "0x%llx\n", (unsigned long long)ec);
        }
    }

    /*
     * 7. Program the launch inputs: the DPR range [0xE00000,
     *    0x1000000) (TOP 0x1000000, 2 MiB blocks, locked -- DPR is
     *    write-once, so this is the one chance), the 4 KiB SINIT
     *    ACM region at 0xE10000 (inside the DPR), and the 4 KiB heap
     *    at 0xE11000.  Give the SINIT region deterministic content.
     */
    {
        volatile uint8_t *acm = (volatile uint8_t *)TEST_SINIT_BASE;

        setup_mle();

        txt_write64(TXT_OFF_DPR, TEST_DPR);
        if (txt_read64(TXT_OFF_DPR) != TEST_DPR) {
            fail_msg("DPR readback mismatch after programming", 64);
        }
        for (i = 0; i < (int)TEST_SINIT_SIZE; i++) {
            acm[i] = (uint8_t)i;
        }
        txt_write64(TXT_OFF_SINIT_BASE, TEST_SINIT_BASE);
        txt_write64(TXT_OFF_SINIT_SIZE, TEST_SINIT_SIZE);
        txt_write64(TXT_OFF_HEAP_BASE, TEST_HEAP_BASE);
        txt_write64(TXT_OFF_HEAP_SIZE, TEST_HEAP_SIZE);
    }
    ml_printf("smx: SINIT/HEAP/DPR programmed\n");

    /*
     * 8. SENTER with valid launch inputs: the preconditions pass, the
     *    DRTM is established over the SINIT region with the TIS hash
     *    signals (which reset PCRs 17-22 and extend PCR 17 with the
     *    region's hash), and the staged launch stops short of the MLE
     *    transfer with LAUNCH_INCOMPLETE.  STS.SENTER_DONE must still
     *    be clear.  The PCR 17 value itself is checked in step 9.
     */
    txt_write64(TXT_OFF_ERRORCODE, 0);
    ml_printf("smx: SENTER, launch inputs set ...\n");
    getsec_senter();
    {
        uint64_t ec = txt_read64(TXT_OFF_ERRORCODE);
        uint64_t sts = txt_read64(TXT_OFF_STS);

        ml_printf("smx: ERRORCODE=0x%llx STS=0x%llx\n",
                  (unsigned long long)ec, (unsigned long long)sts);
        if (ec != TXT_ERR_LAUNCH_INCOMPLETE) {
            fail_msg("SENTER with valid inputs: wrong ERRORCODE", 128);
        }
        if (sts & TXT_STS_SENTER_DONE) {
            fail_msg("SENTER with valid inputs: SENTER_DONE set", 128);
        }
        if (ec == TXT_ERR_LAUNCH_INCOMPLETE &&
            !(sts & TXT_STS_SENTER_DONE)) {
            ml_printf("PASS: SENTER with valid inputs records "
                      "0x%llx (launch incomplete, staged)\n",
                      (unsigned long long)ec);
        }
    }

    /*
     * 9. The measurement itself: PCR 17 must have moved off its
     *    power-on all-ones value to exactly the extend-from-zero of
     *    the region's hash.  This is the assertion that proves a DRTM
     *    actually happened -- the ERRORCODE checks above only show
     *    that SENTER ran.  _TPM_Hash_Start resets the PCR, so an
     *    all-ones result means the sequence was a silent no-op (which
     *    is what happens if locality 4 was never applied).
     */
    {
        uint8_t d[32];
        static const uint8_t all_ones[32] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };

        if (!pcr_read(17, d)) {
            fail_msg("PCR 17 could not be read back", 256);
        } else if (pcr_is(d, all_ones)) {
            pcr_print("17 after SENTER", d);
            fail_msg("PCR 17 still all-ones: the DRTM hash sequence "
                     "did not take effect", 256);
        } else if (!pcr_is(d, pcr17_expected)) {
            pcr_print("17 after SENTER", d);
            pcr_print("17 expected   ", pcr17_expected);
            fail_msg("PCR 17 does not match the expected DRTM value", 256);
        } else {
            ml_printf("PASS: PCR 17 holds the expected DRTM "
                      "measurement\n");
        }
    }

    /*
     * 10. PCR 18 must hold the MLE hash (spec step c), extended from
     *     zero because _TPM_Hash_Start zeroed it along with PCR 17.
     *     This is the measurement of the image the page table maps,
     *     not of the SINIT region checked in step 9.
     */
    {
        uint8_t d[32];

        if (!pcr_read(18, d)) {
            fail_msg("PCR 18 could not be read back", 512);
        } else if (!pcr_is(d, pcr18_expected)) {
            pcr_print("18 after SENTER", d);
            pcr_print("18 expected   ", pcr18_expected);
            fail_msg("PCR 18 does not match the expected MLE hash", 512);
        } else {
            ml_printf("PASS: PCR 18 holds the expected MLE hash\n");
        }
    }

    /*
     * 11. Locality enforcement: the measurement that landed in steps
     *     9-10 was issued by the device at locality 4; this step
     *     proves the guest cannot bypass that.  First, the TPM itself
     *     must refuse DRTM-PCR manipulation from locality 0 with
     *     TPM_RC_LOCALITY: a TPM2_PCR_Extend of a DRTM PCR and a
     *     TPM2_PCR_Reset of one both fail there.  (DRTM PCRs 17-22
     *     are not command-resettable at any locality, which is
     *     exactly why SENTER uses the TIS hash sequence, whose
     *     _TPM_Hash_Start zeroes them, instead of PCR_Reset.)
     *     Second, locality 4 itself must be unreachable from the
     *     guest: it is the SENTER/DRTM locality, and like real
     *     chipset behaviour the TIS frontend drops guest writes to
     *     the locality-4 decode area (hw/tpm/tpm_tis_common.c), so a
     *     guest REQUEST_USE there is never granted.  All of the
     *     refused commands change no state, so the PCR 17/18 values
     *     asserted above are left untouched.  The final check is a
     *     positive control: an ordinary PCR is extendable from
     *     locality 0, so the TPM_RC_LOCALITY refusals are
     *     specifically about DRTM locality protection, not the
     *     transport.
     */
    {
        uint32_t rc;

        pcrextend_build(18, pcr18_expected);
        rc = tpm2_cmd_rc(TPM_TIS_BASE, tpm2_pcrextend_cmd,
                         sizeof(tpm2_pcrextend_cmd));
        if (rc != TPM_RC_LOCALITY) {
            ml_printf("smx: TPM2_PCR_Extend(18) at locality 0 rc=0x%x\n",
                      rc);
            fail_msg("TPM2_PCR_Extend(18) at locality 0 was not refused "
                     "with TPM_RC_LOCALITY", 1024);
        } else {
            ml_printf("PASS: TPM2_PCR_Extend(18) at locality 0 refused "
                      "(rc=0x%x)\n", rc);
        }

        pcrreset_build(17);
        rc = tpm2_cmd_rc(TPM_TIS_BASE, tpm2_pcrreset_cmd,
                         sizeof(tpm2_pcrreset_cmd));
        if (rc != TPM_RC_LOCALITY) {
            ml_printf("smx: TPM2_PCR_Reset(17) at locality 0 rc=0x%x\n", rc);
            fail_msg("TPM2_PCR_Reset(17) at locality 0 was not refused "
                     "with TPM_RC_LOCALITY", 1024);
        } else {
            ml_printf("PASS: TPM2_PCR_Reset(17) at locality 0 refused "
                      "(rc=0x%x)\n", rc);
        }

        {
            uint32_t access;
            uint32_t i;
            int granted = 0;

            tis_writeb_at(TPM_TIS_BASE + TIS_LOCTY_OFF(4) + TIS_OFF_ACCESS,
                          TIS_ACCESS_REQUEST_USE);
            for (i = 0; i < 100000; i++) {
                access = tis_readl_at(TPM_TIS_BASE + TIS_LOCTY_OFF(4) +
                                     TIS_OFF_ACCESS);
                if (access & TIS_ACCESS_ACTIVE_LOCALITY) {
                    granted = 1;
                    break;
                }
            }
            if (granted) {
                fail_msg("locality 4 became active for the guest "
                         "(hardware-only locality)", 1024);
            } else {
                ml_printf("PASS: guest cannot select locality 4 "
                          "(ACCESS=0x%x)\n", access);
            }
        }

        pcrextend_build(7, pcr18_expected);
        rc = tpm2_cmd_rc(TPM_TIS_BASE, tpm2_pcrextend_cmd,
                         sizeof(tpm2_pcrextend_cmd));
        if (rc != 0) {
            ml_printf("smx: TPM2_PCR_Extend(7) at locality 0 rc=0x%x\n", rc);
            fail_msg("TPM2_PCR_Extend(7) at locality 0 was not accepted "
                     "(control)", 1024);
        } else {
            ml_printf("PASS: TPM2_PCR_Extend(7) at locality 0 accepted "
                      "(control)\n");
        }
    }

    if (!main_fail) {
        ml_printf("test-smx-getsec: all tests passed\n");
    }
    return main_fail;
}
