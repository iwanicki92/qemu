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
#define GETSEC_LEAF_SEXIT        5
#define GETSEC_LEAF_PARAMETERS   6

/*
 * IA32_FEATURE_CONTROL (MSR 0x3a) bits used by the step 15
 * assertions.  The values mirror the FEATURE_CONTROL_* defines in
 * target/i386/cpu.h, restated here because this binary links no
 * QEMU headers.
 */
#define MSR_IA32_FEATURE_CONTROL 0x3a
#define FC_LOCKED            (1U << 0)
#define FC_VMXON_IN_SMX      (1U << 1)
/*
 * The two SENTER enable fields together: bits 14:8 enable the
 * individual functions and bit 15 enables SENTER globally (tboot:
 * SENTER_PARAM_CTL | ENABLE_SENTER).
 */
#define FC_SENTER_ENABLE     0x0000ff00U
#define FC_RESERVED_BIT3     (1U << 3)
#define FC_RESERVED_BIT16    (1U << 16)
#define FC_SGX               (1U << 18)

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
#define TXT_PRIVATE_BASE       0xFED20000U
#define TXT_OFF_STS            0x000
#define TXT_OFF_ERRORCODE      0x030
#define TXT_OFF_SINIT_BASE     0x270
#define TXT_OFF_SINIT_SIZE     0x278
#define TXT_OFF_MLE_JOIN       0x290
#define TXT_OFF_RLP_WAKEUP     0x2a0
#define TXT_OFF_HEAP_BASE      0x300
#define TXT_OFF_HEAP_SIZE      0x308
#define TXT_OFF_DPR            0x330

#define TXT_OFF_E2STS          0x8f0

#define TXT_STS_SENTER_DONE    (1ULL << 0)
#define TXT_STS_SEXIT_DONE     (1ULL << 1)
#define TXT_STS_MEM_CONFIG_LOCK (1ULL << 6)
#define TXT_STS_PRIVATE_OPEN   (1ULL << 7)
#define TXT_STS_LOCALITY1_OPEN (1ULL << 15)
#define TXT_STS_LOCALITY2_OPEN (1ULL << 16)
#define TXT_E2STS_SECRET_STS   (1ULL << 1)

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
#define TXT_ERR_HEAP_INVALID         0x80030001ULL
#define TXT_ERR_MEASURE_FAILED       0x80050001ULL
#define TXT_ERR_PMR_INVALID          0x80080001ULL
#define TXT_ERR_ACM_INVALID          0x80060001ULL

/*
 * VT-d PMR (Protected Memory Region) register access.  The q35 host
 * bridge exposes the IOMMU CSR region at 0xFED90000 in system
 * memory (it is a sysbus device, not PCI).  The values mirror
 * hw/i386/intel_iommu_internal.h, restated here because this binary
 * links no QEMU headers.  The machine runs with txt=on, so CAP
 * advertises PLMR/PHMR; a PMR-valid SENTER programs the window from
 * the os_sinit data (the 16 MiB low window of this fixture) before
 * establishing the measured environment, and SEXIT releases it.
 */
#define VTD_CSR_BASE            0xfed90000UL
#define VTD_CSR_CAP             0x8
#define VTD_CSR_PMEN            0x64
#define VTD_CSR_PLMBASE         0x68
#define VTD_CSR_PLMLIMIT        0x6c
/* 16 MiB window: last address of [0, 0x1000000) is 0x1000000 - 1. */
#define VTD_PMR_LIMIT_16M       0xffffffU
#define VTD_CAP_PLMR            (1U << 5)
#define VTD_CAP_PHMR            (1U << 6)
#define VTD_PMEN_EPM            (1U << 31)
#define VTD_PMEN_PRS            (1U << 0)

/*
 * The iommu-testdev (0x1b36:0x0005) DMA engine: the test arms a
 * 4-byte write to GVA and a read back from GPA, then polls the
 * result register.  A translation the IOMMU refuses reports
 * ITD_ERR_TX_FAIL immediately; the BUSY poll only bounds the
 * normal path, so a blocked transfer cannot hang the test.  The
 * values mirror hw/misc/iommu-testdev.h.
 */
#define ITD_VENDOR              0x1b36
#define ITD_DEVICE              0x0005
#define ITD_REG_TRIGGERING      0x00
#define ITD_REG_GVA_LO          0x04
#define ITD_REG_GVA_HI          0x08
#define ITD_REG_LEN             0x0c
#define ITD_REG_RESULT          0x10
#define ITD_REG_DBELL           0x14
#define ITD_REG_ATTRS           0x18
#define ITD_REG_GPA_LO          0x1c
#define ITD_REG_GPA_HI          0x20
#define ITD_DBELL_ARM           0x1
#define ITD_RESULT_IDLE         0xffffffffU
#define ITD_RESULT_BUSY         0xfffffffeU
#define ITD_ERR_TX_FAIL         0xdead0002U

/*
 * Launch inputs for SENTER: an 8 KiB ACM in a 16 KiB SINIT slot at
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
#ifdef TEST_TXT_MLE_UNALIGNED
/*
 * Not page aligned: the SDG's MLE Size is in bytes and needs no
 * alignment; the final partial page is measured up to MLE Size.
 */
#define TEST_MLE_SIZE          0x1800ULL
#else
#define TEST_MLE_SIZE          0x2000ULL
#endif
#define TEST_MLE_HDR_OFF       0x100ULL
#define TEST_HEAP_SIZE         0x1000ULL
#ifdef TEST_TXT_TPM2_LOG
/* Outside the 16 MiB PMR and not page aligned: both are permitted. */
#define TEST_EVENT_LOG_BASE    0x110014cULL
#define TEST_EVENT_LOG_SIZE    0x1000U
typedef volatile uint8_t txt_guest_u8;   /* SENTER accesses this guest RAM. */
typedef volatile uint32_t txt_guest_u32; /* SENTER accesses this guest RAM. */
typedef volatile uint64_t txt_guest_u64; /* SENTER accesses this guest RAM. */
#endif

/*
 * os_sinit_data carries capabilities only in the MONITOR-wake build;
 * the default section stops before that field, which leaves
 * GETSEC[WAKEUP] as the negotiated RLP wake mechanism.
 */
#ifdef TEST_TXT_TPM2_LOG
#define TEST_OS_SINIT_SIZE     0x90
#elif defined(TEST_TXT_MONITOR_WAKE)
#define TEST_OS_SINIT_SIZE     0x60
#else
#define TEST_OS_SINIT_SIZE     0x48
#endif
#define TEST_SINIT_MLE_OFF     (0x20 + TEST_OS_SINIT_SIZE)
/* sinit_mle_data.rlp_wakeup_addr, past the section's u64 size prefix */
#define SINIT_MLE_OFF_RLP_WAKEUP 0x78

/*
 * Offsets inside the synthetic SINIT ACM fixture (see setup_acm()).
 * Header offsets are from tboot's acm_hdr_t, the info table from
 * acm_info_table_t, the chipset id list from acm_chipset_id_list_t.
 */
#define ACM_OFF_MODULE_TYPE     0x00   /* u16 */
#define ACM_OFF_MODULE_SUBTYPE  0x02   /* u16 */
#define ACM_OFF_HEADER_LEN      0x04   /* u32, dwords */
#define ACM_OFF_MODULE_VENDOR   0x10   /* u32 */
#define ACM_OFF_SIZE            0x18   /* u32, dwords */
#define ACM_OFF_GDT_LIMIT       0x28   /* u32 */
#define ACM_OFF_GDT_BASE        0x2c   /* u32 */
#define ACM_OFF_SEG_SEL         0x30   /* u32 */
#define ACM_OFF_ENTRY_POINT     0x34   /* u32 */
/*
 * The GDT the ACM header describes, placed in the fixture body just
 * past the chipset id list: null, flat 32-bit code, flat 32-bit data.
 * seg_sel picks the code entry, and the MLE guide's data selector is
 * seg_sel + 8, which is the third entry -- so the limit has to cover
 * all three.
 */
#define ACM_GDT_OFF             0x520
#define ACM_GDT_SIZE            0x18
#define ACM_GDT_LIMIT           (ACM_GDT_SIZE - 1)
#define ACM_SEG_SEL             0x08
#define ACM_OFF_SCRATCH_SIZE    0x7c   /* u32, dwords */
#define ACM_HEADER_LEN          161    /* dwords */
#define ACM_SCRATCH_SIZE        143    /* dwords */
/* (header_len + scratch_size) * 4 */
#define ACM_INFO_OFF            0x4c0
#define ACM_INFO_OFF_TYPE       (ACM_INFO_OFF + 0x10)  /* u8 */
#define ACM_INFO_OFF_VERSION    (ACM_INFO_OFF + 0x11)  /* u8 */
#define ACM_INFO_OFF_LENGTH     (ACM_INFO_OFF + 0x12)  /* u16 */
#define ACM_INFO_OFF_ID_LIST    (ACM_INFO_OFF + 0x14)  /* u32 */
#define ACM_ID_LIST_OFF         0x500
#define ACM_ID_OFF_FLAGS        (ACM_ID_LIST_OFF + 0x04)  /* u32 */
#define ACM_ID_OFF_VENDOR       (ACM_ID_LIST_OFF + 0x08)  /* u16 */
#define ACM_ID_OFF_DEVICE       (ACM_ID_LIST_OFF + 0x0a)  /* u16 */
#define ACM_ID_OFF_REVISION     (ACM_ID_LIST_OFF + 0x0c)  /* u16 */

/* The chipset the fixture claims to be for: TXT.DIDVID's default. */
#define ACM_CHIPSET_VENDOR      0x8086
#define ACM_CHIPSET_DEVICE      0x29c0
#define ACM_CHIPSET_REVISION    0x0000
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
     * Stage a single aligned 8-byte MMIO access through XMM in 32-bit
     * mode. Firmware may also use separate aligned 32-bit halves.
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

static void getsec_senter_size(uint32_t acm_size)
{
    /*
     * SENTER is GETSEC[4]: EAX=leaf, EBX=ACM base, ECX=actual ACM
     * size, EDX=0. Rejected launches return with TXT.ERRORCODE.
     */
    asm volatile(".byte 0x0f, 0x37"
                 :
                 : "a"(GETSEC_LEAF_SENTER), "b"((uint32_t)TEST_SINIT_BASE),
                   "c"(acm_size), "d"(0)
                 : "memory");
}

static void getsec_senter(void)
{
    getsec_senter_size(TEST_SINIT_SIZE);
}

static uint64_t msr_read64(uint32_t index)
{
    uint32_t eax, edx;

    asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(index));
    return ((uint64_t)edx << 32) | (uint64_t)eax;
}

static void msr_write32(uint32_t index, uint32_t val)
{
    /*
     * The high 32 bits are always zero: the bits asserted here all
     * live in the low half of the register.
     */
    asm volatile("wrmsr" :: "a"(val), "d"((uint32_t)0), "c"(index));
}

static uint32_t port_inl(uint32_t port)
{
    uint32_t v;

    asm volatile("inl %%dx, %0" : "=a"(v) : "d"(port));
    return v;
}

static void port_outl(uint32_t port, uint32_t v)
{
    asm volatile("outl %%eax, %%dx" :: "a"(v), "d"(port));
}

static void port_outb(uint32_t port, uint32_t v)
{
    asm volatile("outb %%al, %%dx" :: "a"(v), "d"(port));
}

/* PCI config access on bus 0; the test's devices are all on bus 0. */
static uint32_t pci_cfg_readl(uint32_t devfn, uint32_t off)
{
    port_outl(0xcf8, 0x80000000U | (devfn << 8) | (off & 0xfc));
    return port_inl(0xcfc);
}

static void pci_cfg_writel(uint32_t devfn, uint32_t off, uint32_t v)
{
    port_outl(0xcf8, 0x80000000U | (devfn << 8) | (off & 0xfc));
    port_outl(0xcfc, v);
}

static uint32_t vtd_readl(uint32_t off)
{
    /* volatile: MMIO read of an IOMMU CSR register. */
    return *(volatile uint32_t *)(uintptr_t)(VTD_CSR_BASE + off);
}

static uint32_t itd_readl(uint32_t bar, uint32_t off)
{
    /* volatile: MMIO read of a test device register. */
    return *(volatile uint32_t *)(uintptr_t)(bar + off);
}

static void itd_writel(uint32_t bar, uint32_t off, uint32_t v)
{
    /* volatile: MMIO write of a test device register. */
    *(volatile uint32_t *)(uintptr_t)(bar + off) = v;
}

/*
 * ICH9 LPC (device 0:31) SMI injection: PMBASE is programmed at
 * 0x1000 with ACPI enabled, and the APM control port (0xb2) raises
 * an SMI on any command other than 0x80/0x84 when SMI_EN.APMC_EN is
 * set.  SeaBIOS relocates SMBASE and installs its own SMM handler;
 * MSR_SMI_COUNT records actual SMM entry without assuming the reset
 * SMBASE or overwriting firmware SMRAM.
 */
#define ICH9_LPC_DEVFN        0xf8
#define APM_CNT_PORT          0xb2
#define SMI_COUNT_MSR         0x34

/* Program the ICH9 PM IO region for APM SMI injection. */
static uint32_t smi_trigger_setup(void)
{
    uint32_t v;

    /* PMBASE 0x1000, RTE on; ACPI enabled so the PM IO maps. */
    pci_cfg_writel(ICH9_LPC_DEVFN, 0x40, 0x1001);
    v = pci_cfg_readl(ICH9_LPC_DEVFN, 0x48);
    pci_cfg_writel(ICH9_LPC_DEVFN, 0x48, v | 0x80);
    return 0x1000;
}

static void smi_trigger(uint32_t pm_io)
{
    /* volatile: PM IO SMI_EN register, ICH9 APM control port. */
    *(volatile uint32_t *)(uintptr_t)(pm_io + 0x30) = 0x20;
    port_outb(APM_CNT_PORT, 0x86);
}

/*
 * A pending SMI is consumed at the next translation-block boundary;
 * an outb to the POST diagnostic port forces one.
 */
static void smi_wait(void)
{
    port_outb(0x80, 0);
}

/*
 * Find the iommu-testdev on bus 0, enable its memory space and bus
 * mastering, and return its 4 KiB BAR0 base.  Returns 0 if absent; the
 * meson args always create it, so 0 is a test-environment failure.
 */
static uint32_t itd_find_bar(void)
{
    uint32_t devfn;
    uint32_t id;
    uint32_t cmd;

    for (devfn = 0; devfn < 32; devfn++) {
        id = pci_cfg_readl(devfn, 0x0);
        if ((id & 0xffff) != ITD_VENDOR || (id >> 16) != ITD_DEVICE) {
            continue;
        }
        cmd = pci_cfg_readl(devfn, 0x4);
        pci_cfg_writel(devfn, 0x4, cmd | 0x6); /* MEM | MASTER */
        return pci_cfg_readl(devfn, 0x10) & 0xfffffff0UL;
    }
    return 0;
}

/*
 * Run one 4-byte DMA of the test value at @addr through the device's
 * IOMMU address space (IOVA == GPA).  Returns 0 on success and
 * ITD_ERR_TX_FAIL when the IOMMU refuses the transfer.
 */
static uint32_t itd_dma(uint32_t bar, uint64_t addr)
{
    uint32_t result;
    uint32_t i;

    itd_writel(bar, ITD_REG_GVA_LO, (uint32_t)addr);
    itd_writel(bar, ITD_REG_GVA_HI, (uint32_t)(addr >> 32));
    itd_writel(bar, ITD_REG_GPA_LO, (uint32_t)addr);
    itd_writel(bar, ITD_REG_GPA_HI, (uint32_t)(addr >> 32));
    itd_writel(bar, ITD_REG_LEN, 4);
    itd_writel(bar, ITD_REG_ATTRS, 0);
    itd_writel(bar, ITD_REG_DBELL, ITD_DBELL_ARM);
    /* The read of the triggering register starts the DMA. */
    (void)itd_readl(bar, ITD_REG_TRIGGERING);

    result = ITD_RESULT_BUSY;
    for (i = 0; i < 1000; i++) {
        result = itd_readl(bar, ITD_REG_RESULT);
        if (result != ITD_RESULT_BUSY) {
            break;
        }
    }
    if (result == ITD_RESULT_BUSY) {
        return ITD_ERR_TX_FAIL;
    }
    return result;
}

/*
 * The IDT installed by boot.S only carries fixed-up gates that point
 * at address 0, so install our own: #UD (6) and #GP (13) for the
 * GETSEC faults, plus a DPL-3 gate at 0x80 that the CPL3 cases use to
 * get back to ring 0.
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

/* Vector 0x80 is the CPL3 return gate, so the table runs that far. */
#define IDT_VECTOR_CPL3_RET 0x80

static struct idt_desc idt[IDT_VECTOR_CPL3_RET + 1];
static struct idt_ptr idtr;

static int ud_count;
static int gp_count;
static uint32_t gp_err = 0xffffffffU;

/*
 * The handler is referenced by name from the asm gate below; keep it
 * non-static so the symbol survives in the object.
 */
void ud_handler(void)
{
    ud_count++;
}

/*
 * Records the #GP error code as well as the count: GETSEC at CPL != 0
 * must raise #GP(0), and "(0)" is half the assertion -- a fault with a
 * selector error code would mean something else faulted.
 */
void gp_handler(uint32_t err)
{
    gp_count++;
    gp_err = err;
}

__attribute__((naked))
static void gp_gate(void)
{
    /*
     * #GP pushes an error code, so on entry the frame is
     * [err][EIP][CS][EFLAGS] -- plus [ESP][SS] when the fault came
     * from CPL3, which iret pops for us.  Hand the error code to the
     * handler, step the saved EIP over the 2-byte GETSEC (0F 37),
     * then drop the error code before returning.
     */
    asm volatile(
        "pushal\n"
        "pushl 32(%esp)\n"
        "call gp_handler\n"
        "addl $4, %esp\n"
        "popal\n"
        "addl $2, 4(%esp)\n"
        "addl $4, %esp\n"
        "iret\n"
    );
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

/*
 * Ring-3 entry point.  EAX already holds the GETSEC leaf (enter_cpl3()
 * loads it before the iret), the #GP or #UD gate steps over the
 * 2-byte GETSEC, and int $0x80 hands control back to ring 0.  It
 * touches no memory and no I/O ports, so it needs neither a reloaded
 * DS nor a raised IOPL.
 */
__attribute__((naked))
void cpl3_entry(void)
{
    asm volatile(
        ".byte 0x0f, 0x37\n"
        "int $0x80\n"
    );
}

/*
 * Saved ring-0 continuation for the return gate.  Coming back from
 * CPL3 cannot be an iret -- that would go back to ring 3 -- so the
 * gate restores this stack pointer and jumps, i.e. a longjmp that
 * lands in enter_cpl3() still at CPL0.
 */
uint32_t cpl3_ret_esp;
uint32_t cpl3_ret_eip;
uint32_t cpl3_stack_top;
/*
 * Volatile: the ring-3 stub reads this through a symbol reference
 * from inline asm, so the store below must actually happen.
 */
volatile uint32_t cpl3_leaf;

__attribute__((naked))
void cpl3_ret_gate(void)
{
    asm volatile(
        "movl cpl3_ret_esp, %esp\n"
        "jmp *cpl3_ret_eip\n"
    );
}

static void idt_set(int vector, void (*gate)(void), uint16_t access)
{
    uint32_t a = (uint32_t)(uintptr_t)gate;

    idt[vector].off_lo = (uint16_t)(a & 0xffff);
    idt[vector].off_hi = (uint16_t)((a >> 16) & 0xffff);
    idt[vector].access = access;
}

static void idt_install(void)
{
    int i;

    for (i = 0; i < (int)(sizeof(idt) / sizeof(idt[0])); i++) {
        idt[i] = (struct idt_desc) {
            .sel = 0x08, /* kernel code segment from boot.S */
        };
    }
    /* 386 interrupt gates, present: 0x8e00 is DPL 0, 0xee00 is DPL 3. */
    idt_set(6, ud_gate, 0x8e00);
    idt_set(13, gp_gate, 0x8e00);
    /*
     * The return gate must be reachable by an int from CPL3, and
     * software interrupts do check the gate DPL (unlike exceptions),
     * so this one is DPL 3.
     */
    idt_set(IDT_VECTOR_CPL3_RET, cpl3_ret_gate, 0xee00);

    idtr.limit = sizeof(idt) - 1;
    idtr.base = (uint32_t)(uintptr_t)idt;
    asm volatile("lidt %0" :: "m"(idtr));
}

/*
 * boot.S builds a two-entry GDT (0x08 ring-0 code, 0x10 ring-0 data)
 * and no TSS, which is all a ring-0-only test needs.  Dropping to CPL3
 * needs ring-3 descriptors to iret to and a TSS for the ring-0 stack
 * the fault handlers run on, so install a wider GDT here.  Selectors
 * 0x08 and 0x10 keep boot.S's contents, so the already-loaded CS/DS
 * stay valid across the lgdt.
 */
struct gdt_desc {
    uint16_t limit_lo;
    uint16_t base_lo;
    uint8_t base_mid;
    uint8_t access;
    uint8_t gran;
    uint8_t base_hi;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

/* 32-bit TSS; only ss0/esp0 and the I/O map base matter here. */
struct tss32 {
    uint32_t link;
    uint32_t esp0;
    uint32_t ss0;
    uint32_t unused[22];   /* esp1 .. ldt */
    uint16_t trap;
    uint16_t iomap;
} __attribute__((packed));

#define SEL_CODE3 0x18
#define SEL_DATA3 0x20
#define SEL_TSS   0x28

static struct gdt_desc gdt[6];
static struct gdt_ptr gdtr;
static struct tss32 tss;
/* Ring-3 stack, and the ring-0 stack the fault handlers switch to. */
static uint8_t cpl3_stack[4096] __attribute__((aligned(16)));
static uint8_t cpl0_stack[8192] __attribute__((aligned(16)));

static void gdt_set(int index, uint32_t base, uint32_t limit,
                    uint8_t access, uint8_t gran)
{
    gdt[index].limit_lo = (uint16_t)(limit & 0xffff);
    gdt[index].base_lo = (uint16_t)(base & 0xffff);
    gdt[index].base_mid = (uint8_t)((base >> 16) & 0xff);
    gdt[index].access = access;
    gdt[index].gran = (uint8_t)(gran | ((limit >> 16) & 0x0f));
    gdt[index].base_hi = (uint8_t)((base >> 24) & 0xff);
}

static void gdt_install(void)
{
    uint32_t tss_base = (uint32_t)(uintptr_t)&tss;

    gdt_set(0, 0, 0, 0, 0);
    /* Flat 4 GiB segments: access 0x9b/0x93 ring 0, 0xfb/0xf3 ring 3. */
    gdt_set(1, 0, 0xfffff, 0x9b, 0xc0);
    gdt_set(2, 0, 0xfffff, 0x93, 0xc0);
    gdt_set(3, 0, 0xfffff, 0xfb, 0xc0);
    gdt_set(4, 0, 0xfffff, 0xf3, 0xc0);
    /* Available 32-bit TSS (type 0x9, present), byte granular. */
    gdt_set(5, tss_base, sizeof(tss) - 1, 0x89, 0x00);

    tss.ss0 = 0x10;
    tss.esp0 = (uint32_t)(uintptr_t)(cpl0_stack + sizeof(cpl0_stack));
    /* No I/O permission bitmap: a base past the TSS limit denies all. */
    tss.iomap = sizeof(tss);

    cpl3_stack_top = (uint32_t)(uintptr_t)(cpl3_stack + sizeof(cpl3_stack));

    gdtr.limit = sizeof(gdt) - 1;
    gdtr.base = (uint32_t)(uintptr_t)gdt;
    asm volatile("lgdt %0" :: "m"(gdtr));
    /* Reload CS from the new table even though 0x08 is unchanged. */
    asm volatile("ljmp $0x08, $1f\n"
                 "1:\n");
    asm volatile("ltr %%ax" :: "a"((uint16_t)SEL_TSS));
}

/*
 * Run GETSEC with leaf @leaf at CPL3 and come back.  The iret frame
 * drops to ring 3 with IOPL 0 and interrupts left masked; cpl3_entry()
 * returns through int $0x80, whose gate restores the stack saved here.
 * Everything is referenced through globals because the return path is
 * a longjmp: no register the compiler picked would survive it.
 */
static void enter_cpl3(uint32_t leaf)
{
    cpl3_leaf = leaf;
    asm volatile(
        "movl %%esp, cpl3_ret_esp\n"
        "movl $1f, cpl3_ret_eip\n"
        "movl cpl3_leaf, %%eax\n"
        "pushl $0x23\n"              /* SS  = SEL_DATA3 | RPL 3 */
        "pushl cpl3_stack_top\n"     /* ESP */
        "pushl $0x00000002\n"        /* EFLAGS: reserved bit only */
        "pushl $0x1b\n"              /* CS  = SEL_CODE3 | RPL 3 */
        "pushl $cpl3_entry\n"
        "iret\n"
        "1:\n"
        : /* no outputs */
        : /* no inputs */
        : "eax", "ebx", "ecx", "edx", "esi", "edi", "memory");
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
 * over the SINIT region, which setup_acm() fills with the synthetic
 * ACM fixture.  The region is deliberately 8 KiB so the measurement
 * spans more than one PTM_HASH_DATA chunk (the control message
 * carries at most 4096 bytes), exercising the backend's chunk loop.
 *
 * _TPM_Hash_Start resets the PCR to zero and _TPM_Hash_End extends it
 * with the hash of the data, so the value is
 *
 *   SHA256( 0x00 * 32 || SHA256(region) )
 *
 * Reproduce with (mirroring setup_acm()):
 *   python3 - <<'EOF'
 *   import hashlib, struct
 *   b = bytearray(i & 0xff for i in range(0x2000))
 *   def w16(o, v): b[o:o+2] = struct.pack('<H', v)
 *   def w32(o, v): b[o:o+4] = struct.pack('<I', v)
 *   w16(0x00, 2); w16(0x02, 0); w32(0x04, 161); w32(0x10, 0x8086)
 *   w32(0x18, 0x800)
 *   w32(0x28, 0x17); w32(0x2c, 0x520); w32(0x30, 8)
 *   w32(0x34, 0x1000); w32(0x7c, 143)
 *   b[0x4c0:0x4f0] = bytes(0x30)
 *   b[0x4c0:0x4d0] = bytes([0xaa,0x3a,0xc0,0x7f,0xa7,0x46,0xdb,0x18,
 *                           0x2e,0xac,0x69,0x8f,0x8d,0x41,0x7f,0x5a])
 *   b[0x4d0] = 1; b[0x4d1] = 4; w16(0x4d2, 0x30); w32(0x4d4, 0x500)
 *   b[0x500:0x514] = bytes(0x14)
 *   w32(0x500, 1); w32(0x504, 0)
 *   w16(0x508, 0x8086); w16(0x50a, 0x29c0); w16(0x50c, 0)
 *   b[0x520:0x538] = bytes([0,0,0,0,0,0,0,0,
 *                           0xff,0xff,0,0,0,0x9a,0xcf,0,
 *                           0xff,0xff,0,0,0,0x92,0xcf,0])
 *   print(hashlib.sha256(bytes(32) +
 *         hashlib.sha256(bytes(b)).digest()).hexdigest())
 *   EOF
 */
#ifdef TEST_TXT_TPM2_LOG
/*
 * A version-7 launch continues past the ACM hash with the rest of the
 * SDG launch-context events, so PCR 17 is
 *
 *   E(E(E(E(0, H(acm)), H(mle)), H(caps)), H(scrtm))
 *
 * where E(a,b) = SHA256(a || b), caps is the os_sinit_data
 * capabilities DWORD (3 here) and scrtm is the S-CRTM status DWORD
 * (1, processor-established).  Append to the recipe above:
 *   ext = lambda c, d: hashlib.sha256(c + d).digest()
 *   h = lambda d: hashlib.sha256(d).digest()
 *   p = ext(bytes(32), h(bytes(b)))
 *   p = ext(p, h(bytes(img)))          # img from the PCR 18 recipe
 *   p = ext(p, h(struct.pack('<I', 3)))
 *   p = ext(p, h(struct.pack('<I', 1)))
 *   print(p.hex())
 */
static const uint8_t pcr17_expected[32] = {
    0xd4, 0x90, 0x94, 0x67, 0x22, 0x6d, 0x7d, 0xd1,
    0x9e, 0xa2, 0xb1, 0x1c, 0x6f, 0x76, 0xc9, 0xe8,
    0xd8, 0x4c, 0x36, 0x68, 0x1b, 0x24, 0x1b, 0x90,
    0xe1, 0x80, 0x3e, 0xdb, 0xf4, 0x00, 0xf1, 0xbc,
};
#else
static const uint8_t pcr17_expected[32] = {
    0x10, 0x02, 0x9f, 0xff, 0xe9, 0x12, 0xaa, 0x85,
    0x7e, 0x80, 0x08, 0x75, 0x28, 0x0c, 0x72, 0xb3,
    0xa7, 0xc7, 0x9b, 0x9d, 0x98, 0x4c, 0x08, 0x4a,
    0xa4, 0x30, 0x93, 0x74, 0xfe, 0x55, 0xa9, 0x04,
};
#endif

/*
 * Expected PCR 18 (SHA-256 bank): the MLE hash, extended from zero
 * because _TPM_Hash_Start zeroes PCR 18 as well as PCR 17.  The image
 * is mle[i] = (i ^ 0x5A) with the MLE header overwritten at
 * TEST_MLE_HDR_OFF, so the digest covers the header bytes too -- which
 * is correct: the header lives inside the measured image.  For
 * TEST_TXT_MLE_UNALIGNED the image is the first 0x1800 bytes and the
 * mle_end_off header field is 0x1800.
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
#if defined(TEST_TXT_TPM2_LOG)
/* As for PCR 17, but the chain is E(E(E(0, H(mle)), H(caps)), H(scrtm)). */
static const uint8_t pcr18_expected[32] = {
    0x85, 0xca, 0x0c, 0x70, 0x54, 0x13, 0x87, 0x69,
    0x39, 0x28, 0x55, 0x47, 0x7b, 0xd9, 0x23, 0xd2,
    0x47, 0xc9, 0xf2, 0x63, 0x62, 0x7e, 0xf8, 0x47,
    0xab, 0x6f, 0x28, 0xc5, 0x79, 0x36, 0x0a, 0x89,
};
#elif defined(TEST_TXT_MLE_UNALIGNED)
/* Same recipe as below with 0x1800 in both places. */
static const uint8_t pcr18_expected[32] = {
    0x72, 0x18, 0xc5, 0x50, 0x90, 0x64, 0x59, 0x1a,
    0x02, 0x84, 0x81, 0x4e, 0x58, 0x47, 0xc7, 0xcc,
    0x99, 0xb3, 0x81, 0x28, 0xc7, 0x75, 0xfb, 0xc4,
    0xcb, 0x4a, 0x15, 0xbf, 0x4f, 0xcf, 0xc4, 0xae,
};
#else
static const uint8_t pcr18_expected[32] = {
    0x48, 0xf9, 0x98, 0x67, 0x42, 0xb8, 0xc2, 0x73,
    0xae, 0x33, 0x8f, 0xf5, 0xb9, 0x1d, 0xbe, 0x73,
    0x6f, 0xea, 0x75, 0x23, 0x52, 0xe1, 0x2e, 0xbc,
    0x56, 0x5f, 0xf6, 0x6f, 0x13, 0xa0, 0x3f, 0xe7,
};
#endif

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

/* ACM_UUID_V3 (tboot tboot/include/txt/acmod.h) in wire order. */
static const uint8_t acm_uuid[16] = {
    0xaa, 0x3a, 0xc0, 0x7f, 0xa7, 0x46, 0xdb, 0x18,
    0x2e, 0xac, 0x69, 0x8f, 0x8d, 0x41, 0x7f, 0x5a,
};

/*
 * Fixture stores go through volatile pointers: the bytes land in
 * guest RAM that the TXT device reads back during SENTER, not in
 * anything this program reads, so the compiler must not elide or
 * reorder them.  setup_mle() writes its inputs the same way.
 */
static void acm_write16(uint32_t off, uint16_t val)
{
    /* Volatile: a store into guest RAM the device reads. */
    *(volatile uint16_t *)(uintptr_t)(TEST_SINIT_BASE + off) = val;
}

static void acm_write32(uint32_t off, uint32_t val)
{
    /* Volatile: a store into guest RAM the device reads. */
    *(volatile uint32_t *)(uintptr_t)(TEST_SINIT_BASE + off) = val;
}

/*
 * Build the synthetic SINIT ACM fixture the device's precondition-3
 * validation accepts: a chipset ACM of subtype SINIT from Intel,
 * whose info table carries the ACM UUID and points at a chipset id
 * list covering TXT.DIDVID.
 *
 * The body is the byte pattern acm[i] = (uint8_t)i with the header,
 * info table and id list written over it, so the measurement still
 * covers 8 KiB of varied content (two PTM_HASH_DATA chunks) and the
 * expected PCR 17 digest below stays reproducible.
 */
static void setup_acm(void)
{
    /* Volatile for the same reason as the acm_write*() helpers. */
    volatile uint8_t *acm = (volatile uint8_t *)(uintptr_t)TEST_SINIT_BASE;
    uint32_t i;

    for (i = 0; i < (uint32_t)TEST_SINIT_SIZE; i++) {
        acm[i] = (uint8_t)i;
    }

    acm_write16(ACM_OFF_MODULE_TYPE, 0x0002);     /* chipset ACM */
    acm_write16(ACM_OFF_MODULE_SUBTYPE, 0x0000);  /* SINIT, not reset */
    acm_write32(ACM_OFF_HEADER_LEN, ACM_HEADER_LEN);
    acm_write32(ACM_OFF_MODULE_VENDOR, 0x8086);
    acm_write32(ACM_OFF_SIZE, (uint32_t)TEST_SINIT_SIZE / 4);
    acm_write32(ACM_OFF_GDT_LIMIT, ACM_GDT_LIMIT);
    /* GDTBasePtr is an offset from the module base, not an address. */
    acm_write32(ACM_OFF_GDT_BASE, ACM_GDT_OFF);
    acm_write32(ACM_OFF_SEG_SEL, ACM_SEG_SEL);
    acm_write32(ACM_OFF_ENTRY_POINT, 0x1000);
    acm_write32(ACM_OFF_SCRATCH_SIZE, ACM_SCRATCH_SIZE);

    /* Info table at (header_len + scratch_size) * 4. */
    for (i = 0; i < 0x30; i++) {
        acm[ACM_INFO_OFF + i] = 0;
    }
    for (i = 0; i < 16; i++) {
        acm[ACM_INFO_OFF + i] = acm_uuid[i];
    }
    acm[ACM_INFO_OFF_TYPE] = 0x01;                /* SINIT ACM */
    acm[ACM_INFO_OFF_VERSION] = 4;
    acm_write16(ACM_INFO_OFF_LENGTH, 0x30);
    acm_write32(ACM_INFO_OFF_ID_LIST, ACM_ID_LIST_OFF);

    /* One chipset id entry, matching TXT.DIDVID exactly (flags = 0). */
    for (i = 0; i < 0x14; i++) {
        acm[ACM_ID_LIST_OFF + i] = 0;
    }
    acm_write32(ACM_ID_LIST_OFF, 1);              /* count */
    acm_write32(ACM_ID_OFF_FLAGS, 0);
    acm_write16(ACM_ID_OFF_VENDOR, ACM_CHIPSET_VENDOR);
    acm_write16(ACM_ID_OFF_DEVICE, ACM_CHIPSET_DEVICE);
    acm_write16(ACM_ID_OFF_REVISION, ACM_CHIPSET_REVISION);

    /* The GDT the header points at: null, flat code, flat data. */
    for (i = 0; i < ACM_GDT_SIZE; i++) {
        acm[ACM_GDT_OFF + i] = 0;
    }
    for (i = 0; i < 2; i++) {
        uint32_t e = ACM_GDT_OFF + 8 + i * 8;

        acm[e + 0] = 0xff;                 /* limit 15:0  */
        acm[e + 1] = 0xff;
        acm[e + 5] = i == 0 ? 0x9a : 0x92; /* code / data, present, DPL0 */
        acm[e + 6] = 0xcf;                 /* 32-bit, 4 KiB granularity */
    }
}

/* One §3.5 mutation: corrupt @width bytes of the fixture at @off. */
struct acm_mutation {
    const char *name;
    uint32_t off;
    uint8_t width;
    uint32_t val;
};

static const struct acm_mutation acm_mutations[] = {
    { "module_type not a chipset ACM", ACM_OFF_MODULE_TYPE, 2, 0x0003 },
    { "module_subtype is a reset ACM", ACM_OFF_MODULE_SUBTYPE, 2, 0x0001 },
    { "module_vendor not Intel", ACM_OFF_MODULE_VENDOR, 4, 0x1022 },
    { "header size field disagrees with SINIT_SIZE", ACM_OFF_SIZE, 4,
      0x400 },
    { "entry_point past the end of the module", ACM_OFF_ENTRY_POINT, 4,
      0x2000 },
    { "entry_point zero", ACM_OFF_ENTRY_POINT, 4, 0 },
    { "seg_sel null", ACM_OFF_SEG_SEL, 4, 0 },
    { "seg_sel is an LDT selector", ACM_OFF_SEG_SEL, 4,
      ACM_SEG_SEL | 0x04 },
    { "seg_sel is not ring 0", ACM_OFF_SEG_SEL, 4, ACM_SEG_SEL | 0x03 },
    /* Low three bits clear, so this reaches the gdt_limit check. */
    { "seg_sel past gdt_limit", ACM_OFF_SEG_SEL, 4, ACM_GDT_SIZE },
    { "gdt_limit too small for seg_sel", ACM_OFF_GDT_LIMIT, 4, 0 },
    { "seg_sel plus 8 overflows", ACM_OFF_SEG_SEL, 4, 0xfffffff8 },
    { "GDT code descriptor is not executable", ACM_GDT_OFF + 8 + 5,
      1, 0x92 },
    { "GDT data descriptor not present", ACM_GDT_OFF + 16 + 5,
      1, 0x12 },
    { "header_len puts the info table out of bounds", ACM_OFF_HEADER_LEN,
      4, 0x40000 },
    { "scratch_size puts the info table out of bounds",
      ACM_OFF_SCRATCH_SIZE, 4, 0x40000 },
    { "info table UUID corrupted", ACM_INFO_OFF, 1, 0x00 },
    { "chipset_acm_type is BIOS, not SINIT", ACM_INFO_OFF_TYPE, 1, 0x00 },
    { "info table version below the minimum", ACM_INFO_OFF_VERSION, 1, 2 },
    { "chipset id list out of bounds", ACM_INFO_OFF_ID_LIST, 4, 0x2000 },
    { "chipset id list empty", ACM_ID_LIST_OFF, 4, 0 },
    { "chipset id vendor does not match DIDVID", ACM_ID_OFF_VENDOR, 2,
      0x1234 },
    { "chipset id device does not match DIDVID", ACM_ID_OFF_DEVICE, 2,
      0x1234 },
    { "chipset id revision does not match DIDVID", ACM_ID_OFF_REVISION, 2,
      0x0003 },
    { "chipset id revision mask matches nothing", ACM_ID_OFF_FLAGS, 4, 1 },
};

static void acm_mutate(const struct acm_mutation *m)
{
    switch (m->width) {
    case 1:
        /* Volatile: a store into guest RAM the device reads. */
        *(volatile uint8_t *)(uintptr_t)(TEST_SINIT_BASE + m->off) =
            (uint8_t)m->val;
        break;
    case 2:
        acm_write16(m->off, (uint16_t)m->val);
        break;
    default:
        acm_write32(m->off, m->val);
        break;
    }
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
 *   [os_sinit_data_size=0x48][version, flags, mle_ptab, mle_size,
 *                             mle_hdr_base, low/high PMR base+size]
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

    /* Only the MLE-linear image is mapped; entry runs with PG=0. */
    for (i = 0; i < 0x200; i++) {
        pdpt[i] = 0;
        pd[i] = 0;
        pt[i] = 0;
    }
    pdpt[0] = (TEST_MLE_PTAB + 0x1000) | 1;
    pd[0] = (TEST_MLE_PTAB + 0x2000) | 1;
    for (i = 0; i < (uint32_t)((TEST_MLE_SIZE + 0xfff) / 0x1000); i++) {
        uint64_t phys = TEST_MLE_BASE + (uint64_t)i * 0x1000;

        pt[i] = phys | 1;
    }

    /* Heap sections. */
    for (i = 0; i < TEST_SINIT_MLE_OFF + 8; i++) {
        heap[i] = 0;
    }
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x00) = 0x10;
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x10) = 0x10;
    /* volatile: the SENTER helper reads this guest heap between writes. */
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x20) =
        TEST_OS_SINIT_SIZE;
    /* volatile: keep launches rejected until the final entry test. */
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + TEST_SINIT_MLE_OFF) =
        0xffff;

    os_sinit = (volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + 0x28);
    *(volatile uint32_t *)os_sinit = 6;                 /* version */
    *((volatile uint32_t *)os_sinit + 1) = 0;           /* flags */
    os_sinit[1] = TEST_MLE_PTAB;                        /* mle_ptab */
    os_sinit[2] = TEST_MLE_SIZE;                        /* mle_size */
    os_sinit[3] = TEST_MLE_HDR_OFF;                     /* mle_hdr_base */
    os_sinit[4] = 0;                                    /* lo base */
    os_sinit[5] = 0x1000000;                            /* lo size: 16 MiB */
    os_sinit[6] = 0;                                    /* empty hi base */
    os_sinit[7] = 0;                                    /* empty hi size */
#if defined(TEST_TXT_MONITOR_WAKE) || defined(TEST_TXT_TPM2_LOG)
    os_sinit[8] = 0;                                    /* lcp_po_base */
    os_sinit[9] = 0;                                    /* lcp_po_size */
    /* capabilities: ask for MONITOR wake, with GETSEC[WAKEUP] offered */
    *((volatile uint32_t *)os_sinit + 20) = 0x00000003;
#endif
#ifdef TEST_TXT_TPM2_LOG
    {
        txt_guest_u8 *ext = heap + 0x28 + 0x5c;
        txt_guest_u8 *log = (txt_guest_u8 *)(uintptr_t)
            TEST_EVENT_LOG_BASE;

        *(txt_guest_u32 *)os_sinit = 7;
        *(txt_guest_u32 *)(ext + 0) = 8;  /* TPM2 log pointer 2.1 */
        *(txt_guest_u32 *)(ext + 4) = 28;
        *(txt_guest_u64 *)(ext + 8) = TEST_EVENT_LOG_BASE;
        *(txt_guest_u32 *)(ext + 16) = TEST_EVENT_LOG_SIZE;
        *(txt_guest_u32 *)(ext + 20) = 0;
        *(txt_guest_u32 *)(ext + 24) = 0;
        *(txt_guest_u32 *)(ext + 28) = 0; /* END */
        *(txt_guest_u32 *)(ext + 32) = 8;
        for (i = 0; i < TEST_EVENT_LOG_SIZE; i++) {
            log[i] = 0;
        }
    }
#endif

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

/* The MLE entry stub sets its own stack before touching C code. */
static uint8_t mle_entry_stack[4096] __attribute__((aligned(16)));
/* volatile: the naked assembly entry writes these before C reads them. */
static volatile uint32_t mle_seen_ebx, mle_seen_ecx, mle_seen_edx;
/* volatile: these too are written by assembly, outside the C flow. */
static volatile uint32_t mle_seen_eflags, mle_seen_cr0;

/* volatile: read guest RAM that SENTER populated outside the C flow. */
static uint64_t guest_le(volatile uint8_t *p, unsigned int bytes)
{
    uint64_t value = 0;
    unsigned int i;

    for (i = 0; i < bytes; i++) {
        value |= (uint64_t)p[i] << (8 * i);
    }
    return value;
}

#ifdef TEST_TXT_TPM2_LOG
static void check_tpm2_event_log(void)
{
    txt_guest_u8 *ext = (txt_guest_u8 *)(uintptr_t)
        (TEST_HEAP_BASE + 0x28 + 0x5c);
    txt_guest_u8 *log = (txt_guest_u8 *)(uintptr_t)
        TEST_EVENT_LOG_BASE;
    uint32_t banks = guest_le(log + 56, 4);
    uint32_t next = guest_le(ext + 24, 4);
    uint32_t pos = 60, pcr;
    unsigned i, j;
    uint32_t has_sha256 = 0;
    const char signature[] = "Spec ID Event03";

    if (guest_le(ext + 20, 4) != 0 || next > TEST_EVENT_LOG_SIZE ||
        banks < 2 || banks > 4 || guest_le(log + 0, 4) != 0 ||
        guest_le(log + 4, 4) != 3 || guest_le(log + 53, 1) != 2 ||
        guest_le(log + 56, 4) != banks) {
        fail_msg("TPM2 Spec ID or event-log offsets invalid", 16384);
    }
    for (i = 0; i < sizeof(signature); i++) {
        if (log[32 + i] != signature[i]) {
            fail_msg("TPM2 Spec ID signature invalid", 16384);
        }
    }
    for (i = 0; i < banks; i++) {
        uint16_t alg = guest_le(log + pos, 2);
        uint16_t length = guest_le(log + pos + 2, 2);

        if ((alg != 4 || length != 20) && (alg != 11 || length != 32) &&
            (alg != 12 || length != 48) && (alg != 13 || length != 64)) {
            fail_msg("TPM2 Spec ID bank descriptor invalid", 16384);
        }
        if (alg == 11) {
            has_sha256++;
        }
        pos += 4;
    }
    if (has_sha256 != 1 || log[pos] != 0 ||
        guest_le(log + 28, 4) != pos + 1 - 32) {
        fail_msg("TPM2 Spec ID payload invalid", 16384);
    }
    pos++;
    /*
     * The launch-context records, in extend order per PCR (SDG
     * Table 35 event types).  Anything QEMU cannot derive -- LCP
     * policy, the AUX index, NV public info, the real signer key --
     * is absent, so this is the whole expected sequence.
     */
    static const struct {
        uint32_t pcr;
        uint32_t type;
        uint32_t size;
        uint32_t data;
    } expected_events[] = {
        { 17, 0x402, 0, 0 },  /* EVTYPE_HASH_START    */
        { 18, 0x404, 0, 0 },  /* EVTYPE_MLE_HASH      */
        { 17, 0x404, 0, 0 },  /* EVTYPE_MLE_HASH      */
        { 17, 0x40f, 4, 3 },  /* EVTYPE_OSSINITDATA_CAP: capabilities */
        { 17, 0x40b, 4, 1 },  /* EVTYPE_CPU_SCRTM_STAT: CPU S-CRTM   */
        { 18, 0x40f, 4, 3 },
        { 18, 0x40b, 4, 1 },
    };

#define NR_EXPECTED_EVENTS \
    (sizeof(expected_events) / sizeof(expected_events[0]))

    for (unsigned ev = 0; ev < NR_EXPECTED_EVENTS; ev++) {
        uint32_t event_banks, event_size;

        pcr = expected_events[ev].pcr;
        if (guest_le(log + pos, 4) != pcr ||
            guest_le(log + pos + 4, 4) != expected_events[ev].type) {
            ml_printf("smx: event %u is PCR %u type 0x%x, want PCR %u "
                      "type 0x%x\n", ev, guest_le(log + pos, 4),
                      guest_le(log + pos + 4, 4), pcr,
                      expected_events[ev].type);
            fail_msg("TXT measurement missing from TPM2 event log", 16384);
        }
        event_banks = guest_le(log + pos + 8, 4);
        if (event_banks != banks) {
            fail_msg("TPM2 event digest count invalid", 16384);
        }
        pos += 12;
        for (i = 0; i < banks; i++) {
            uint16_t alg = guest_le(log + pos, 2);
            unsigned digest_len = 0;
            uint8_t any = 0;

            for (j = 0; j < banks; j++) {
                if (guest_le(log + 60 + 4 * j, 2) == alg) {
                    digest_len = guest_le(log + 62 + 4 * j, 2);
                    break;
                }
            }
            if (!digest_len) {
                fail_msg("TPM2 log event has undeclared bank", 16384);
            }
            pos += 2;
            for (j = 0; j < digest_len; j++) {
                any |= log[pos + j];
            }
            if (!any) {
                fail_msg("TPM2 event contains an empty digest", 16384);
            }
            pos += digest_len;
        }
        event_size = guest_le(log + pos, 4);
        if (event_size != expected_events[ev].size) {
            fail_msg("TPM2 TXT event data size wrong", 16384);
        }
        pos += 4;
        if (event_size == 4 &&
            guest_le(log + pos, 4) != expected_events[ev].data) {
            fail_msg("TPM2 TXT event data wrong", 16384);
        }
        pos += event_size;
    }
    if (pos != next) {
        fail_msg("TPM2 next_record_offset does not follow events", 16384);
    }
    ml_printf("PASS: TPM2 Spec ID and the %u SINIT event records\n",
              (unsigned)NR_EXPECTED_EVENTS);
#undef NR_EXPECTED_EVENTS
}
#endif

#ifdef TEST_TXT_SMP
/* Volatile: AP writes this word concurrently with the BSP's spin wait. */
static volatile uint32_t ap_joined;

/* The AP has no stack on entry. Use no C prologue and a private stack. */
static void __attribute__((naked, noreturn, used)) ap_landing(void)
{
    asm volatile("movl $0xe5f000, %%esp\n"
                 "movl $1, ap_joined\n"
                 "1: hlt\n"
                 "jmp 1b\n" : : : "memory");
}
#endif

static void __attribute__((noreturn, noinline, used)) mle_landing_c(void)
{
    struct {
        uint16_t limit;
        uint32_t base;
    } __attribute__((packed)) gdtr;
    uint32_t cr0, cr3, cr4;
    uint16_t cs, ds;
    uint64_t sts;
    /* volatile: SINIT writes this guest heap outside the C flow. */
    volatile uint8_t *section = (volatile uint8_t *)(uintptr_t)
        (TEST_HEAP_BASE + TEST_SINIT_MLE_OFF);
    uint32_t count, off;
    uint32_t original_pmbase, original_acpi_ctrl;
    uint64_t smi_count_before;

    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    asm volatile("sgdt %0" : "=m"(gdtr));
    asm volatile("mov %%cs, %0" : "=r"(cs));
    asm volatile("mov %%ds, %0" : "=r"(ds));
    /*
     * SINIT hands over CR4 = SMXE only, so the SSE staging used by
     * txt_read64() is disabled until the MLE turns it back on -- as a
     * real MLE must re-establish whatever CR4 features it needs.
     */
    write_cr4(cr4 | CR4_OSFXSR_MASK | CR4_OSXMMEXCPT_MASK);
    sts = txt_read64(TXT_OFF_STS);
    count = guest_le(section + 8 + 0x80, 4);
    off = guest_le(section + 8 + 0x84, 4);

    if (mle_seen_ebx != TEST_MLE_BASE + 0x200 ||
        mle_seen_ecx != TEST_MLE_PTAB || mle_seen_edx != 0 ||
        mle_seen_eflags != 0x2 || (mle_seen_cr0 & (1u << 31)) ||
        (cr0 & (1u << 31)) || cr4 != CR4_SMXE_MASK ||
        cr3 != TEST_MLE_PTAB) {
        fail_msg("MLE entry register/paging state is wrong", 16384);
    }
    if (gdtr.base != TEST_SINIT_BASE + ACM_GDT_OFF ||
        gdtr.limit != ACM_GDT_LIMIT || cs != ACM_SEG_SEL ||
        ds != ACM_SEG_SEL + 8) {
        fail_msg("MLE entry GDT or segment selectors are wrong", 16384);
    }
    if ((sts & (TXT_STS_SENTER_DONE | TXT_STS_MEM_CONFIG_LOCK |
                TXT_STS_PRIVATE_OPEN)) !=
        (TXT_STS_SENTER_DONE | TXT_STS_MEM_CONFIG_LOCK |
         TXT_STS_PRIVATE_OPEN) || txt_read64(TXT_OFF_ERRORCODE)) {
        fail_msg("MLE entry TXT status is wrong", 16384);
    }
#ifdef TEST_TXT_TPM2_LOG
    check_tpm2_event_log();
#endif
    if (guest_le(section + 8, 4) != 6 ||
        count == 0 || off != 0x98 ||
        guest_le(section, 8) < off + 0x18 ||
        !guest_le(section + off + 8, 8) ||
        section[off + 0x10] != 0) {
        fail_msg("MLE entry SINIT-MLE MDR is missing", 16384);
    }

    /*
     * The machine runs with -device intel-iommu, so the guest has a
     * DMAR ACPI table and SENTER must have copied it in right after
     * the MDRs.  Linux under tboot reads VT-d configuration only from
     * here (arch/x86/kernel/tboot.c, tboot_get_dmar_table()), so a
     * missing or malformed copy is a launch bug, not a cosmetic one.
     */
    {
        uint32_t ndmar = guest_le(section + 8 + 0x88, 4);
        uint32_t dmar_off = guest_le(section + 8 + 0x8c, 4);
        uint32_t dmar_len, i;
        uint8_t sum = 0;

        if (ndmar != 1 || dmar_off != off + count * 0x18) {
            ml_printf("smx: num_vtd_dmars=%u vtd_dmars_off=0x%x "
                      "(expected 1 and 0x%x)\n", ndmar, dmar_off,
                      off + count * 0x18);
            fail_msg("SINIT-MLE DMAR is missing or misplaced", 16384);
        }
        dmar_len = guest_le(section + dmar_off + 4, 4);
        if (section[dmar_off] != 'D' || section[dmar_off + 1] != 'M' ||
            section[dmar_off + 2] != 'A' || section[dmar_off + 3] != 'R' ||
            dmar_len < 36 || guest_le(section, 8) < dmar_off + dmar_len) {
            fail_msg("SINIT-MLE DMAR copy is not a sane DMAR table", 16384);
        }
        /* A correctly copied ACPI table still checksums to zero. */
        for (i = 0; i < dmar_len; i++) {
            sum += section[dmar_off + i];
        }
        if (sum != 0) {
            fail_msg("SINIT-MLE DMAR copy fails its ACPI checksum", 16384);
        }
        if (itd_dma(itd_find_bar(),
                    TEST_HEAP_BASE + TEST_SINIT_MLE_OFF + dmar_off) !=
            ITD_ERR_TX_FAIL) {
            fail_msg("DMA can overwrite the live TXT heap DMAR copy",
                     16384);
        } else {
            ml_printf("PASS: DPR protects the measured DMAR copy\n");
        }
    }

    /*
     * SMCTRL releases SMIs.  While the measured environment is live,
     * an SMI must not enter SMM: trigger one, verify it is held, then
     * let SMCTRL release it and verify exactly one SMM entry via
     * MSR_SMI_COUNT.  The SMP variant provides a
     * valid RLP join block, then verifies that its own AP landing
     * code ran.
     */
    {
        uint32_t pm_io;

        original_pmbase = pci_cfg_readl(ICH9_LPC_DEVFN, 0x40);
        original_acpi_ctrl = pci_cfg_readl(ICH9_LPC_DEVFN, 0x48);
        pm_io = smi_trigger_setup();
        smi_count_before = msr_read64(SMI_COUNT_MSR);
        smi_trigger(pm_io);
        smi_wait();
        if (msr_read64(SMI_COUNT_MSR) != smi_count_before) {
            fail_msg("SMI entered SMM while SMI inhibition was engaged",
                     16384);
        }
    }
    asm volatile(".byte 0x0f, 0x37" : : "a"(7), "b"(0) : "memory");
    {
        smi_wait();
        if (msr_read64(SMI_COUNT_MSR) != smi_count_before + 1) {
            fail_msg("GETSEC[SMCTRL] did not redeliver the held SMI",
                     16384);
        } else {
            ml_printf("PASS: SMI held during SENTER, redelivered by SMCTRL\n");
        }
    }
#ifdef TEST_TXT_SMP
    {
        /* Volatile: WAKEUP reads this stack block through guest RAM. */
        volatile uint32_t join[4];
        unsigned retries = 10000000;

        gp_count = 0;
        gp_err = 0xffffffffU;
        asm volatile(".byte 0x0f, 0x37" : : "a"(8) : "memory");
        if (gp_count != 1 || gp_err != 0 || ap_joined) {
            fail_msg("WAKEUP without MLE_JOIN did not #GP safely", 16384);
        }
        join[0] = 7; /* too small to contain CS and DS */
        join[1] = TEST_SINIT_BASE + ACM_GDT_OFF;
        join[2] = ACM_SEG_SEL;
        join[3] = (uint32_t)(uintptr_t)ap_landing;
        /* Volatile: this is a guest MMIO register, not ordinary RAM. */
        *(volatile uint32_t *)(TXT_PRIVATE_BASE + TXT_OFF_MLE_JOIN) =
            (uint32_t)(uintptr_t)join;
        gp_count = 0;
        asm volatile(".byte 0x0f, 0x37" : : "a"(8) : "memory");
        if (gp_count != 1 || gp_err != 0 || ap_joined) {
            fail_msg("WAKEUP with bad GDT partially released AP", 16384);
        }
        gp_count = 0;
        asm volatile(".byte 0x0f, 0x37" : : "a"(5) : "memory");
        if (gp_count != 1 || gp_err != 0 ||
            !(txt_read64(TXT_OFF_STS) & TXT_STS_SENTER_DONE)) {
            fail_msg("SEXIT abandoned a sleeping AP", 16384);
        }
        join[0] = ACM_GDT_LIMIT;
#ifdef TEST_TXT_MONITOR_WAKE
        {
            /* Volatile: a guest MMIO register, not ordinary RAM. */
            volatile uint32_t *wake = (volatile uint32_t *)
                (TXT_PUBLIC_BASE + TXT_OFF_RLP_WAKEUP);
            /* volatile: SINIT wrote this heap section outside the C flow. */
            volatile uint8_t *smd = (volatile uint8_t *)(uintptr_t)
                (TEST_HEAP_BASE + TEST_SINIT_MLE_OFF + 8);
            unsigned settle;

            if (guest_le(smd + SINIT_MLE_OFF_RLP_WAKEUP, 4) !=
                TXT_PUBLIC_BASE + TXT_OFF_RLP_WAKEUP) {
                fail_msg("SINIT did not publish the MONITOR wake address",
                         16384);
            }
            /* Only a nonzero store joins the RLPs. */
            *wake = 0;
            for (settle = 0; settle < 100000; settle++) {
                asm volatile("pause" : : : "memory");
            }
            if (ap_joined) {
                fail_msg("a zero MONITOR write released the parked AP",
                         16384);
            }
            *wake = 1;
            while (!ap_joined && retries--) {
                asm volatile("pause" : : : "memory");
            }
            if (!ap_joined) {
                fail_msg("MONITOR wake did not release parked AP", 16384);
            } else {
                ml_printf("PASS: RLP joined MLE through MONITOR wake\n");
            }
        }
#else
        gp_count = 0;
        asm volatile(".byte 0x0f, 0x37" : : "a"(8) : "memory");
        if (gp_count != 0) {
            fail_msg("WAKEUP with valid GDT raised #GP", 16384);
        }
        while (!ap_joined && retries--) {
            asm volatile("pause" : : : "memory");
        }
        if (!ap_joined) {
            fail_msg("GETSEC[WAKEUP] did not release parked AP", 16384);
        } else {
            ml_printf("PASS: RLP joined MLE through TXT.MLE_JOIN\n");
        }
#endif
    }
#else
    asm volatile(".byte 0x0f, 0x37" : : "a"(8) : "memory");
#endif

    /*
     * Finally leave the measured environment, the way an MLE does at
     * shutdown (tboot's txt_shutdown()).  SEXIT is not a reset: it
     * has to return to the next instruction, or the MLE's teardown
     * message -- and here, the rest of this function -- would be
     * unreachable.  It must clear the launch *state* while leaving
     * the launch *configuration* programmed, so a further SENTER is
     * possible in the same power cycle.
     */
    {
        uint64_t sinit_base = txt_read64(TXT_OFF_SINIT_BASE);
        uint64_t heap_base = txt_read64(TXT_OFF_HEAP_BASE);
        uint64_t dpr = txt_read64(TXT_OFF_DPR);
        uint64_t sts_after;

        asm volatile(".byte 0x0f, 0x37" : : "a"(5) : "memory");

        /* Reaching this instruction at all is half the test. */
        sts_after = txt_read64(TXT_OFF_STS);
        if ((sts_after & (TXT_STS_SENTER_DONE | TXT_STS_MEM_CONFIG_LOCK |
                          TXT_STS_PRIVATE_OPEN | TXT_STS_LOCALITY1_OPEN |
                          TXT_STS_LOCALITY2_OPEN)) ||
            !(sts_after & TXT_STS_SEXIT_DONE)) {
            ml_printf("smx: TXT.STS after SEXIT is 0x%llx\n",
                      (unsigned long long)sts_after);
            fail_msg("SEXIT left the measured-environment state set", 32768);
        }
        if (txt_read64(TXT_OFF_E2STS) & TXT_E2STS_SECRET_STS) {
            fail_msg("SEXIT did not clear the secrets flag", 32768);
        }
        if (txt_read64(TXT_OFF_SINIT_BASE) != sinit_base ||
            txt_read64(TXT_OFF_HEAP_BASE) != heap_base ||
            txt_read64(TXT_OFF_DPR) != dpr) {
            fail_msg("SEXIT cleared launch configuration registers", 32768);
        }
        /* volatile: the closed private TXT MMIO alias must not leak. */
        if (*(volatile uint32_t *)(TXT_PRIVATE_BASE + TXT_OFF_HEAP_BASE) !=
            UINT32_MAX) {
            fail_msg("private TXT MMIO remained readable after SEXIT", 32768);
        }
        if (!main_fail) {
            ml_printf("PASS: GETSEC[SEXIT] left the measured environment "
                      "and returned\n");
        }
    }

    /*
     * SEXIT also released the PMR: PMEN reads back cleared and DMA
     * into the former window succeeds again, so the guest that takes
     * over after the measured environment can DMA freely whether or
     * not it programs the IOMMU itself.
     */
    {
        uint32_t bar = itd_find_bar();

        if (vtd_readl(VTD_CSR_PMEN) != 0) {
            ml_printf("smx: PMEN=0x%x after SEXIT\n",
                      vtd_readl(VTD_CSR_PMEN));
            fail_msg("SEXIT left the PMR enabled", 65536);
        }
        if (bar && itd_dma(bar, 0x40000) != 0) {
            fail_msg("DMA into the former PMR window is still refused "
                     "after SEXIT", 65536);
        } else {
            ml_printf("PASS: SEXIT released the PMR\n");
        }
    }

    /*
     * SEXIT also released the SMI inhibition: a new SMI now enters
     * SMM immediately without waiting for SMCTRL.
     */
    {
        smi_trigger(0x1000);
        smi_wait();
        if (msr_read64(SMI_COUNT_MSR) != smi_count_before + 2) {
            fail_msg("SMI after SEXIT did not enter SMM immediately",
                     65536);
        } else {
            ml_printf("PASS: SMI inhibition released by SEXIT\n");
        }
    }
    /* Restore SeaBIOS's PM IO mapping (including the 0x604 exit port). */
    pci_cfg_writel(ICH9_LPC_DEVFN, 0x40, original_pmbase);
    pci_cfg_writel(ICH9_LPC_DEVFN, 0x48, original_acpi_ctrl);

    if (main_fail) {
        ml_printf("smx: MLE landing failed (0x%x)\n", main_fail);
        asm volatile("out %%eax, $0xf4" :: "a"(main_fail));
    } else {
        ml_printf("PASS: SENTER transferred to the MLE with heap and "
                  "CPU state intact\n");
        ml_printf("test-smx-getsec: all tests passed\n");
        asm volatile("out %%ax, %%dx" :: "a"(0x2000), "d"(0x604));
    }
    for (;;) {
        asm volatile("hlt");
    }
}

/*
 * Capture the register state before the compiler can reuse caller-saved
 * registers.  The physical MLE stub jumps here with paging disabled.
 */
static void __attribute__((naked, noreturn, used)) mle_landing(void)
{
    asm volatile("movl %%ebx, mle_seen_ebx\n"
                 "movl %%ecx, mle_seen_ecx\n"
                 "movl %%edx, mle_seen_edx\n"
                 "movl %%edi, mle_seen_eflags\n"
                 "movl %%esi, mle_seen_cr0\n"
                 "jmp mle_landing_c\n" : : : "memory");
}

static void setup_mle_entry(void)
{
    /*
     * Physical code at TEST_MLE_BASE+0x200: set a known stack, save
     * EFLAGS and CR0, turn paging off, and jump to the guest-side C
     * assertion routine.  The kernel text is not in the MLE mapping.
     */
    static const uint8_t stub[] = {
        0xbc, 0, 0, 0, 0,          /* mov esp, stack top */
        0x9c, 0x5f,                /* pushfd; pop edi */
        0x0f, 0x20, 0xc6,          /* mov esi, cr0 */
        0x0f, 0x20, 0xc0,          /* mov eax, cr0 */
        0x25, 0xff, 0xff, 0xff, 0x7f, /* and eax, ~CR0.PG */
        0x0f, 0x22, 0xc0,          /* mov cr0, eax */
        0xb8, 0, 0, 0, 0,          /* mov eax, landing */
        0xff, 0xe0,                /* jmp eax */
    };
    /* volatile: SENTER executes the bytes from guest physical RAM. */
    volatile uint8_t *code = (volatile uint8_t *)(uintptr_t)
        (TEST_MLE_BASE + 0x200);
    uint32_t stack = (uintptr_t)mle_entry_stack + sizeof(mle_entry_stack);
    uint32_t landing = (uintptr_t)mle_landing;
    uint32_t i;

    /* SINIT enters with paging disabled; the stack is physical. */
    for (i = 0; i < sizeof(stub); i++) {
        code[i] = stub[i];
    }
    for (i = 0; i < 4; i++) {
        code[1 + i] = stack >> (8 * i);
        code[22 + i] = landing >> (8 * i);
    }
    /* volatile: SINIT reads the guest heap; create the fourth section. */
    *(volatile uint64_t *)(uintptr_t)(TEST_HEAP_BASE + TEST_SINIT_MLE_OFF) = 0;
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
        case 1: /* max ACM size: EAX[31:5] is byte-positioned */
            if (type != GETSEC_PARAM_MAX_ACM_SIZE ||
                (eax & ~GETSEC_PARAM_TYPE_MASK) != 0x40000) {
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
     *    write-once, so this is the one chance), the 16 KiB SINIT
     *    reserved region at 0xE10000 (inside the DPR), and the 4 KiB heap
     *    at 0xE20000.  The SINIT region gets the synthetic ACM
     *    fixture, which precondition 3 must accept.
     */
    {
        setup_acm();
        ml_printf("smx: synthetic SINIT ACM built\n");
        setup_mle();

        txt_write64(TXT_OFF_DPR, TEST_DPR);
        if (txt_read64(TXT_OFF_DPR) != TEST_DPR) {
            fail_msg("DPR readback mismatch after programming", 64);
        }
        txt_write64(TXT_OFF_SINIT_BASE, TEST_SINIT_BASE);
        txt_write64(TXT_OFF_SINIT_SIZE, 2 * TEST_SINIT_SIZE);
        txt_write64(TXT_OFF_HEAP_BASE, TEST_HEAP_BASE);
        txt_write64(TXT_OFF_HEAP_SIZE, TEST_HEAP_SIZE);
    }
    ml_printf("smx: SINIT/HEAP/DPR programmed\n");
    {
        uint32_t bar = itd_find_bar();
        /* volatile: the CPU may still populate protected TXT heap RAM. */
        volatile uint8_t *scratch = (volatile uint8_t *)(uintptr_t)
            (TEST_HEAP_BASE + TEST_HEAP_SIZE - 1);
        uint8_t saved = *scratch;

        *scratch = 0xa5;
        if (!bar || *scratch != 0xa5 ||
            itd_dma(bar, TEST_HEAP_BASE) != ITD_ERR_TX_FAIL) {
            fail_msg("locked DPR did not exclude prelaunch PCI DMA", 64);
        } else {
            ml_printf("PASS: locked DPR excludes DMA, allows CPU writes\n");
        }
        *scratch = saved;
    }

    /* A protected SINIT alone is insufficient: the heap/DMAR must fit. */
    {
        uint8_t before[32], after[32];
        int read_before = pcr_read(17, before);

        txt_write64(TXT_OFF_HEAP_BASE, TEST_HEAP_BASE - 0x200000);
        txt_write64(TXT_OFF_ERRORCODE, 0);
        getsec_senter();
        if (txt_read64(TXT_OFF_ERRORCODE) != TXT_ERR_HEAP_INVALID ||
            !read_before || !pcr_read(17, after) || !pcr_is(before, after)) {
            fail_msg("heap outside locked DPR accepted before DRTM", 64);
        }
        txt_write64(TXT_OFF_HEAP_BASE, TEST_HEAP_BASE);
        txt_write64(TXT_OFF_HEAP_SIZE, 0x200000);
        txt_write64(TXT_OFF_ERRORCODE, 0);
        getsec_senter();
        if (txt_read64(TXT_OFF_ERRORCODE) != TXT_ERR_HEAP_INVALID ||
            !pcr_read(17, after) || !pcr_is(before, after)) {
            fail_msg("heap crossing DPR top accepted before DRTM", 64);
        } else {
            ml_printf("PASS: DPR excludes heap: rejected before PCR reset\n");
        }
        txt_write64(TXT_OFF_HEAP_SIZE, TEST_HEAP_SIZE);
    }

    /* The ECX ACM size must match the header even inside a larger slot. */
    txt_write64(TXT_OFF_ERRORCODE, 0);
    getsec_senter_size(2 * TEST_SINIT_SIZE);
    if (txt_read64(TXT_OFF_ERRORCODE) != TXT_ERR_ACM_INVALID) {
        fail_msg("SENTER accepts ECX size that disagrees with ACM header", 64);
    }

    /* Reject a PMR that leaves the MLE DMA-writable before resetting PCRs. */
    {
        /* Volatile: SENTER reads guest heap and page-table mutations. */
        volatile uint64_t *lo_size = (volatile uint64_t *)(uintptr_t)
            (TEST_HEAP_BASE + 0x28 + 0x28);
        /* Volatile: SENTER translates the first MLE page after the write. */
        volatile uint64_t *first_pte = (volatile uint64_t *)(uintptr_t)
            (TEST_MLE_PTAB + 0x2000);
        uint8_t before[32], after[32];
        int read_before = pcr_read(17, before);

        *lo_size = 0x200000; /* MLE is at TEST_MLE_BASE, above 2 MiB. */
        txt_write64(TXT_OFF_ERRORCODE, 0);
        getsec_senter();
        if (txt_read64(TXT_OFF_ERRORCODE) != TXT_ERR_PMR_INVALID ||
            !read_before || !pcr_read(17, after) || !pcr_is(before, after)) {
            fail_msg("unprotected MLE was not rejected before DRTM", 64);
        } else {
            ml_printf("PASS: PMR excludes MLE: rejected before PCR reset\n");
        }
        *lo_size = 0x1000000;
        *first_pte = 0x1200000 | 1; /* Page tables covered; MLE not. */
        txt_write64(TXT_OFF_ERRORCODE, 0);
        getsec_senter();
        if (txt_read64(TXT_OFF_ERRORCODE) != TXT_ERR_PMR_INVALID ||
            !pcr_read(17, after) || !pcr_is(before, after)) {
            fail_msg("unprotected MLE mapping was not rejected", 64);
        } else {
            ml_printf("PASS: PMR excludes mapped MLE page: rejected\n");
        }
        *first_pte = TEST_MLE_BASE | 1;
    }

    /*
     * 8a. Before any SENTER has programmed a PMR, the IOMMU is plain
     *     passthrough: the machine advertises PLMR/PHMR (txt=on),
     *     PMEN is released, and DMA into the would-be 16 MiB PMR
     *     window succeeds.  The target sits below the test image, so
     *     a refused transfer could not be blamed on unmapped RAM.
     */
    {
        uint32_t bar = itd_find_bar();

        if (!bar) {
            fail_msg("iommu-testdev not found on the PCI bus", 2048);
        }
        if (!(vtd_readl(VTD_CSR_CAP) & (VTD_CAP_PLMR | VTD_CAP_PHMR))) {
            fail_msg("CAP does not advertise PLMR/PHMR on a txt=on "
                     "machine", 2048);
        }
        if (vtd_readl(VTD_CSR_PMEN) != 0) {
            ml_printf("smx: PMEN=0x%x before launch\n",
                      vtd_readl(VTD_CSR_PMEN));
            fail_msg("PMEN is set before any SENTER programmed a PMR",
                     2048);
        }
        if (itd_dma(bar, 0x40000) != 0) {
            fail_msg("DMA into the would-be PMR window failed before "
                     "any PMR was enabled", 2048);
        } else {
            ml_printf("PASS: PMR released, DMA passthrough before "
                      "launch\n");
        }
    }

    /*
     * 8b. SENTER with valid launch inputs: the preconditions pass and
     *     the PMR is programmed into the IOMMU, then the DRTM is
     *     established over the SINIT region with the TIS hash signals
     *     (which reset PCRs 17-22 and extend PCR 17 with the
     *     region's hash).  The fourth heap section is deliberately
     *     malformed until the final entry test, so SENTER rejects it
     *     with HEAP_INVALID after measuring, without transferring away
     *     from the remaining negative tests.  STS.SENTER_DONE stays
     *     clear.
     */
    txt_write64(TXT_OFF_ERRORCODE, 0);
    ml_printf("smx: SENTER, launch inputs set ...\n");
    getsec_senter();
    {
        uint64_t ec = txt_read64(TXT_OFF_ERRORCODE);
        uint64_t sts = txt_read64(TXT_OFF_STS);

        ml_printf("smx: ERRORCODE=0x%llx STS=0x%llx\n",
                  (unsigned long long)ec, (unsigned long long)sts);
        if (ec != TXT_ERR_HEAP_INVALID) {
            fail_msg("SENTER without SINIT-MLE heap: wrong ERRORCODE",
                     128);
        }
        if (sts & TXT_STS_SENTER_DONE) {
            fail_msg("SENTER with valid inputs: SENTER_DONE set", 128);
        }
        if (ec == TXT_ERR_HEAP_INVALID &&
            !(sts & TXT_STS_SENTER_DONE)) {
            ml_printf("PASS: SENTER measures but rejects missing "
                      "SINIT-MLE heap (0x%llx)\n",
                      (unsigned long long)ec);
        }
    }

    /*
     * 8c. The step-8b SENTER validated the PMR and programmed the
     *     IOMMU before measuring, so even though it then rejected the
     *     malformed heap, the protected window is live: DMA into
     *     [0, 16 MiB) -- the os_sinit low PMR of this fixture -- must
     *     fail while DMA outside it still succeeds.  Remapping is off,
     *     so without the PMR check this DMA would bypass the IOMMU
     *     entirely.
     */
    {
        uint32_t bar = itd_find_bar();
        uint32_t pmen;

        if (!bar) {
            fail_msg("iommu-testdev not found on the PCI bus", 4096);
        }
        pmen = vtd_readl(VTD_CSR_PMEN);
        if (pmen != (VTD_PMEN_EPM | VTD_PMEN_PRS)) {
            ml_printf("smx: PMEN=0x%x after the PMR-valid SENTER\n", pmen);
            fail_msg("PMR was not enabled by the PMR-valid SENTER", 4096);
        }
        if (vtd_readl(VTD_CSR_PLMBASE) != 0 ||
            vtd_readl(VTD_CSR_PLMLIMIT) != VTD_PMR_LIMIT_16M) {
            ml_printf("smx: PLMBASE=0x%x PLMLIMIT=0x%x\n",
                      vtd_readl(VTD_CSR_PLMBASE),
                      vtd_readl(VTD_CSR_PLMLIMIT));
            fail_msg("PMR registers do not hold the os_sinit window",
                     4096);
        }
        if (itd_dma(bar, 0x40000) != ITD_ERR_TX_FAIL) {
            fail_msg("DMA into the live PMR window was not denied", 4096);
        } else if (itd_dma(bar, 0x2000000) != 0) {
            fail_msg("DMA outside the PMR window failed", 4096);
        } else {
            ml_printf("PASS: the live PMR denies DMA into the protected "
                      "window\n");
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

    /*
     * 12. ACM validation (spec precondition 3): each mutation of the
     *     fixture must be rejected with TXT_ERR_ACM_INVALID and must
     *     measure nothing.  The fixture is rebuilt after every case,
     *     so a mutation that somehow passed cannot poison the next
     *     one, and the recovery SENTER at the end proves the rebuilt
     *     fixture is still accepted -- without it a validator that
     *     rejected everything would pass this whole step.
     */
    {
        uint32_t n = sizeof(acm_mutations) / sizeof(acm_mutations[0]);
        uint32_t m;
        uint32_t bad = 0;

        for (m = 0; m < n; m++) {
            uint64_t ec;

            acm_mutate(&acm_mutations[m]);
            txt_write64(TXT_OFF_ERRORCODE, 0);
            getsec_senter();
            ec = txt_read64(TXT_OFF_ERRORCODE);

            if (ec != TXT_ERR_ACM_INVALID) {
                ml_printf("smx: ACM mutation \"%s\" gave ERRORCODE "
                          "0x%llx\n", acm_mutations[m].name,
                          (unsigned long long)ec);
                bad++;
            }

            setup_acm();
            txt_write64(TXT_OFF_SINIT_SIZE, TEST_SINIT_SIZE);
        }

        if (bad) {
            fail_msg("ACM mutations were not all rejected with "
                     "ACM_INVALID", 2048);
        } else {
            ml_printf("PASS: all %u ACM mutations rejected with 0x%llx\n",
                      n, (unsigned long long)TXT_ERR_ACM_INVALID);
        }
    }

    /*
     * 13. Recovery: the rebuilt fixture must still launch, and the
     *     re-run measurement must land on the same PCR 17 value --
     *     the mutations measured nothing, so nothing drifted.
     */
    txt_write64(TXT_OFF_ERRORCODE, 0);
    getsec_senter();
    {
        uint64_t ec = txt_read64(TXT_OFF_ERRORCODE);
        uint8_t d[32];

        if (ec != TXT_ERR_HEAP_INVALID) {
            ml_printf("smx: ERRORCODE=0x%llx\n", (unsigned long long)ec);
            fail_msg("the rebuilt ACM fixture was not accepted", 4096);
        } else if (!pcr_read(17, d)) {
            fail_msg("PCR 17 could not be read back after recovery", 4096);
        } else if (!pcr_is(d, pcr17_expected)) {
            pcr_print("17 after recovery", d);
            fail_msg("PCR 17 changed across the ACM mutation cases", 4096);
        } else {
            ml_printf("PASS: the rebuilt ACM fixture launches and "
                      "re-measures to the same PCR 17\n");
        }
    }

    /*
     * The MLE entry is a linear offset in the image, not a physical
     * pointer.  Reject both an offset outside the image and a valid
     * offset whose page table entry is absent.  Restore the header so
     * the rest of the test is independent of these mutations.
     */
    {
        /*
         * Guest physical RAM is observed asynchronously by SENTER;
         * keep the test's page table and header writes observable.
         */
        volatile uint32_t *entry = (volatile uint32_t *)(uintptr_t)
            (TEST_MLE_BASE + TEST_MLE_HDR_OFF + 0x18);
        /* volatile: SENTER reads this guest page table between writes. */
        volatile uint64_t *second_pte = (volatile uint64_t *)(uintptr_t)
            (TEST_MLE_PTAB + 0x2000 + 8);
        /* volatile: this is the adjacent guest page table entry. */
        volatile uint64_t *third_pte = second_pte + 1;
        const uint32_t bad_entries[] = { TEST_MLE_SIZE, 0x1000 };
        uint32_t i;

        for (i = 0; i < 2; i++) {
            uint64_t ec;

            if (i == 0) {
                /*
                 * Make the out-of-range offset mapped: only the image
                 * bound must reject it, not a coincidental absent PTE.
                 */
                *third_pte = TEST_MLE_BASE | 1;
            } else {
                *third_pte = 0;
                *second_pte = 0;
            }
            *entry = bad_entries[i];
            txt_write64(TXT_OFF_ERRORCODE, 0);
            getsec_senter();
            ec = txt_read64(TXT_OFF_ERRORCODE);
            if (ec != TXT_ERR_MEASURE_FAILED) {
                ml_printf("smx: invalid MLE entry 0x%x gave ERRORCODE "
                          "0x%llx\n", bad_entries[i],
                          (unsigned long long)ec);
                fail_msg("invalid MLE entry was not rejected", 8192);
            }
        }
        *entry = 0x200;
        *second_pte = (TEST_MLE_BASE + 0x1000) | 1;
        if (!main_fail) {
            ml_printf("PASS: out-of-range and unmapped MLE entries rejected\n");
        }
    }

    /*
     * 14. GETSEC is a CPL0 instruction: from CPL3 it must raise
     *     #GP(0), and with CR4.SMXE clear the #UD must take
     *     precedence over that #GP (SDM; smx_helper.c checks SMXE
     *     first).  Ring 3 is entered through a real iret with a TSS
     *     in place, so this exercises the CPL check the way a guest
     *     userspace program would hit it.
     */
    /*
     * SEXIT outside a measured environment is #GP: there is nothing
     * to leave.  Checked here, before any launch, while
     * STS.SENTER_DONE is still clear.  The successful case runs in
     * the MLE after SENTER (see mle_landing_c).
     */
    {
        gp_count = 0;
        gp_err = 0xffffffffU;
        asm volatile(".byte 0x0f, 0x37"
                     : : "a"(GETSEC_LEAF_SEXIT) : "memory");
        if (gp_count != 1 || gp_err != 0) {
            ml_printf("smx: #GP count=%d error code=0x%x\n", gp_count,
                      gp_err);
            fail_msg("GETSEC[SEXIT] outside a measured environment did "
                     "not raise #GP(0)", 8192);
        } else {
            ml_printf("PASS: GETSEC[SEXIT] outside a measured "
                      "environment raises #GP(0)\n");
        }
    }

    gdt_install();
    ml_printf("smx: ring-3 descriptors and TSS installed\n");
    {
        int ud_before;

        /* CAPABILITIES is the most innocuous leaf; CPL still wins. */
        gp_count = 0;
        gp_err = 0xffffffffU;
        enter_cpl3(GETSEC_LEAF_CAPABILITIES);
        if (gp_count != 1) {
            ml_printf("smx: #GP count=%d\n", gp_count);
            fail_msg("GETSEC[CAPABILITIES] at CPL3 did not raise #GP",
                     8192);
        } else if (gp_err != 0) {
            ml_printf("smx: #GP error code=0x%x\n", gp_err);
            fail_msg("GETSEC at CPL3 raised #GP with a non-zero error "
                     "code", 8192);
        } else {
            ml_printf("PASS: GETSEC[CAPABILITIES] at CPL3 raises "
                      "#GP(0)\n");
        }

        /*
         * SENTER from CPL3 must fault before the device sees
         * anything: ERRORCODE stays at the value written here, which
         * no SENTER path ever records.
         */
        txt_write64(TXT_OFF_ERRORCODE, 0);
        gp_count = 0;
        gp_err = 0xffffffffU;
        enter_cpl3(GETSEC_LEAF_SENTER);
        {
            uint64_t ec = txt_read64(TXT_OFF_ERRORCODE);

            if (gp_count != 1 || gp_err != 0) {
                ml_printf("smx: #GP count=%d error code=0x%x\n", gp_count,
                          gp_err);
                fail_msg("GETSEC[SENTER] at CPL3 did not raise #GP(0)",
                         8192);
            } else if (ec != 0) {
                ml_printf("smx: ERRORCODE=0x%llx\n",
                          (unsigned long long)ec);
                fail_msg("GETSEC[SENTER] at CPL3 reached the chipset",
                         8192);
            } else {
                ml_printf("PASS: GETSEC[SENTER] at CPL3 raises #GP(0) "
                          "without reaching the chipset\n");
            }
        }

        /* With SMXE clear the #UD wins, even at CPL3. */
        write_cr4(read_cr4() & ~CR4_SMXE_MASK);
        ud_before = ud_count;
        gp_count = 0;
        enter_cpl3(GETSEC_LEAF_CAPABILITIES);
        write_cr4(read_cr4() | CR4_SMXE_MASK);
        if (ud_count != ud_before + 1 || gp_count != 0) {
            ml_printf("smx: #UD count=%d (was %d), #GP count=%d\n",
                      ud_count, ud_before, gp_count);
            fail_msg("GETSEC at CPL3 with CR4.SMXE=0 did not take the "
                     "#UD precedence", 8192);
        } else {
            ml_printf("PASS: GETSEC at CPL3 with CR4.SMXE=0 raises #UD, "
                      "not #GP\n");
        }
    }

    /*
     * 15. IA32_FEATURE_CONTROL (MSR 0x3a): the register the TXT
     *     firmware programs and locks.  Check the lifecycle: the
     *     reset value, unlocked write/readback of the SENTER and
     *     VMX-on bits, #GP(0) for writes of bits the platform does
     *     not support, and #GP(0) for every write after the lock bit
     *     is set while reads keep returning the locked value.  Both
     *     RDMSR (0F 32) and WRMSR (0F 30) are 2-byte encodings, so
     *     the #GP gate's EIP step applies unchanged.
     */
    {
        uint32_t unlocked = FC_SENTER_ENABLE | FC_VMXON_IN_SMX;
        uint64_t v;

        /* Reset value: 0. */
        v = msr_read64(MSR_IA32_FEATURE_CONTROL);
        if (v != 0) {
            ml_printf("smx: feature control at boot = 0x%llx\n",
                      (unsigned long long)v);
            fail_msg("IA32_FEATURE_CONTROL is not 0 at boot", 8);
        } else {
            ml_printf("PASS: IA32_FEATURE_CONTROL resets to 0\n");
        }

        /*
         * tboot's supports_smx() requires the SENTER enable bit 15
         * (tboot's ENABLE_SENTER) to be writable.  Write it alone and
         * confirm no #GP(0) and an exact readback, so a mask that
         * covers only bits 14:8 (0x7f0) is caught here.
         */
        gp_count = 0;
        gp_err = 0xffffffffU;
        msr_write32(MSR_IA32_FEATURE_CONTROL, 1U << 15);
        if (gp_count != 0 ||
            msr_read64(MSR_IA32_FEATURE_CONTROL) != (uint64_t)(1U << 15)) {
            ml_printf("smx: #GP count=%d\n", gp_count);
            fail_msg("SENTER enable bit 15 is not writable", 8);
        } else {
            ml_printf("PASS: SENTER enable bit 15 writes and reads back\n");
        }

        /*
         * Unlocked: both SENTER enable fields and the VMX-in-SMX
         * enable bit are writable and read back exactly.
         */
        msr_write32(MSR_IA32_FEATURE_CONTROL, unlocked);
        v = msr_read64(MSR_IA32_FEATURE_CONTROL);
        if (v != (uint64_t)unlocked) {
            ml_printf("smx: feature control readback = 0x%llx\n",
                      (unsigned long long)v);
            fail_msg("unlocked IA32_FEATURE_CONTROL write did not "
                     "read back", 8);
        } else {
            ml_printf("PASS: IA32_FEATURE_CONTROL reads back 0x%x "
                      "while unlocked\n", unlocked);
        }

        /*
         * Writes of bits the platform does not support raise #GP(0)
         * and change nothing: first reserved bit 3, then the SGX
         * bit, which TCG does not implement.
         */
        gp_count = 0;
        gp_err = 0xffffffffU;
        msr_write32(MSR_IA32_FEATURE_CONTROL, unlocked | FC_RESERVED_BIT3);
        if (gp_count != 1 || gp_err != 0) {
            ml_printf("smx: #GP count=%d error code=0x%x\n",
                      gp_count, gp_err);
            fail_msg("writing reserved bit 3 did not raise #GP(0)",
                     8);
        } else if (msr_read64(MSR_IA32_FEATURE_CONTROL) !=
                   (uint64_t)unlocked) {
            fail_msg("reserved-bit write changed the stored value",
                     8);
        } else {
            ml_printf("PASS: reserved-bit write raises #GP(0) and "
                      "changes nothing\n");
        }

        gp_count = 0;
        gp_err = 0xffffffffU;
        msr_write32(MSR_IA32_FEATURE_CONTROL, unlocked | FC_SGX);
        if (gp_count != 1 || gp_err != 0) {
            ml_printf("smx: #GP count=%d error code=0x%x\n",
                      gp_count, gp_err);
            fail_msg("writing the SGX bit did not raise #GP(0)",
                     8);
        } else if (msr_read64(MSR_IA32_FEATURE_CONTROL) !=
                   (uint64_t)unlocked) {
            fail_msg("SGX-bit write changed the stored value", 8);
        } else {
            ml_printf("PASS: SGX-bit write raises #GP(0) and changes "
                      "nothing\n");
        }

        /*
         * Bit 16 is reserved.  It sits directly above the SENTER
         * enable field, so a mask written as bits 16:8 rather than
         * 15:8 would accept it; check it explicitly.
         */
        gp_count = 0;
        gp_err = 0xffffffffU;
        msr_write32(MSR_IA32_FEATURE_CONTROL, unlocked | FC_RESERVED_BIT16);
        if (gp_count != 1 || gp_err != 0) {
            ml_printf("smx: #GP count=%d error code=0x%x\n",
                      gp_count, gp_err);
            fail_msg("writing reserved bit 16 did not raise #GP(0)",
                     8);
        } else if (msr_read64(MSR_IA32_FEATURE_CONTROL) !=
                   (uint64_t)unlocked) {
            fail_msg("reserved bit 16 write changed the stored value",
                     8);
        } else {
            ml_printf("PASS: reserved bit 16 write raises #GP(0) and "
                      "changes nothing\n");
        }

        /* Lock the register with the same configuration. */
        msr_write32(MSR_IA32_FEATURE_CONTROL, unlocked | FC_LOCKED);
        v = msr_read64(MSR_IA32_FEATURE_CONTROL);
        if (v != (uint64_t)(unlocked | FC_LOCKED)) {
            ml_printf("smx: feature control after lock = 0x%llx\n",
                      (unsigned long long)v);
            fail_msg("IA32_FEATURE_CONTROL lock write did not read "
                     "back", 8);
        } else {
            ml_printf("PASS: IA32_FEATURE_CONTROL locked at 0x%x\n",
                      (unlocked | FC_LOCKED));
        }

        /*
         * Locked: any further WRMSR raises #GP(0) -- even one that
         * writes the identical value -- and the stored value is
         * unchanged, while the read still returns it.
         */
        gp_count = 0;
        gp_err = 0xffffffffU;
        msr_write32(MSR_IA32_FEATURE_CONTROL, unlocked);
        if (gp_count != 1 || gp_err != 0) {
            ml_printf("smx: #GP count=%d error code=0x%x\n",
                      gp_count, gp_err);
            fail_msg("write after lock did not raise #GP(0)", 8);
        } else {
            v = msr_read64(MSR_IA32_FEATURE_CONTROL);
            if (v != (uint64_t)(unlocked | FC_LOCKED)) {
                ml_printf("smx: feature control after failed write = "
                          "0x%llx\n", (unsigned long long)v);
                fail_msg("write after lock changed the stored value",
                         8);
            } else {
                ml_printf("PASS: write after lock raises #GP(0) and "
                          "the read still returns the locked value\n");
            }
        }
    }

#ifdef TEST_TXT_TPM2_LOG
    /* Bad log pointers, sizes and ext-data all fail before PCR reset. */
    {
        txt_guest_u8 *ext = (txt_guest_u8 *)(uintptr_t)
            (TEST_HEAP_BASE + 0x28 + 0x5c);
        txt_guest_u64 *addr = (txt_guest_u64 *)(ext + 8);
        txt_guest_u32 *capacity = (txt_guest_u32 *)(ext + 16);
        txt_guest_u32 *end_type = (txt_guest_u32 *)(ext + 28);
        uint8_t before[32], after[32];
        unsigned i;

        if (!pcr_read(17, before)) {
            fail_msg("PCR17 unavailable before bad-log test", 16384);
        }
        for (i = 0; i < 5; i++) {
            if (i == 0) {
                *addr = TEST_HEAP_BASE; /* overlaps the TXT heap */
            } else if (i == 1) {
                *addr = 0xfed00000; /* HPET MMIO, not guest RAM */
            } else if (i == 2) {
                *capacity = 128; /* cannot fit even a single-bank log */
            } else if (i == 3) {
                *end_type = 8; /* duplicate malformed element */
            } else {
                *addr = TEST_MLE_BASE; /* would overwrite measured image */
            }
            txt_write64(TXT_OFF_ERRORCODE, 0);
            getsec_senter();
            if (txt_read64(TXT_OFF_ERRORCODE) != TXT_ERR_HEAP_INVALID ||
                !pcr_read(17, after) || !pcr_is(before, after)) {
                fail_msg("bad TPM2 log changed the DRTM PCR", 16384);
            }
            *addr = TEST_EVENT_LOG_BASE;
            *capacity = TEST_EVENT_LOG_SIZE;
            *end_type = 0;
        }
        ml_printf("PASS: malformed TPM2 logs rejected before PCR reset\n");
    }
#endif
    if (main_fail) {
        return main_fail;
    }

    setup_mle_entry();
    txt_write64(TXT_OFF_ERRORCODE, 0);
    ml_printf("smx: final SENTER to the MLE ...\n");
    getsec_senter();
    fail_msg("successful SENTER returned instead of entering MLE", 16384);
    return main_fail;
}
