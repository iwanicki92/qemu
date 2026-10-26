/*
 * QEMU Intel TXT (Trusted Execution Technology) chipset device
 *
 * Emulates the TXT public and private configuration spaces at
 * 0xFED30000 / 0xFED20000 on the q35 machine ("-machine txt=on").
 *
 * Register storage, defaults, command register semantics,
 * write-once DPR locking and the DRTM measurement plumbing used by
 * the measured launch flow (GETSEC[SENTER] standing in for the
 * SINIT ACM).  See docs/specs/intel-txt.rst for the register map
 * and the overall design.
 *
 * Copyright (c) 2026 Michał Kopeć <michal@nozomi.space>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "e820_memory_layout.h"
#include "fw_cfg.h"
#include "hw/core/boards.h"
#include "hw/i386/intel_iommu.h"
#include "hw/i386/intel_txt.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/sysbus.h"
#include "hw/i386/x86-iommu.h"
#include "migration/vmstate.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/units.h"
#include "qom/object.h"
#include "system/runstate.h"
#include "system/tpm_util.h"
#include "target/i386/cpu.h"
#include "trace.h"

#ifdef CONFIG_TPM
#include "crypto/hash.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/tpm_backend.h"
#endif

struct IntelTxtState {
    SysBusDevice parent_obj;

    MemoryRegion mmio_public;
    MemoryRegion mmio_private;

    /* TXT.STS */
    uint64_t sts;
    /* TXT.ESTS */
    uint64_t ests;
    /* TXT.ERRORCODE */
    uint64_t errorcode;
    /* TXT.SPAD */
    uint64_t spad;
    /* TXT.SINIT.BASE / TXT.SINIT.SIZE */
    uint64_t sinit_base;
    uint64_t sinit_size;
    /* TXT.MLE_JOIN */
    uint64_t mle_join;
    /* TXT.HEAP_BASE / TXT.HEAP_SIZE */
    uint64_t heap_base;
    uint64_t heap_size;
    /* TXT.MSEG_BASE / TXT.MSEG_SIZE */
    uint64_t mseg_base;
    uint64_t mseg_size;
    /* TXT.BIOSACM_ERRORCODE */
    uint64_t biosacm_errorcode;
    /* TXT.DPR */
    uint64_t dpr;
    /* TXT.E2STS */
    uint64_t e2sts;

    /*
     * MONITOR-based RLP wakeup, chosen by the MLE through
     * os_sinit_data.capabilities and answered by publishing
     * TXT_RLP_WAKEUP in sinit_mle_data.rlp_wakeup_addr.  False leaves
     * GETSEC[WAKEUP] as the only way to join the RLPs.
     */
    bool rlp_wake_monitor;

    /*
     * SMI inhibition while a measured environment is live: engaged
     * by a successful SENTER, released by SEXIT or GETSEC[SMCTRL].
     * SMIs arriving while it is set are held per CPU and redelivered
     * on release (see intel_txt_hold_smi / intel_txt_release_smis).
     */
    bool smi_inhibit;

    /* TXT.DIDVID, configurable for experimentation (see spec) */
    uint64_t didvid;

    /* The DPR txt-firmware=on sets up on every reset, 0 without it */
    uint64_t fw_dpr_base;

#ifdef CONFIG_TPM
    /*
     * TPM backend the DRTM measurements are submitted through.
     * Resolved at realize; a device link, not migratable state.
     */
    TPMBackend *tpm;
#endif
};

/*
 * TXT configuration registers are 64 bits wide. Accept aligned quadword
 * accesses or aligned 32-bit accesses to either half for 32-bit firmware;
 * smaller or misaligned accesses are rejected by the memory core.
 */

/* DPR has 1 MiB granularity and protects a half-open physical range. */
static bool intel_txt_dpr_range(uint64_t dpr, uint64_t *base, uint64_t *top)
{
    uint64_t size = (dpr >> 4) & 0xff;
    uint64_t top_mb = (dpr >> 20) & 0xfff;

    if (!(dpr & TXT_DPR_LOCK) || !size || size > top_mb) {
        return false;
    }
    *base = (top_mb - size) << 20;
    *top = top_mb << 20;
    return true;
}

bool intel_txt_dpr_blocks(IntelTxtState *s, hwaddr addr, size_t len)
{
    uint64_t base, top;

    if (!len || !intel_txt_dpr_range(qatomic_read(&s->dpr), &base, &top) ||
        addr >= top) {
        return false;
    }
    return addr >= base || len > base - addr;
}

static uint64_t intel_txt_reg_read64(IntelTxtState *s, hwaddr addr)
{
    /*
     * TXT.PUBLIC_KEY is a 4-quadword register: every qword of the
     * range reports the fixed placeholder (see the spec).
     */
    if (addr >= TXT_PUBLIC_KEY &&
        addr < TXT_PUBLIC_KEY + 4 * sizeof(uint64_t)) {
        return TXT_PUBLIC_KEY_PLACEHOLDER;
    }

    switch (addr) {
    case TXT_STS:
        return s->sts;
    case TXT_ESTS:
        return s->ests;
    case TXT_ERRORCODE:
        return s->errorcode;
    case TXT_SPAD:
        return s->spad;
    case TXT_VER_FSBIF:
        return TXT_VER_FSBIF_PROD_FUSED;
    case TXT_DIDVID:
        return s->didvid;
    case TXT_CAPABILITIES:
        return TXT_CAPABILITIES_DPR;
    case TXT_SINIT_BASE:
        return s->sinit_base;
    case TXT_SINIT_SIZE:
        return s->sinit_size;
    case TXT_MLE_JOIN:
        return s->mle_join;
    case TXT_HEAP_BASE:
        return s->heap_base;
    case TXT_HEAP_SIZE:
        return s->heap_size;
    case TXT_MSEG_BASE:
        return s->mseg_base;
    case TXT_MSEG_SIZE:
        return s->mseg_size;
    case TXT_BIOSACM_ERRORCODE:
        return s->biosacm_errorcode;
    case TXT_DPR:
        return s->dpr;
    case TXT_E2STS:
        return s->e2sts;
    default:
        /* write-only command registers */
        return 0;
    }
}

#ifdef CONFIG_TPM
static IntelIOMMUState *intel_txt_iommu(void)
{
    X86IOMMUState *x86_iommu = x86_iommu_get_default();
    Object *iommu = x86_iommu ?
        object_dynamic_cast(OBJECT(&x86_iommu->busdev),
                            TYPE_INTEL_IOMMU_DEVICE) : NULL;

    return iommu ? INTEL_IOMMU_DEVICE(iommu) : NULL;
}
#endif

static void intel_txt_reg_write64(IntelTxtState *s, hwaddr addr,
                                  uint64_t val)
{
    switch (addr) {
    case TXT_ESTS:
        /* W1C on the defined bits */
        s->ests &= ~(val & TXT_ESTS_W1C_MASK);
        break;
    case TXT_ERRORCODE:
        s->errorcode = val;
        break;
    case TXT_CMD_RESET:
        /*
         * On real hardware this resets the platform but, unlike a
         * normal reset, TXT_RESET_STS remains readable afterwards
         * so the boot firmware can tell that a TXT reset occurred.
         */
        s->ests |= TXT_ESTS_TXT_RESET_STS;
        trace_txt_reset_request();
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
        break;
    case TXT_CMD_CLOSE_PRIVATE:
        s->sts &= ~TXT_STS_PRIVATE_OPEN;
        trace_txt_close_private();
        break;
    case TXT_SPAD:
        s->spad = val;
        break;
    case TXT_SINIT_BASE:
        s->sinit_base = val;
        break;
    case TXT_SINIT_SIZE:
        s->sinit_size = val;
        break;
    case TXT_MLE_JOIN:
        s->mle_join = val;
        break;
    case TXT_HEAP_BASE:
        s->heap_base = val;
        break;
    case TXT_HEAP_SIZE:
        s->heap_size = val;
        break;
    case TXT_MSEG_BASE:
        s->mseg_base = val;
        break;
    case TXT_MSEG_SIZE:
        s->mseg_size = val;
        break;
    case TXT_DPR:
        if (s->dpr & TXT_DPR_LOCK) {
            /* write-once: locked, ignore */
            trace_txt_reg_write_ignored("public", addr, val);
            break;
        }
        val &= TXT_DPR_MASK;
#ifdef CONFIG_TPM
        if ((val & TXT_DPR_LOCK) && ((val >> 4) & 0xff)) {
            uint64_t base, top;
            IntelIOMMUState *iommu = intel_txt_iommu();
            Error *err = NULL;

            if (!intel_txt_dpr_range(val, &base, &top) || !iommu) {
                error_report("TXT: cannot lock a nonempty DPR without "
                             "valid bounds and an intel-iommu device");
                trace_txt_reg_write_ignored("public", addr, val);
                break;
            }
            if (!intel_iommu_set_txt_dpr(iommu, base, top, &err)) {
                error_report_err(err);
                trace_txt_reg_write_ignored("public", addr, val);
                break;
            }
        }
#endif
        qatomic_set(&s->dpr, val);
        if (val & TXT_DPR_LOCK) {
            trace_txt_dpr_locked(val);
        }
        break;
    case TXT_CMD_OPEN_LOCALITY1:
        s->sts |= TXT_STS_LOCALITY1_OPEN;
        trace_txt_locality_open(1);
        break;
    case TXT_CMD_CLOSE_LOCALITY1:
        s->sts &= ~TXT_STS_LOCALITY1_OPEN;
        trace_txt_locality_close(1);
        break;
    case TXT_CMD_OPEN_LOCALITY2:
        s->sts |= TXT_STS_LOCALITY2_OPEN;
        trace_txt_locality_open(2);
        break;
    case TXT_CMD_CLOSE_LOCALITY2:
        s->sts &= ~TXT_STS_LOCALITY2_OPEN;
        trace_txt_locality_close(2);
        break;
    case TXT_CMD_SECRETS:
        s->e2sts |= TXT_E2STS_SECRET_STS;
        trace_txt_secrets(true);
        break;
    case TXT_CMD_NO_SECRETS:
        s->e2sts &= ~TXT_E2STS_SECRET_STS;
        trace_txt_secrets(false);
        break;
    default:
        /*
         * Read-only registers (VER.FSBIF, DIDVID, CAPABILITIES,
         * BIOSACM_ERRORCODE, PUBLIC_KEY, E2STS) and commands that
         * have no effect in the semantic model (UNLOCK_MEM_CONFIG).
         */
        trace_txt_reg_write_ignored("public", addr, val);
        break;
    }
}

static uint64_t intel_txt_reg_read(IntelTxtState *s, hwaddr addr,
                                   unsigned size)
{
    uint64_t val = intel_txt_reg_read64(s, addr & ~7);

    return size == 4 ? (val >> ((addr & 4) * 8)) & UINT32_MAX : val;
}

static void intel_txt_reg_write(IntelTxtState *s, hwaddr addr,
                                uint64_t val, unsigned size)
{
    hwaddr reg = addr & ~7;
    unsigned shift = (addr & 4) * 8;
    uint64_t mask;

    if (size == 8) {
        intel_txt_reg_write64(s, addr, val);
        return;
    }
    if (addr & 4) {
        /* High halves of command registers do not execute commands. */
        switch (reg) {
        case TXT_CMD_RESET:
        case TXT_CMD_CLOSE_PRIVATE:
        case TXT_CMD_UNLOCK_MEM:
        case TXT_CMD_OPEN_LOCALITY1:
        case TXT_CMD_CLOSE_LOCALITY1:
        case TXT_CMD_OPEN_LOCALITY2:
        case TXT_CMD_CLOSE_LOCALITY2:
        case TXT_CMD_SECRETS:
        case TXT_CMD_NO_SECRETS:
            trace_txt_reg_write_ignored("public", addr, val);
            return;
        default:
            break;
        }
    }
    if (reg == TXT_ESTS) {
        /* Preserve write-one-to-clear semantics, not the old status. */
        intel_txt_reg_write64(s, reg, val << shift);
        return;
    }

    mask = UINT64_C(0xffffffff) << shift;
    val = (intel_txt_reg_read64(s, reg) & ~mask) | ((val << shift) & mask);
    intel_txt_reg_write64(s, reg, val);
}

static uint64_t intel_txt_public_read(void *opaque, hwaddr addr,
                                      unsigned size)
{
    IntelTxtState *s = INTEL_TXT(opaque);
    uint64_t val = intel_txt_reg_read(s, addr, size);

    trace_txt_reg_read("public", addr, val);
    return val;
}

/*
 * The MLE joins the RLPs by storing a nonzero value to the address
 * SINIT published in sinit_mle_data.rlp_wakeup_addr.  Only a launched
 * environment that negotiated MONITOR wake reacts; anything else
 * leaves the RLPs parked, exactly like a rejected GETSEC[WAKEUP].
 */
static void intel_txt_monitor_wake(IntelTxtState *s, uint64_t val)
{
#if defined(CONFIG_TPM) && defined(CONFIG_TCG)
    IntelTxtRlpEntry rlp;

    if (!s->rlp_wake_monitor || val == 0) {
        trace_txt_monitor_wake_ignored(val);
        return;
    }
    if (!intel_txt_wakeup(s, &rlp)) {
        return;
    }
    trace_txt_monitor_wake(val);
    /* Device dispatch already holds the BQL; run_on_cpu requires it. */
    BQL_LOCK_GUARD();
    intel_txt_join_parked_rlps(&rlp);
#else
    trace_txt_monitor_wake_ignored(val);
#endif
}

static void intel_txt_public_write(void *opaque, hwaddr addr,
                                   uint64_t val, unsigned size)
{
    IntelTxtState *s = INTEL_TXT(opaque);

    trace_txt_reg_write("public", addr, val);
    if (addr == TXT_RLP_WAKEUP) {
        intel_txt_monitor_wake(s, val);
        return;
    }
    intel_txt_reg_write(s, addr, val, size);
}

static uint64_t intel_txt_private_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    IntelTxtState *s = INTEL_TXT(opaque);
    uint64_t val;

    /*
     * The pre-launch mirror remains accessible to firmware.  Once a
     * launch has closed private space, do not leak its register values
     * through the alias (including after SEXIT).  SENTER reopens it.
     */
    if (!(s->sts & TXT_STS_PRIVATE_OPEN) &&
        (s->sts & (TXT_STS_SENTER_DONE | TXT_STS_SEXIT_DONE))) {
        val = size == 4 ? UINT32_MAX : UINT64_MAX;
    } else {
        val = intel_txt_reg_read(s, addr, size);
    }
    trace_txt_reg_read("private", addr, val);
    return val;
}

static void intel_txt_private_write(void *opaque, hwaddr addr,
                                    uint64_t val, unsigned size)
{
    IntelTxtState *s = INTEL_TXT(opaque);

    /*
     * The MLE publishes the RLP join block here after SENTER, while
     * private space is open.  Other private registers are reserved for
     * SINIT (which the semantic launch models without ACM execution).
     */
    if ((addr & ~7) == TXT_MLE_JOIN &&
        (s->sts & (TXT_STS_SENTER_DONE | TXT_STS_PRIVATE_OPEN)) ==
        (TXT_STS_SENTER_DONE | TXT_STS_PRIVATE_OPEN)) {
        trace_txt_reg_write("private", addr, val);
        intel_txt_reg_write(s, addr, val, size);
    } else {
        trace_txt_reg_write_ignored("private", addr, val);
    }
}

static const MemoryRegionOps intel_txt_public_ops = {
    .read = intel_txt_public_read,
    .write = intel_txt_public_write,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
        .unaligned = false,
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

/*
 * DRTM measurement plumbing (see docs/specs/intel-txt.rst, "Steps
 * performed by QEMU" steps a and d): QEMU stands in for the SINIT
 * ACM, so the chipset's locality-4 hash sequence is performed with
 * ordinary TPM2 commands sent through the linked TPM backend.
 */
#ifdef CONFIG_TPM

/*
 * TPM2 wire constants for the DRTM measurement commands (TCG TPM
 * 2.0 Library Specification, Part 2: Structures, Table 22 and the
 * TPM2_PCR_Reset / TPM2_PCR_Extend command definitions).  These are
 * deliberately duplicated here rather than taken from
 * backends/tpm/tpm_int.h, which is backend-internal.
 */
enum {
    TPM2_ST_NO_SESSIONS = 0x8001,
    TPM2_ST_SESSIONS   = 0x8002,
    TPM2_CC_PCR_Extend = 0x00000182,
    TPM2_RS_PW         = 0x40000009, /* password auth session handle */
    TPM2_RC_SUCCESS    = 0x00000000,
};

/*
 * Response header: tag (u16) + responseSize (u32) + responseCode (u32).
 * A failing TPM2 command answers with this header alone and no
 * parameter area, so 10 bytes is the shortest legal response.  It is
 * also the size tpm_util_write_fatal_error_response() writes when the
 * backend transport itself fails -- that one carries the TPM 1.2
 * TPM_TAG_RSP_COMMAND tag and TPM_FAIL (9) rather than a TPM2 code,
 * which is harmless here because only the error code is ever read.
 * Anything shorter than this is genuinely truncated.
 */
#define TPM2_RESP_HDR_SIZE 10
#define TPM2_CC_GET_CAPABILITY 0x0000017a
#define TPM2_CAP_PCRS          0x00000005

/*
 * Response buffer handed to the backend.
 *
 * Deliberately a fixed size rather than tpm_backend_get_buffer_size():
 * that getter is *not* a pure query.  For the emulator backend it runs
 * tpm_emulator_set_buffer_size(), which begins with
 * tpm_emulator_stop_tpm() -- a CMD_STOP to swtpm -- and does not send a
 * CMD_INIT afterwards.  Every other in-tree caller pairs it with
 * tpm_backend_startup_tpm() and caches the result once
 * (hw/tpm/tpm_tis_common.c:821+854, hw/tpm/tpm_crb.c:461+463,
 * hw/tpm/tpm_spapr.c:302+307), so calling it per command would stop the
 * guest's TPM before each measurement.  Caching it at realize would be
 * wrong too: the TXT device is created during machine init, before the
 * -device tpm-tis frontend exists to re-initialise the backend.
 *
 * 4096 is the buffer size the TPM 2.0 spec guarantees, and the value
 * the emulator backend itself falls back to.  The commands built here
 * are far smaller (65 bytes for a one-bank PCR_Extend, 87 for two banks) and their responses are a few dozen bytes.
 */
#define INTEL_TXT_TPM_BUF_SIZE 4096

/* The DRTM measurements always run at TIS locality 4 (spec step d) */
#define INTEL_TXT_DRTM_LOCTY 4

/* The DRTM PCR extended with the SINIT ACM hashes (spec step d,
   first component). */

/*
 * The launch inputs must address guest RAM below 4 GiB; this also
 * bounds the SINIT region read below.
 */
#define INTEL_TXT_GUEST_32BIT_LIMIT (1ull << 32)

/*
 * Max ACM size, in bytes.  Must match the AC execution area that
 * GETSEC[PARAMETERS] advertises (GETSEC_PARAM_MAX_ACM_SIZE): the SDG
 * tells system software to check the module against that value, so a
 * loader that honors it must not then be refused here.  Bounds the
 * SINIT region read rather than allocating whatever the guest asked
 * for.  Production SINIT ACMs run from roughly 53 KiB (SNB/IVB) to
 * 132 KiB (TGL), so 32 KiB rejected every real module.
 */
#define INTEL_TXT_MAX_ACM_SIZE 0x40000

/*
 * MLE measurement (spec step c).
 *
 * The TXT heap is a sequence of sections, each preceded by a u64 byte
 * count that includes the count itself (tboot
 * include/txt/heap.h:383-425): bios_data, os_mle_data, os_sinit_data,
 * sinit_mle_data.  Only os_sinit_data is read here.
 *
 * Inside os_sinit_data, the MLE is described by mle_ptab, mle_size and
 * mle_hdr_base.  Note what these mean, because it is easy to get wrong:
 *
 *  - mle_ptab is a *physical* address, of a 3-level page table
 *    (PDPT -> PD -> PT, 4 KiB pages) that maps the MLE.
 *  - The MLE occupies linear addresses [0, mle_size) in that mapping;
 *    linear 0 is the first measured byte.  Both tboot
 *    (txt/txt.c build_mle_pagetable) and GRUB
 *    (loader/slaunch/txt.c grub_txt_setup_mle_ptab) build a flat map,
 *    but the table is walked here rather than assumed flat.
 *  - mle_hdr_base is a *linear offset* within that range, not a
 *    physical address: tboot computes it as
 *    "&g_mle_hdr - &_mle_start" and comments it "linear addr (offset
 *    from MLE base)".
 *  - mle_start_off / mle_end_off in the MLE header are the loader's
 *    own bookkeeping, used to derive mle_size; SINIT does not need
 *    them and neither do we.
 */
#define INTEL_TXT_OS_SINIT_MIN_VER 4

/*
 * Upper bound on the MLE.  The SDG defines os_sinit_data "MLE Size"
 * in bytes and sets no architectural limit; TrenchBoot's MLEs far
 * exceed the 2 MiB a single page table covers (Xen 0x3cfa20, Linux
 * around 54 MiB), and intel_txt_mle_xlate() walks a PD with many
 * page tables anyway.  64 MiB is a QEMU resource bound on the
 * measurement buffer and the page-by-page read cost, not an
 * architectural one.
 */
#define INTEL_TXT_MAX_MLE_SIZE (16384 * 4096)

/* Page/table address bits of a 64-bit PDPTE/PDE/PTE. */
#define INTEL_TXT_PTE_ADDR_MASK 0x000ffffffffff000ULL

/*
 * PCR 17 accumulates the launch "details" (SDG Table 1) and PCR 18
 * carries the MLE hash (MLE Dev Guide, DRTM PCR usage).
 */
#define INTEL_TXT_DRTM_PCR_ACM 17
#define INTEL_TXT_DRTM_PCR_MLE 18

/* Offsets within os_sinit_data (tboot include/txt/heap.h, __packed) */
#define OS_SINIT_OFF_VERSION      0x00   /* u32 */
#define OS_SINIT_OFF_FLAGS        0x04   /* u32 */
#define OS_SINIT_OFF_MLE_PTAB     0x08   /* u64 */
#define OS_SINIT_OFF_MLE_SIZE     0x10   /* u64 */
#define OS_SINIT_OFF_MLE_HDR_BASE 0x18   /* u64 */
#define OS_SINIT_OFF_PMR_LO_BASE  0x20   /* u64 */
#define OS_SINIT_OFF_PMR_LO_SIZE  0x28   /* u64 */
#define OS_SINIT_OFF_PMR_HI_BASE  0x30   /* u64 */
#define OS_SINIT_OFF_PMR_HI_SIZE  0x38   /* u64 */
#define OS_SINIT_OFF_LCP_PO_BASE  0x40   /* u64 */
#define OS_SINIT_OFF_LCP_PO_SIZE  0x48   /* u64 */
#define OS_SINIT_OFF_CAPABILITIES 0x50   /* u32 */
#define OS_SINIT_OFF_EXT_DATA     0x5c   /* version 7: after EFI RSDP */
#define TXT_EXT_END              0
#define TXT_EXT_EVENT_LOG_2_1    8
#define TXT_EXT_HEADER_SIZE      8
#define TXT_EXT_LOG_SIZE         28      /* header + 20-byte descriptor */
#define TXT_LOG_MAX_SIZE         (1024 * 1024)
#define TXT_LOG_EV_ACTION        5       /* semantic QEMU measurements */

/*
 * SINIT event types (SDG "TPM Event Log", Table 35).  Only the ones
 * whose inputs this model actually has are produced; the rest of the
 * table describes LCP policy, the AUX index, TPM NV public info, the
 * real ACM signer key and Boot Guard manifests, none of which QEMU
 * models.  See docs/specs/intel-txt.rst.
 */
#define TXT_EVTYPE_BASE              0x400
#define TXT_EVTYPE_HASH_START        (TXT_EVTYPE_BASE + 2)
#define TXT_EVTYPE_MLE_HASH          (TXT_EVTYPE_BASE + 4)
#define TXT_EVTYPE_CPU_SCRTM_STAT    (TXT_EVTYPE_BASE + 11)
#define TXT_EVTYPE_OSSINITDATA_CAP   (TXT_EVTYPE_BASE + 15)

/* EVTYPE_CPU_SCRTM_STAT event data: SCRTM was established by the CPU. */
#define TXT_SCRTM_STAT_CPU       1
#define TXT_LOG_NR_BANKS         4

static const struct {
    uint16_t alg;
    QCryptoHashAlgo crypto;
    uint8_t len;
} intel_txt_log_banks[TXT_LOG_NR_BANKS] = {
    { TPM2_ALG_SHA1, QCRYPTO_HASH_ALGO_SHA1, 20 },
    { TPM2_ALG_SHA256, QCRYPTO_HASH_ALGO_SHA256, 32 },
    { TPM2_ALG_SHA384, QCRYPTO_HASH_ALGO_SHA384, 48 },
    { TPM2_ALG_SHA512, QCRYPTO_HASH_ALGO_SHA512, 64 },
};

typedef struct IntelTxtEventLog {
    uint64_t addr;
    uint64_t ext_addr;
    uint32_t size;
    uint8_t banks;
    uint8_t acm[TXT_LOG_NR_BANKS][64];
    uint8_t mle[TXT_LOG_NR_BANKS][64];
    /* Digests of the two DWORD events, over caps_data/scrtm_data. */
    uint8_t caps[TXT_LOG_NR_BANKS][64];
    uint8_t scrtm[TXT_LOG_NR_BANKS][64];
    uint8_t caps_data[4];
    uint8_t scrtm_data[4];
} IntelTxtEventLog;

/* os_sinit_data.capabilities bits (tboot include/mle.h, txt_caps_t) */
#define TXT_CAPS_RLP_WAKE_GETSEC   BIT(0)
#define TXT_CAPS_RLP_WAKE_MONITOR  BIT(1)
#define OS_SINIT_MIN_SIZE         0x20
#define OS_SINIT_PMR_MIN_SIZE     0x40
/* Through capabilities, i.e. enough to choose the RLP wake mechanism. */
#define OS_SINIT_CAPS_MIN_SIZE    0x54
#define TXT_PMR_GRANULARITY      (2 * 1024 * 1024ULL)

/* Offsets within the MLE header (tboot include/mle.h mle_hdr_t) */
#define MLE_HDR_OFF_UUID          0x00   /* 16 bytes */
#define MLE_HDR_OFF_LENGTH        0x10   /* u32 */
#define MLE_HDR_OFF_VERSION       0x14   /* u32 */
#define MLE_HDR_OFF_ENTRY_POINT   0x18   /* u32 */
#define MLE_HDR_OFF_FIRST_VALID   0x1c   /* u32 */
#define MLE_HDR_MIN_SIZE          0x30

/*
 * SINIT ACM header (tboot tboot/include/txt/acmod.h, acm_hdr_t).
 * Offsets are bytes from the ACM base; header_len, scratch_size and
 * size are counts of 32-bit words, not bytes.
 */
#define ACM_HDR_OFF_MODULE_TYPE     0x00   /* u16 */
#define ACM_HDR_OFF_MODULE_SUBTYPE  0x02   /* u16 */
#define ACM_HDR_OFF_HEADER_LEN      0x04   /* u32, dwords */
#define ACM_HDR_OFF_MODULE_VENDOR   0x10   /* u32 */
#define ACM_HDR_OFF_SIZE            0x18   /* u32, dwords */
#define ACM_HDR_OFF_GDT_LIMIT       0x28   /* u32 */
#define ACM_HDR_OFF_GDT_BASE        0x2c   /* u32 */
#define ACM_HDR_OFF_SEG_SEL         0x30   /* u32 */
#define ACM_HDR_OFF_ENTRY_POINT     0x34   /* u32 */
#define ACM_HDR_OFF_SCRATCH_SIZE    0x7c   /* u32, dwords */
/* Through the RSA-2048 signature and the 143-dword scratch area. */
#define ACM_HDR_MIN_SIZE            0x4c0

#define ACM_TYPE_CHIPSET            0x02
#define ACM_SUBTYPE_SINIT           0x00
#define ACM_VENDOR_INTEL            0x8086

/* ACM info table (acm_info_table_t), at (header_len + scratch_size) * 4 */
#define ACM_INFO_OFF_UUID             0x00   /* 16 bytes */
#define ACM_INFO_OFF_CHIPSET_ACM_TYPE 0x10   /* u8 */
#define ACM_INFO_OFF_VERSION          0x11   /* u8 */
#define ACM_INFO_OFF_CHIPSET_ID_LIST  0x14   /* u32, offset from ACM base */
/* Through the version-3 fields (capabilities, acm_ver, reserved). */
#define ACM_INFO_MIN_SIZE             0x28

#define ACM_CHIPSET_TYPE_SINIT      0x01
#define ACM_INFO_MIN_VERSION        3

/* acm_chipset_id_list_t: a u32 count followed by acm_chipset_id_t */
#define ACM_CHIPSET_ID_LIST_OFF_COUNT 0x00   /* u32 */
#define ACM_CHIPSET_ID_LIST_HDR_SIZE  0x04
#define ACM_CHIPSET_ID_SIZE           0x10
#define ACM_CHIPSET_ID_OFF_FLAGS      0x00   /* u32, bit 0: revision mask */
#define ACM_CHIPSET_ID_OFF_VENDOR     0x04   /* u16 */
#define ACM_CHIPSET_ID_OFF_DEVICE     0x06   /* u16 */
#define ACM_CHIPSET_ID_OFF_REVISION   0x08   /* u16 */
#define ACM_CHIPSET_ID_FLAG_REV_MASK  0x1

/*
 * sinit_mle_data (tboot include/txt/heap.h, sinit_mle_data_t) and
 * the memory descriptors it carries.  Offsets are bytes from the
 * start of the structure, which is the data part of the heap section
 * (after its size prefix); the fields marked "TPM 1.2" and the VT-d
 * DMAR fields are all zero in QEMU.
 */
#define SINIT_MLE_OFF_VERSION           0x00  /* u32 */
#define SINIT_MLE_OFF_BIOS_ACM_ID       0x04  /* 20 bytes, TPM 1.2 */
#define SINIT_MLE_OFF_EDX_SENTER_FLAGS  0x18  /* u32, TPM 1.2 */
#define SINIT_MLE_OFF_MSEG_VALID        0x1c  /* u64, TPM 1.2 */
#define SINIT_MLE_OFF_SINIT_HASH        0x24  /* 20 bytes, TPM 1.2 */
#define SINIT_MLE_OFF_MLE_HASH          0x38  /* 20 bytes, TPM 1.2 */
#define SINIT_MLE_OFF_STM_HASH          0x4c  /* 20 bytes, TPM 1.2 */
#define SINIT_MLE_OFF_LCP_POLICY_HASH   0x60  /* 20 bytes, TPM 1.2 */
#define SINIT_MLE_OFF_LCP_POLICY_CTRL   0x74  /* u32, TPM 1.2 */
#define SINIT_MLE_OFF_RLP_WAKEUP_ADDR   0x78  /* u32 */
#define SINIT_MLE_OFF_RESERVED          0x7c  /* u32 */
#define SINIT_MLE_OFF_NUM_MDRS          0x80  /* u32 */
#define SINIT_MLE_OFF_MDRS_OFF          0x84  /* u32, from section start */
#define SINIT_MLE_OFF_NUM_VTD_DMARS     0x88  /* u32 */
#define SINIT_MLE_OFF_VTD_DMARS_OFF     0x8c  /* u32 */
#define SINIT_MLE_FIXED_SIZE            0x90  /* version 6 fixed part */
#define SINIT_MLE_VERSION               6

/* sinit_mdr_t: u64 base, u64 length, u8 mem_type, 7 reserved bytes */
/* ACPI 6.x "Description Header", common to RSDT/XSDT/DMAR. */
#define ACPI_TABLE_HEADER_SIZE          36
/* Sanity bound on any ACPI table this code will read or checksum. */
#define INTEL_TXT_MAX_ACPI_TABLE        (1024 * 1024)

#define SINIT_MDR_SIZE                  0x18
#define SINIT_MDR_OFF_BASE              0x00  /* u64 */
#define SINIT_MDR_OFF_LENGTH            0x08  /* u64 */
#define SINIT_MDR_OFF_MEM_TYPE          0x10  /* u8 */
/* The only MDR type tboot's e820 verification treats as covering */
#define MDR_MEMTYPE_GOOD                0x00

/* ACM_UUID_V3 from tboot include/txt/acmod.h, in wire order */
static const uint8_t intel_txt_acm_uuid[16] = {
    0xaa, 0x3a, 0xc0, 0x7f, 0xa7, 0x46, 0xdb, 0x18,
    0x2e, 0xac, 0x69, 0x8f, 0x8d, 0x41, 0x7f, 0x5a,
};

/* MLE_HDR_UUID from tboot include/mle.h, in wire (little-endian) order */
static const uint8_t intel_txt_mle_uuid[16] = {
    0x5a, 0xac, 0x82, 0x90, 0x6f, 0x47, 0xa7, 0x74,
    0x0f, 0x5c, 0x55, 0xa2, 0xcb, 0x51, 0xb6, 0x42,
};

/*
 * Fixed password-authorization area appended to both DRTM commands:
 * the TPM2_RS_PW session handle with an empty nonce and HMAC.
 */
struct tpm2_pw_auth_area {
    uint32_t session_handle;
    uint16_t nonce_size;
    uint8_t  session_attributes;
    uint16_t hmac_size;
} QEMU_PACKED; /* 9 bytes */

/* TPM2_PCR_Reset command: exactly 27 bytes on the wire */
/*
 * TPM2_PCR_Extend command: the fixed header part, followed by the
 * TPML_DIGEST_VALUES entries (2-byte algorithm tag plus the digest
 * itself, repeated count times).
 */
struct tpm2_cmd_pcr_extend {
    uint16_t tag;
    uint32_t cmd_size;
    uint32_t cmd_code;
    uint32_t pcr_handle;
    uint32_t auth_size;
    struct tpm2_pw_auth_area auth;
    uint32_t count;
    uint8_t  digest[];
} QEMU_PACKED;

/*
 * Submit one prebuilt TPM2 command to the linked TPM backend at
 * locality 4 and wait for the response.
 *
 * The helper owns the BQL and the backend's single in-flight command
 * slot: tpm_backend_deliver_request() has one slot and silently drops
 * a second submission (which the in-flight check below rejects), and
 * tpm_backend_finish_sync() spins aio_poll() on the main AioContext,
 * which requires the BQL (see include/qemu/aio-wait.h).  Holding the
 * BQL here keeps the measurement path strictly one command at a time
 * and non-reentrant; it also means no other BQL-protected frontend
 * can interleave a submission with ours.
 */
static int intel_txt_tpm_send_response(IntelTxtState *s, const uint8_t *cmd,
                                       uint32_t cmd_len, uint8_t *result,
                                       size_t *result_len, Error **errp)
{
    TPMBackendCmd tcmd;
    uint8_t *resp;
    uint32_t resp_len;
    size_t resp_size;
    int ret = 0;

    BQL_LOCK_GUARD();

    if (s->tpm == NULL) {
        error_setg(errp, "Intel TXT device has no TPM backend");
        return -1;
    }
    /*
     * A backend with no frontend attached can deliver no useful
     * measurement, so refuse to measure through it.  This is a
     * configuration sanity check rather than crash avoidance: the
     * completion callback no longer dereferences a NULL tpmif for
     * device-originated commands (TPMBackendCmd::no_frontend_notify
     * skips the frontend notify entirely, see
     * backends/tpm/tpm_backend.c, tpm_backend_request_completed()).
     * It cannot be checked at realize: the TXT device is created
     * during machine init, before the -device tpm-tis frontend is
     * instantiated.
     */
    if (tpm_find() == NULL) {
        error_setg(errp, "Intel TXT needs a TPM frontend device; "
                   "add -device tpm-tis,tpmdev=...");
        return -1;
    }
    if (tpm_backend_request_pending(s->tpm)) {
        error_setg(errp, "a TPM request is already in flight");
        return -1;
    }
    resp_size = INTEL_TXT_TPM_BUF_SIZE;
    if (resp_size < cmd_len) {
        error_setg(errp, "TPM buffer is 0x%" PRIx64 " bytes, "
                   "too small for the 0x%" PRIx32 " byte command",
                   (uint64_t)resp_size, cmd_len);
        return -1;
    }

    resp = g_malloc(resp_size);
    tcmd = (TPMBackendCmd) {
        .locty = INTEL_TXT_DRTM_LOCTY,
        .in = cmd,
        .in_len = cmd_len,
        .out = resp,
        .out_len = resp_size,
        /*
         * The response goes to our own buffer, not to a TPM frontend
         * data buffer: completing it must not run the frontend's
         * request_completed (state machine corruption, spurious IRQ)
         * for a command the guest never sent.
         */
        .no_frontend_notify = true,
    };
    tpm_backend_deliver_request(s->tpm, &tcmd);
    tpm_backend_finish_sync(s->tpm);

    resp_len = tpm_cmd_get_size(resp);
    if (resp_len < TPM2_RESP_HDR_SIZE || resp_len > resp_size) {
        error_setg(errp, "TPM backend returned a truncated response "
                   "(%u of 0x%" PRIx64 " bytes)",
                   resp_len, (uint64_t)resp_size);
        ret = -1;
    } else if (tpm_cmd_get_errcode(resp) != TPM2_RC_SUCCESS) {
        uint32_t errcode = tpm_cmd_get_errcode(resp);

        trace_txt_drtm_tpm_error(errcode);
        error_setg(errp, "TPM2 command at locality 4 failed: "
                   "response code 0x%" PRIx32, errcode);
        ret = -1;
    } else if (result_len) {
        if (*result_len < resp_len) {
            error_setg(errp, "TPM response of %u bytes exceeds %zu-byte "
                       "destination", resp_len, *result_len);
            ret = -1;
        } else {
            memcpy(result, resp, resp_len);
            *result_len = resp_len;
        }
    }
    g_free(resp);
    return ret;
}

static int intel_txt_tpm_send(IntelTxtState *s, const uint8_t *cmd,
                              uint32_t cmd_len, Error **errp)
{
    return intel_txt_tpm_send_response(s, cmd, cmd_len, NULL, NULL, errp);
}

/*
 * Build the 27-byte TPM2_PCR_Reset command for @pcr (0-based PCR
 * index) into @cmd.
 */
/*
 * Build the TPM2_PCR_Extend command for @pcr carrying the @n digests
 * in @digests into @cmd (exactly @cmd_len bytes, as precomputed by
 * the caller).
 */
static void intel_txt_build_pcr_extend(uint8_t *cmd, uint32_t cmd_len,
                                       uint32_t pcr,
                                       const TPMDigestValue *digests,
                                       size_t n)
{
    struct tpm2_cmd_pcr_extend *t = (void *)cmd;
    size_t off = sizeof(*t);
    size_t i;

    t->tag = cpu_to_be16(TPM2_ST_SESSIONS);
    t->cmd_size = cpu_to_be32(cmd_len);
    t->cmd_code = cpu_to_be32(TPM2_CC_PCR_Extend);
    t->pcr_handle = cpu_to_be32(pcr);
    t->auth_size = cpu_to_be32(sizeof(t->auth));
    t->auth = (struct tpm2_pw_auth_area) {
        .session_handle = cpu_to_be32(TPM2_RS_PW),
        .nonce_size = 0,
        .session_attributes = 0,
        .hmac_size = 0,
    };
    t->count = cpu_to_be32(n);

    for (i = 0; i < n; i++) {
        stw_be_p(cmd + off, digests[i].alg);
        memcpy(cmd + off + 2, digests[i].digest, digests[i].len);
        off += 2 + digests[i].len;
    }
}

/*
 * Extend PCR @pcr with the @n digests in @digests at locality 4
 * (spec step d).
 */
int intel_txt_drtm_extend_pcr(IntelTxtState *s, uint32_t pcr,
                              const TPMDigestValue *digests, size_t n,
                              Error **errp)
{
    uint32_t cmd_len = sizeof(struct tpm2_cmd_pcr_extend);
    uint8_t *cmd;
    int ret;

    if (n == 0) {
        error_setg(errp, "no digests given for the PCR %u extend", pcr);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        bool supported = false;

        for (unsigned j = 0; j < TXT_LOG_NR_BANKS; j++) {
            if (digests[i].alg == intel_txt_log_banks[j].alg &&
                digests[i].len == intel_txt_log_banks[j].len) {
                supported = true;
                break;
            }
        }
        if (!supported) {
            error_setg(errp, "digest %zu: unsupported algorithm 0x%" PRIx16
                       " with %zu-byte digest", i, digests[i].alg,
                       digests[i].len);
            return -1;
        }
    }

    for (size_t i = 0; i < n; i++) {
        cmd_len += 2 + (uint32_t)digests[i].len;
    }

    cmd = g_malloc(cmd_len);
    intel_txt_build_pcr_extend(cmd, cmd_len, pcr, digests, n);
    trace_txt_drtm_extend_pcr(pcr, n);
    ret = intel_txt_tpm_send(s, cmd, cmd_len, errp);
    g_free(cmd);
    return ret;
}

/*
 * Staged GETSEC[SENTER] measured launch (see
 * docs/specs/intel-txt.rst, "Semantic measured launch"): QEMU stands
 * in for the SINIT ACM.  This slice validates the launch inputs,
 * performs step a (reset the DRTM PCRs) and the first component of
 * step d (extend PCR 17 with the SHA-1 and SHA-256 hashes of the
 * SINIT ACM region), then stops short of the MLE transfer: no
 * STS.SENTER_DONE, no control transfer, and a defined
 * "launch incomplete" TXT.ERRORCODE instead of a successful launch.
 * That staging state is sanctioned by the master plan (a loader
 * checking ERRORCODE/STS sees a failed launch); see the numbered
 * deviation in the spec.
 *
 * Called from the GETSEC helper (vCPU context, TCG only); the BQL is
 * taken inside intel_txt_tpm_send() and must not be taken again here.
 */
/*
 * Establish the DRTM over @data with the TIS hash signals at locality
 * 4 (spec steps a and d).  Unlike the PCR_Extend path this runs
 * entirely on the backend's control channel: there is no
 * TPMBackendCmd, so none of the single-slot serialisation of
 * intel_txt_tpm_send() applies and nothing blocks on aio_poll().  The
 * BQL is still taken because the control channel is a chardev.
 */
static int intel_txt_drtm_hash_measure(IntelTxtState *s, const uint8_t *data,
                                       size_t len, Error **errp)
{
    BQL_LOCK_GUARD();

    if (s->tpm == NULL) {
        error_setg(errp, "Intel TXT device has no TPM backend");
        return -1;
    }
    /*
     * The hash signals travel on the control channel rather than as a
     * TPMBackendCmd, so they cannot collide with the backend's single
     * command slot.  They can still interleave with a guest TIS
     * command already in flight on the data channel: swtpm serialises
     * the two, but the ordering of that guest command against the PCR
     * reset would be undefined.  SENTER is a quiescence point on
     * hardware, so refuse rather than measure into an unclear order.
     */
    if (tpm_backend_request_pending(s->tpm)) {
        error_setg(errp, "a TPM request is already in flight");
        return -1;
    }

    trace_txt_drtm_hash_start(INTEL_TXT_DRTM_LOCTY, len);

    if (tpm_backend_hash_sequence(s->tpm, data, len, errp) < 0) {
        return -1;
    }

    trace_txt_drtm_hash_done(len);

    return 0;
}

/*
 * Trace the digests that go into the DRTM PCRs.  They are otherwise
 * unobservable: the ACM digest is computed inside the TPM by the
 * _TPM_Hash_* sequence and never returned, and the MLE digest is
 * consumed directly by the extend.  Exposing both makes a PCR value
 * reproducible offline -- replay Extend() from zero over these and
 * the MLE's own event log and the result must equal what the guest
 * reads back from sysfs.
 */
static void intel_txt_trace_digest(const char *what,
                                   const uint8_t *sha1, size_t sha1_len,
                                   const uint8_t *sha256, size_t sha256_len)
{
    g_autofree char *h1 = NULL;
    g_autofree char *h256 = NULL;

    if (!trace_event_get_state_backends(TRACE_TXT_DRTM_DIGEST)) {
        return;
    }
    h1 = g_malloc0(sha1_len * 2 + 1);
    h256 = g_malloc0(sha256_len * 2 + 1);
    for (size_t i = 0; i < sha1_len; i++) {
        sprintf(h1 + i * 2, "%02x", sha1[i]);
    }
    for (size_t i = 0; i < sha256_len; i++) {
        sprintf(h256 + i * 2, "%02x", sha256[i]);
    }
    trace_txt_drtm_digest(what, h1, h256);
}

/* Read @len bytes of guest memory, reporting the failing address. */
static bool intel_txt_gread(uint64_t addr, void *buf, size_t len, Error **errp)
{
    if (address_space_read(&address_space_memory, addr,
                           MEMTXATTRS_UNSPECIFIED, buf, len) != MEMTX_OK) {
        error_setg(errp, "cannot read %zu bytes of guest memory at 0x%"
                   PRIx64, len, addr);
        return false;
    }
    return true;
}

static bool intel_txt_gread_u32(uint64_t addr, uint32_t *out, Error **errp)
{
    uint32_t v;

    if (!intel_txt_gread(addr, &v, sizeof(v), errp)) {
        return false;
    }
    *out = le32_to_cpu(v);
    return true;
}

static bool intel_txt_gread_u64(uint64_t addr, uint64_t *out, Error **errp)
{
    uint64_t v;

    if (!intel_txt_gread(addr, &v, sizeof(v), errp)) {
        return false;
    }
    *out = le64_to_cpu(v);
    return true;
}

/* Write @len bytes of guest memory, reporting the failing address. */
static bool intel_txt_gwrite(uint64_t addr, const void *buf, size_t len,
                             Error **errp)
{
    if (address_space_write(&address_space_memory, addr,
                           MEMTXATTRS_UNSPECIFIED, buf, len) != MEMTX_OK) {
        error_setg(errp, "cannot write %zu bytes of guest memory at 0x%"
                   PRIx64, len, addr);
        return false;
    }
    return true;
}

/*
 * Translate MLE linear offset @lin to a guest physical address using the
 * page table at @ptab: PDPT[0] -> PD -> PT -> 4 KiB page.  Only the
 * first PDPT entry is used, matching what both loaders build, but the
 * PD and PT are indexed properly so a larger MLE still resolves.
 */
static bool intel_txt_mle_xlate(uint64_t ptab, uint64_t lin, uint64_t *phys,
                                uint64_t *pd_phys, uint64_t *pt_phys,
                                Error **errp)
{
    uint64_t pdpte, pde, pte;
    uint64_t pd = 0, pt = 0;

    if (!intel_txt_gread_u64(ptab, &pdpte, errp)) {
        return false;
    }
    if (!(pdpte & 1)) {
        error_setg(errp, "MLE page table: PDPT entry 0 not present");
        return false;
    }
    pd = pdpte & INTEL_TXT_PTE_ADDR_MASK;
    if (!intel_txt_gread_u64(pd + ((lin >> 21) & 0x1ff) * 8,
                             &pde, errp)) {
        return false;
    }
    if (!(pde & 1)) {
        error_setg(errp, "MLE page table: no PD entry for linear 0x%"
                   PRIx64, lin);
        return false;
    }
    pt = pde & INTEL_TXT_PTE_ADDR_MASK;
    if (!intel_txt_gread_u64(pt + ((lin >> 12) & 0x1ff) * 8,
                             &pte, errp)) {
        return false;
    }
    if (!(pte & 1)) {
        error_setg(errp, "MLE page table: no PT entry for linear 0x%"
                   PRIx64, lin);
        return false;
    }
    *phys = (pte & INTEL_TXT_PTE_ADDR_MASK) | (lin & 0xfff);
    if (pd_phys) {
        *pd_phys = pd;
    }
    if (pt_phys) {
        *pt_phys = pt;
    }
    return true;
}

/*
 * Parse the size-prefixed TXT heap sections (tboot include/txt/heap.h,
 * "TXT heap data format and field accessor fns"): bios_data,
 * os_mle_data, os_sinit_data and sinit_mle_data follow one another at
 * HEAP_BASE, each preceded by a u64 byte count that includes the count
 * itself.  Reads the first three sizes and requires that the sections
 * fit in HEAP_SIZE.  The caller is responsible for the heap register
 * preconditions (HEAP_BASE/SIZE set, the heap entirely below 4 GiB),
 * which also bound every offset computed from them.
 */
static bool intel_txt_heap_parse(IntelTxtState *s,
                                 uint64_t *bios_sz, uint64_t *os_mle_sz,
                                 uint64_t *os_sinit_sz, Error **errp)
{
    if (!intel_txt_gread_u64(s->heap_base, bios_sz, errp) ||
        !intel_txt_gread_u64(s->heap_base + *bios_sz, os_mle_sz, errp) ||
        !intel_txt_gread_u64(s->heap_base + *bios_sz + *os_mle_sz,
                             os_sinit_sz, errp)) {
        return false;
    }
    if (*bios_sz < sizeof(uint64_t) || *os_mle_sz < sizeof(uint64_t) ||
        *os_sinit_sz < sizeof(uint64_t) ||
        *bios_sz + *os_mle_sz + *os_sinit_sz > s->heap_size) {
        error_setg(errp, "TXT heap sections do not fit in HEAP_SIZE "
                   "(bios 0x%" PRIx64 ", os_mle 0x%" PRIx64
                   ", os_sinit 0x%" PRIx64 ", heap 0x%" PRIx64 ")",
                   *bios_sz, *os_mle_sz, *os_sinit_sz, s->heap_size);
        return false;
    }
    return true;
}

typedef struct IntelTxtPmrs {
    uint64_t lo_base, lo_size, hi_base, hi_size;
} IntelTxtPmrs;

static bool intel_txt_pmr_covers(const IntelTxtPmrs *pmr,
                                 uint64_t phys, uint64_t size)
{
    return (phys >= pmr->lo_base && size <= pmr->lo_size &&
            phys - pmr->lo_base <= pmr->lo_size - size) ||
           (pmr->hi_size && phys >= pmr->hi_base &&
            size <= pmr->hi_size &&
            phys - pmr->hi_base <= pmr->hi_size - size);
}

/*
 * Check PMR inputs before any PCR is reset. An uncovered page of the
 * MLE or its page tables would remain DMA-writable after launch.
 */
static bool intel_txt_validate_pmrs(IntelTxtState *s, IntelTxtPmrs *pmr,
                                    uint64_t *errorcode, Error **errp)
{
    uint64_t bios_sz, os_mle_sz, os_sinit_sz, os_sinit;
    uint64_t ptab, mle_size, phys, pd_phys, pt_phys;

    *errorcode = TXT_ERRORCODE_PMR_INVALID;
    if (!intel_txt_heap_parse(s, &bios_sz, &os_mle_sz, &os_sinit_sz,
                              errp)) {
        return false;
    }
    if (os_sinit_sz < sizeof(uint64_t) + OS_SINIT_PMR_MIN_SIZE) {
        error_setg(errp, "os_sinit_data (0x%" PRIx64 ") at heap 0x%" PRIx64
                   " too short for VT-d PMRs", os_sinit_sz, s->heap_base);
        return false;
    }
    os_sinit = s->heap_base + bios_sz + os_mle_sz + sizeof(uint64_t);
    if (!intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_MLE_PTAB,
                             &ptab, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_MLE_SIZE,
                             &mle_size, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_PMR_LO_BASE,
                             &pmr->lo_base, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_PMR_LO_SIZE,
                             &pmr->lo_size, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_PMR_HI_BASE,
                             &pmr->hi_base, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_PMR_HI_SIZE,
                             &pmr->hi_size, errp)) {
        return false;
    }
    if (!pmr->lo_size ||
        ((pmr->lo_base | pmr->lo_size | pmr->hi_base | pmr->hi_size) &
         (TXT_PMR_GRANULARITY - 1)) ||
        pmr->lo_base >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        pmr->lo_size > INTEL_TXT_GUEST_32BIT_LIMIT - pmr->lo_base ||
        (pmr->hi_size &&
         (pmr->hi_base < INTEL_TXT_GUEST_32BIT_LIMIT ||
          pmr->hi_size > UINT64_MAX - pmr->hi_base)) ||
        (!pmr->hi_size && pmr->hi_base) ||
        ptab == 0 || (ptab & 0xfff) ||
        ptab >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        /* MLE Size is in bytes; no page alignment is required */
        mle_size == 0 ||
        mle_size > INTEL_TXT_MAX_MLE_SIZE ||
        !intel_txt_pmr_covers(pmr, ptab, 4096)) {
        error_setg(errp, "invalid VT-d PMR ranges or MLE page tables "
                   "not protected");
        return false;
    }
    for (uint64_t offset = 0; offset < mle_size; offset += 4096) {
        if (!intel_txt_mle_xlate(ptab, offset, &phys, &pd_phys,
                                 &pt_phys, errp)) {
            *errorcode = TXT_ERRORCODE_MEASURE_FAILED;
            return false;
        }
        if (!intel_txt_pmr_covers(pmr, pd_phys, 4096) ||
            !intel_txt_pmr_covers(pmr, pt_phys, 4096) ||
            !intel_txt_pmr_covers(pmr, phys, 4096)) {
            error_setg(errp, "MLE page or page table at physical 0x%" PRIx64
                       " is outside VT-d PMR protection", phys);
            return false;
        }
    }
    return true;
}

/* Query the enabled PCR banks before constructing any Spec ID or PCR event. */
static bool intel_txt_event_log_banks(IntelTxtState *s, uint8_t *banks,
                                      Error **errp)
{
    uint8_t cmd[22], rsp[INTEL_TXT_TPM_BUF_SIZE];
    size_t len = sizeof(rsp), pos = 19;
    uint32_t count;

    stw_be_p(cmd, TPM2_ST_NO_SESSIONS);
    stl_be_p(cmd + 2, sizeof(cmd));
    stl_be_p(cmd + 6, TPM2_CC_GET_CAPABILITY);
    stl_be_p(cmd + 10, TPM2_CAP_PCRS);
    stl_be_p(cmd + 14, 0); /* property: ignored for TPM_CAP_PCRS */
    stl_be_p(cmd + 18, 1); /* propertyCount */
    if (intel_txt_tpm_send_response(s, cmd, sizeof(cmd), rsp, &len, errp) < 0) {
        return false;
    }
    if (len < pos || lduw_be_p(rsp) != TPM2_ST_NO_SESSIONS ||
        rsp[10] != 0 || ldl_be_p(rsp + 11) != TPM2_CAP_PCRS) {
        error_setg(errp, "TPM2_GetCapability(PCRS) returned an invalid or "
                   "partial response");
        return false;
    }
    count = ldl_be_p(rsp + 15);
    *banks = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint16_t alg;
        uint8_t select_size, bit;

        if (len - pos < 3) {
            goto malformed;
        }
        alg = lduw_be_p(rsp + pos);
        select_size = rsp[pos + 2];
        pos += 3;
        if (select_size < 3 || select_size > len - pos) {
            goto malformed;
        }
        /* Both PCR17 and PCR18 must be active in each reported bank. */
        bit = rsp[pos + 2] & 0x06;
        if (bit) {
            bool supported = false;

            if (bit != 0x06) {
                error_setg(errp, "TPM PCR17/18 bank 0x%x is only partially "
                           "allocated", alg);
                return false;
            }
            for (unsigned j = 0; j < TXT_LOG_NR_BANKS; j++) {
                if (intel_txt_log_banks[j].alg == alg) {
                    if (*banks & BIT(j)) {
                        goto malformed;
                    }
                    *banks |= BIT(j);
                    supported = true;
                    break;
                }
            }
            if (!supported) {
                error_setg(errp, "active DRTM PCR bank 0x%x is not "
                           "supported by the semantic TXT model", alg);
                return false;
            }
        }
        pos += select_size;
    }
    if (pos != len || !*banks) {
        goto malformed;
    }
    return true;
malformed:
    error_setg(errp, "TPM2_GetCapability(PCRS) returned malformed selections");
    return false;
}

/* Never write a log through MMIO, ROM or a hole in guest RAM. */
static bool intel_txt_log_is_ram(uint64_t addr, uint32_t size)
{
    while (size) {
        hwaddr xlat, n = size;
        MemoryRegion *mr = address_space_translate(&address_space_memory,
                                                    addr, &xlat, &n, true,
                                                    MEMTXATTRS_UNSPECIFIED);

        if (!mr || !memory_region_is_ram(mr) || !n) {
            return false;
        }
        addr += n;
        size -= n;
    }
    return true;
}

/* Validate the TPM2 v7 OS-to-SINIT extended element and its log address. */
static bool intel_txt_event_log_prepare(IntelTxtState *s,
                                        IntelTxtEventLog *log, Error **errp)
{
    uint64_t bios_sz, os_mle_sz, os_sinit_sz, os_sinit, remaining, ext;
    uint64_t ptab, mle_size, phys, pd, pt, os_mle_payload;
    uint32_t version, type, size, count = 0;
    uint8_t desc[20];
    bool found = false, ended = false;

    if (!intel_txt_heap_parse(s, &bios_sz, &os_mle_sz, &os_sinit_sz, errp)) {
        return false;
    }
    os_sinit = s->heap_base + bios_sz + os_mle_sz + sizeof(uint64_t);
    if (!intel_txt_gread_u32(os_sinit, &version, errp)) {
        return false;
    }
    if (version < 7) { /* TPM 1.2 and the existing version-6 fixture */
        return true;
    }
    /*
     * Event data for the two DWORD events, captured here so the log
     * and the extends cannot disagree about them later.  The S-CRTM
     * status is 1 because GETSEC[PARAMETERS] advertises processor
     * SCRTM; the capabilities are whatever the MLE negotiated.
     */
    {
        uint32_t caps = 0;

        if (os_sinit_sz >= sizeof(uint64_t) + OS_SINIT_OFF_CAPABILITIES + 4 &&
            !intel_txt_gread_u32(os_sinit + OS_SINIT_OFF_CAPABILITIES,
                                 &caps, errp)) {
            return false;
        }
        stl_le_p(log->caps_data, caps);
        stl_le_p(log->scrtm_data, TXT_SCRTM_STAT_CPU);
    }
    if (os_sinit_sz < sizeof(uint64_t) + OS_SINIT_OFF_EXT_DATA +
                        TXT_EXT_HEADER_SIZE) {
        error_setg(errp, "TPM2 os_sinit_data has no extended data");
        return false;
    }
    remaining = os_sinit_sz - sizeof(uint64_t) - OS_SINIT_OFF_EXT_DATA;
    ext = os_sinit + OS_SINIT_OFF_EXT_DATA;
    while (remaining >= TXT_EXT_HEADER_SIZE) {
        if (!intel_txt_gread_u32(ext, &type, errp) ||
            !intel_txt_gread_u32(ext + 4, &size, errp)) {
            return false;
        }
        if (size < TXT_EXT_HEADER_SIZE || size > remaining) {
            break;
        }
        if (type == TXT_EXT_END) {
            ended = (size == TXT_EXT_HEADER_SIZE);
            break;
        }
        if (type == TXT_EXT_EVENT_LOG_2_1) {
            if (found || size != TXT_EXT_LOG_SIZE) {
                break;
            }
            if (!intel_txt_gread(ext + 8, desc, sizeof(desc), errp)) {
                return false;
            }
            found = true;
            log->ext_addr = ext + 8;
            log->addr = ldq_le_p(desc);
            log->size = ldl_le_p(desc + 8);
            if (ldl_le_p(desc + 12) > log->size ||
                ldl_le_p(desc + 16) > log->size) {
                break;
            }
        }
        ext += size;
        remaining -= size;
        if (++count > 256) {
            break;
        }
    }
    /* The loader may reserve the event log within its OS-MLE data. */
    os_mle_payload = s->heap_base + bios_sz + sizeof(uint64_t);
    if (!found || !ended ||
        log->size > TXT_LOG_MAX_SIZE ||
        log->addr == 0 ||
        log->addr >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        log->size > INTEL_TXT_GUEST_32BIT_LIMIT - log->addr ||
        ((log->addr < s->heap_base + s->heap_size &&
          s->heap_base < log->addr + log->size) &&
         (log->addr < os_mle_payload ||
          log->size > os_mle_sz - sizeof(uint64_t) ||
          log->addr - os_mle_payload >
              os_mle_sz - sizeof(uint64_t) - log->size)) ||
        (log->addr < s->sinit_base + s->sinit_size &&
         s->sinit_base < log->addr + log->size) ||
        !intel_txt_log_is_ram(log->addr, log->size)) {
        error_setg(errp, "invalid TPM2 event-log pointer or heap data "
                   "(log=0x%" PRIx64 "/%u, os_mle=0x%" PRIx64 "/0x%" PRIx64
                   ", heap=0x%" PRIx64 "/0x%" PRIx64 ", found=%u, end=%u)",
                   log->addr, log->size, os_mle_payload,
                   os_mle_sz - sizeof(uint64_t), s->heap_base,
                   s->heap_size, found, ended);
        return false;
    }
    /* The log must not overwrite bytes measured into PCR18 or its mappings. */
    if (!intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_MLE_PTAB,
                             &ptab, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_MLE_SIZE,
                             &mle_size, errp)) {
        return false;
    }
    for (uint64_t off = 0; off < mle_size; off += 4096) {
        if (!intel_txt_mle_xlate(ptab, off, &phys, &pd, &pt, errp)) {
            return false;
        }
        if ((phys < log->addr + log->size &&
             log->addr < phys + 4096) ||
            (pd < log->addr + log->size &&
             log->addr < pd + 4096) ||
            (pt < log->addr + log->size &&
             log->addr < pt + 4096) ||
            (ptab < log->addr + log->size &&
             log->addr < ptab + 4096)) {
            error_setg(errp, "TPM2 event log overlaps measured MLE or "
                       "its page tables");
            return false;
        }
    }
    if (!intel_txt_event_log_banks(s, &log->banks, errp)) {
        return false;
    }
    /* Every record and its digests must fit before any PCR is reset. */
    {
        /* ACM, MLE x2, then caps and S-CRTM for each of PCR 17 and 18. */
        const size_t nr_records = 7;
        size_t needed = 60 + 4 * ctpop8(log->banks) + 1;

        for (unsigned i = 0; i < TXT_LOG_NR_BANKS; i++) {
            if (log->banks & BIT(i)) {
                needed += nr_records * (2 + intel_txt_log_banks[i].len);
            }
        }
        /* Per-record header and eventSize, plus the DWORD event data. */
        needed += nr_records * (12 + 4) + 4 * sizeof(uint32_t);
        if (needed > log->size) {
            error_setg(errp, "TPM2 event log size %u is too small for "
                       "%zu bytes of measurements", log->size, needed);
            return false;
        }
    }
    return true;
}

/* Append a TCG_PCR_EVENT2 whose digest matches the model's actual extend. */
static size_t intel_txt_log_append(uint8_t *dst, uint32_t pcr,
                                   uint32_t event_type,
                                   const IntelTxtEventLog *log,
                                   const uint8_t digests[TXT_LOG_NR_BANKS][64],
                                   const void *event_data, size_t data_len)
{
    size_t off = 12;

    stl_le_p(dst, pcr);
    stl_le_p(dst + 4, event_type);
    stl_le_p(dst + 8, ctpop8(log->banks));
    for (unsigned i = 0; i < TXT_LOG_NR_BANKS; i++) {
        if (!(log->banks & BIT(i))) {
            continue;
        }
        stw_le_p(dst + off, intel_txt_log_banks[i].alg);
        memcpy(dst + off + 2, digests[i], intel_txt_log_banks[i].len);
        off += 2 + intel_txt_log_banks[i].len;
    }
    stl_le_p(dst + off, data_len);
    if (data_len) {
        memcpy(dst + off + 4, event_data, data_len);
    }
    return off + 4 + data_len;
}

/*
 * Hash @data in every active bank into @out, then extend it into @pcr.
 * The digests stored in @out are the ones the log will carry, so a
 * replay of the log reproduces the PCR exactly.
 */
static int intel_txt_extend_event(IntelTxtState *s, IntelTxtEventLog *log,
                                  uint32_t pcr, const void *data,
                                  size_t len,
                                  uint8_t out[TXT_LOG_NR_BANKS][64],
                                  Error **errp)
{
    TPMDigestValue digests[TXT_LOG_NR_BANKS];
    size_t nr = 0;

    for (unsigned i = 0; i < TXT_LOG_NR_BANKS; i++) {
        g_autofree uint8_t *digest = NULL;
        size_t dlen = 0;

        if (!(log->banks & BIT(i))) {
            continue;
        }
        if (qcrypto_hash_bytes(intel_txt_log_banks[i].crypto, data, len,
                               &digest, &dlen, errp) < 0) {
            return -1;
        }
        g_assert(dlen == intel_txt_log_banks[i].len);
        memcpy(out[i], digest, dlen);
        digests[nr++] = (TPMDigestValue) {
            .alg = intel_txt_log_banks[i].alg,
            .digest = out[i], .len = dlen,
        };
    }
    if (nr == 0) {
        return 0;
    }
    return intel_txt_drtm_extend_pcr(s, pcr, digests, nr, errp);
}

/*
 * Step d, continued: the launch-context events this model can honestly
 * produce.  PCR 17 also takes the MLE digest (SDG Table 1 lists the
 * MLE among the PCR 17 "details"); PCR 18 already received it in
 * intel_txt_measure_mle().  Both PCRs then take the OsSinitData
 * capabilities DWORD and the processor S-CRTM status DWORD, which
 * SDG Tables 1 and 2 extend to 17 and 18 alike.
 */
static int intel_txt_extend_context(IntelTxtState *s, IntelTxtEventLog *log,
                                    Error **errp)
{
    TPMDigestValue mle_digests[TXT_LOG_NR_BANKS];
    size_t nr = 0;

    if (!log->banks) {
        return 0; /* version-6 launch: no TPM2 log, keep the old PCR set */
    }
    for (unsigned i = 0; i < TXT_LOG_NR_BANKS; i++) {
        if (!(log->banks & BIT(i))) {
            continue;
        }
        mle_digests[nr++] = (TPMDigestValue) {
            .alg = intel_txt_log_banks[i].alg,
            .digest = log->mle[i], .len = intel_txt_log_banks[i].len,
        };
    }
    if (nr && intel_txt_drtm_extend_pcr(s, INTEL_TXT_DRTM_PCR_ACM,
                                        mle_digests, nr, errp) < 0) {
        return -1;
    }
    for (uint32_t pcr = INTEL_TXT_DRTM_PCR_ACM;
         pcr <= INTEL_TXT_DRTM_PCR_MLE; pcr++) {
        if (intel_txt_extend_event(s, log, pcr, log->caps_data,
                                   sizeof(log->caps_data), log->caps,
                                   errp) < 0 ||
            intel_txt_extend_event(s, log, pcr, log->scrtm_data,
                                   sizeof(log->scrtm_data), log->scrtm,
                                   errp) < 0) {
            return -1;
        }
    }
    return 0;
}

/* Publish the complete bounded log first, then its offsets in the TXT heap. */
static bool intel_txt_event_log_publish(const IntelTxtEventLog *log,
                                        Error **errp)
{
    /*
     * Worst case: a Spec ID header describing all four banks, then
     * seven records each carrying four digests (20+32+48+64 bytes
     * plus a 2-byte alg id each) and up to a DWORD of event data.
     */
    uint8_t data[2048] = { 0 }, offsets[8];
    size_t off = 60;

    if (!log->banks) {
        return true; /* version-6 launch; no TPM2 pointer element */
    }
    stl_le_p(data + 4, 3); /* EV_NO_ACTION, not extended into any PCR */
    memcpy(data + 32, "Spec ID Event03", 15);
    data[53] = 2; /* spec version 2.0 */
    data[55] = 2; /* 64-bit UINTN */
    stl_le_p(data + 56, ctpop8(log->banks));
    for (unsigned i = 0; i < TXT_LOG_NR_BANKS; i++) {
        if (!(log->banks & BIT(i))) {
            continue;
        }
        stw_le_p(data + off, intel_txt_log_banks[i].alg);
        stw_le_p(data + off + 2, intel_txt_log_banks[i].len);
        off += 4;
    }
    data[off++] = 0; /* vendorInfoSize */
    stl_le_p(data + 28, off - 32); /* TCG_PCR_EVENT eventSize */
    /*
     * Record order is extend order, per PCR:
     *   PCR17: ACM (the _TPM_Hash_* sequence), MLE, caps, S-CRTM
     *   PCR18: MLE, caps, S-CRTM
     * EVTYPE_HASH_START carries no event data here: the SDG's
     * SinitHash+EDX pair describes an authentication step this model
     * does not perform (deviation 1), and inventing bytes for it
     * would put a value in the log that nothing produced.
     */
    off += intel_txt_log_append(data + off, INTEL_TXT_DRTM_PCR_ACM,
                                TXT_EVTYPE_HASH_START, log, log->acm,
                                NULL, 0);
    off += intel_txt_log_append(data + off, INTEL_TXT_DRTM_PCR_MLE,
                                TXT_EVTYPE_MLE_HASH, log, log->mle,
                                NULL, 0);
    off += intel_txt_log_append(data + off, INTEL_TXT_DRTM_PCR_ACM,
                                TXT_EVTYPE_MLE_HASH, log, log->mle,
                                NULL, 0);
    for (unsigned pcr = INTEL_TXT_DRTM_PCR_ACM; pcr <= INTEL_TXT_DRTM_PCR_MLE;
         pcr++) {
        off += intel_txt_log_append(data + off, pcr,
                                    TXT_EVTYPE_OSSINITDATA_CAP, log,
                                    log->caps, log->caps_data,
                                    sizeof(log->caps_data));
        off += intel_txt_log_append(data + off, pcr,
                                    TXT_EVTYPE_CPU_SCRTM_STAT, log,
                                    log->scrtm, log->scrtm_data,
                                    sizeof(log->scrtm_data));
    }
    g_assert(off <= sizeof(data));
    if (off > log->size ||
        !intel_txt_gwrite(log->addr, data, off, errp)) {
        if (!*errp) {
            error_setg(errp, "TPM2 event log cannot hold %zu bytes", off);
        }
        return false;
    }
    stl_le_p(offsets, 0); /* Spec ID is the first record */
    stl_le_p(offsets + 4, off);
    if (!intel_txt_gwrite(log->ext_addr + 12, offsets, sizeof(offsets), errp)) {
        return false;
    }
    trace_txt_event_log(log->addr, off, ctpop8(log->banks));
    return true;
}

/*
 * Spec step c: hash the MLE as the page table maps it and extend PCR 18
 * with the result (which is what a real SINIT ACM does).  PCR 18 has
 * already been zeroed by the _TPM_Hash_Start of step a, so the value
 * lands as a clean extend-from-zero.
 */
static int intel_txt_measure_mle(IntelTxtState *s, IntelTxtMleEntry *entry,
                                 IntelTxtEventLog *log, Error **errp)
{
    uint64_t bios_sz, os_mle_sz, os_sinit_sz, os_sinit;
    uint64_t ptab, mle_size, hdr_base, hdr_phys, entry_phys;
    uint32_t version, hdr_len, entry_off;
    uint8_t uuid[sizeof(intel_txt_mle_uuid)];
    uint8_t *mle = NULL;
    uint8_t *sha1 = NULL, *sha256 = NULL;
    size_t sha1_len = 0, sha256_len = 0;
    TPMDigestValue digests[TXT_LOG_NR_BANKS];
    size_t nr_digests = 0;
    uint64_t off;
    int ret = -1;

    /* Walk the size-prefixed heap sections to reach os_sinit_data. */
    if (!intel_txt_heap_parse(s, &bios_sz, &os_mle_sz, &os_sinit_sz,
                              errp)) {
        return -1;
    }
    if (os_sinit_sz < sizeof(uint64_t) + OS_SINIT_MIN_SIZE) {
        error_setg(errp, "os_sinit_data is 0x%" PRIx64 " bytes, below the "
                   "0x%x minimum for its structure", os_sinit_sz,
                   (unsigned)(sizeof(uint64_t) + OS_SINIT_MIN_SIZE));
        return -1;
    }
    os_sinit = s->heap_base + bios_sz + os_mle_sz + sizeof(uint64_t);

    if (!intel_txt_gread_u32(os_sinit + OS_SINIT_OFF_VERSION, &version, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_MLE_PTAB, &ptab, errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_MLE_SIZE, &mle_size,
                             errp) ||
        !intel_txt_gread_u64(os_sinit + OS_SINIT_OFF_MLE_HDR_BASE, &hdr_base,
                             errp)) {
        return -1;
    }

    if (version < INTEL_TXT_OS_SINIT_MIN_VER) {
        error_setg(errp, "os_sinit_data version %u is below the minimum %u",
                   version, INTEL_TXT_OS_SINIT_MIN_VER);
        return -1;
    }
    if (ptab == 0 || (ptab & 0xfff) ||
        ptab >= INTEL_TXT_GUEST_32BIT_LIMIT) {
        error_setg(errp, "mle_ptab 0x%" PRIx64 " is zero, unaligned or "
                   "not below 4 GiB", ptab);
        return -1;
    }
    /*
     * The SDG defines MLE Size in bytes: an unaligned size is legal
     * and the final partial page is measured only up to MLE Size.
     */
    if (mle_size == 0 ||
        mle_size > INTEL_TXT_MAX_MLE_SIZE) {
        error_setg(errp, "mle_size 0x%" PRIx64 " is zero or larger than "
                   "the 0x%x maximum", mle_size, INTEL_TXT_MAX_MLE_SIZE);
        return -1;
    }
    /*
     * mle_hdr_base is a linear offset into the MLE, so it is bounded by
     * mle_size -- not by mle_ptab, which is the page table's physical
     * address and unrelated to the MLE's address space.
     */
    if (hdr_base > mle_size - MLE_HDR_MIN_SIZE) {
        error_setg(errp, "mle_hdr_base 0x%" PRIx64 " leaves no room for an "
                   "MLE header inside mle_size 0x%" PRIx64, hdr_base,
                   mle_size);
        return -1;
    }

    /* The MLE header identifies the image; check its UUID and length. */
    if (!intel_txt_mle_xlate(ptab, hdr_base, &hdr_phys, NULL, NULL, errp) ||
        !intel_txt_gread(hdr_phys + MLE_HDR_OFF_UUID, uuid, sizeof(uuid),
                         errp) ||
        !intel_txt_gread_u32(hdr_phys + MLE_HDR_OFF_LENGTH, &hdr_len, errp) ||
        !intel_txt_gread_u32(hdr_phys + MLE_HDR_OFF_ENTRY_POINT,
                             &entry_off, errp)) {
        return -1;
    }
    if (memcmp(uuid, intel_txt_mle_uuid, sizeof(uuid)) != 0) {
        error_setg(errp, "no MLE header UUID at linear offset 0x%" PRIx64,
                   hdr_base);
        return -1;
    }
    if (hdr_len < MLE_HDR_MIN_SIZE || hdr_len > mle_size - hdr_base) {
        error_setg(errp, "MLE header length %u does not fit inside the "
                   "0x%" PRIx64 " byte image", hdr_len, mle_size);
        return -1;
    }
    if (entry_off >= mle_size ||
        !intel_txt_mle_xlate(ptab, entry_off, &entry_phys, NULL, NULL, errp)) {
        if (entry_off >= mle_size) {
            error_setg(errp, "MLE entry offset 0x%x is outside the "
                       "0x%" PRIx64 " byte image", entry_off, mle_size);
        }
        return -1;
    }
    if (entry_phys >= INTEL_TXT_GUEST_32BIT_LIMIT) {
        error_setg(errp, "MLE entry address 0x%" PRIx64 " is not below 4 GiB",
                   entry_phys);
        return -1;
    }

    /*
     * Gather the MLE image page by page through the mapping.  An
     * unaligned MLE Size ends the final page early; only the
     * remaining bytes belong to the measured image.
     */
    mle = g_malloc(mle_size);
    for (off = 0; off < mle_size; off += 4096) {
        uint64_t page;

        if (!intel_txt_mle_xlate(ptab, off, &page, NULL, NULL, errp) ||
            !intel_txt_gread(page, mle + off,
                             MIN((uint64_t)4096, mle_size - off), errp)) {
            goto out;
        }
    }

    if (qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA1, mle, mle_size,
                           &sha1, &sha1_len, errp) < 0 ||
        qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA256, mle, mle_size,
                           &sha256, &sha256_len, errp) < 0) {
        goto out;
    }

    for (unsigned i = 0; i < TXT_LOG_NR_BANKS; i++) {
        g_autofree uint8_t *extra = NULL;
        const uint8_t *hash = i == 0 ? sha1 : sha256;
        size_t len = i == 0 ? sha1_len : sha256_len;

        if (!(log->banks & BIT(i)) && (log->banks || i >= 2)) {
            continue;
        }
        if (i >= 2) {
            len = 0;
            if (qcrypto_hash_bytes(intel_txt_log_banks[i].crypto, mle,
                                   mle_size, &extra, &len, errp) < 0) {
                goto out;
            }
            hash = extra;
        }
        g_assert(len == intel_txt_log_banks[i].len);
        memcpy(log->mle[i], hash, len);
        digests[nr_digests++] = (TPMDigestValue) {
            .alg = intel_txt_log_banks[i].alg,
            .digest = log->mle[i], .len = len,
        };
    }

    trace_txt_measure_mle(ptab, mle_size, hdr_base);
    intel_txt_trace_digest("MLE", sha1, sha1_len, sha256, sha256_len);
    ret = intel_txt_drtm_extend_pcr(s, INTEL_TXT_DRTM_PCR_MLE, digests,
                                   nr_digests, errp);
    if (ret == 0) {
        entry->entry_phys = entry_phys;
        entry->ptab = ptab;
    }
out:
    g_free(mle);
    g_free(sha1);
    g_free(sha256);
    return ret;
}

/*
 * Build and write the sinit_mle_data heap section, the data SINIT
 * hands to the MLE (tboot include/txt/heap.h, sinit_mle_data_t,
 * version 6): the fixed structure followed immediately by the memory
 * descriptor (MDR) array it points to.
 *
 * The loader has already laid out the four size-prefixed heap
 * sections and reserved the size of the fourth; this fills in its
 * contents and leaves the loader's size prefix in place.  tboot
 * verifies the guest e820 map against the MDRs after the measured
 * launch (txt/verify.c, verify_e820_map): any RAM not covered by an
 * MDR with mem_type at most MDR_MEMTYPE_GOOD is downgraded and the
 * verification fails, and the gaps before the first and after the
 * last covering MDR must hold no RAM.  So every E820_RAM entry of
 * QEMU's own e820 table becomes a GOOD MDR, covering low and high
 * memory alike; the gaps between them are non-RAM by construction,
 * which is exactly what tboot's gap walk requires.
 *
 */
static bool intel_txt_find_dmar(uint64_t *addr, uint32_t *len);

static bool intel_txt_write_sinit_mle_data(IntelTxtState *s, Error **errp)
{
    uint64_t bios_sz, os_mle_sz, os_sinit_sz;
    uint64_t heap_end, region, region_size;
    uint64_t mdr_off, mdr_end, total_end;
    uint64_t dmar_addr = 0;
    uint32_t dmar_len = 0, dmar_off = 0;
    bool new_section, have_dmar;
    int nr_entries, nr_ram = 0, i;
    uint8_t *buf;

    /*
     * The same precondition 4 as the staged launch: the heap
     * registers are set and the whole heap is below 4 GiB, which
     * also bounds every offset computed below.
     */
    if (s->heap_base == 0 || s->heap_size == 0 ||
        s->heap_base >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        s->heap_size > INTEL_TXT_GUEST_32BIT_LIMIT - s->heap_base) {
        error_setg(errp, "TXT.HEAP_BASE/SIZE not set or not entirely "
                   "below 4 GiB (base 0x%" PRIx64 ", size 0x%" PRIx64 ")",
                   s->heap_base, s->heap_size);
        return false;
    }

    if (!intel_txt_heap_parse(s, &bios_sz, &os_mle_sz, &os_sinit_sz,
                              errp)) {
        return false;
    }

    /*
     * The sinit_mle_data section starts after the first three. A real
     * loader leaves its size prefix zero: SINIT writes it on launch.
     * Also accept a preallocated nonzero section for diagnostic guests.
     */
    heap_end = s->heap_base + s->heap_size;
    region = s->heap_base + bios_sz + os_mle_sz + os_sinit_sz;
    if (region > heap_end || heap_end - region < sizeof(uint64_t)) {
        error_setg(errp, "no room for sinit_mle_data size in TXT heap");
        return false;
    }
    if (!intel_txt_gread_u64(region, &region_size, errp)) {
        return false;
    }
    new_section = region_size == 0;
    if (!new_section && (region_size < sizeof(uint64_t) ||
                         region_size > heap_end - region)) {
        error_setg(errp, "sinit_mle_data section of 0x%" PRIx64
                   " bytes at heap offset 0x%" PRIx64 " does not fit "
                   "in the 0x%" PRIx64 " byte heap",
                   region_size, region - s->heap_base, s->heap_size);
        return false;
    }

    /*
     * One GOOD MDR per E820_RAM entry of QEMU's own e820 table, the
     * same collection fw_cfg and the TDX measurement make.
     */
    nr_entries = e820_get_table(NULL);
    for (i = 0; i < nr_entries; i++) {
        uint64_t addr, len;

        if (e820_get_entry(i, E820_RAM, &addr, &len)) {
            nr_ram++;
        }
    }
    if (nr_ram == 0) {
        error_setg(errp, "no E820_RAM entries in the guest e820 table");
        return false;
    }

    /*
     * The MDR array sits right after the fixed structure.  mdrs_off
     * is measured from the start of the section, i.e. its size prefix
     * (tboot txt/txt.c: mdrs_base = sinit_mle_data - sizeof(uint64_t)
     * + mdrs_off), so the 8 byte prefix precedes the structure.
     */
    mdr_off = sizeof(uint64_t) + SINIT_MLE_FIXED_SIZE;
    mdr_end = mdr_off + (uint64_t)nr_ram * SINIT_MDR_SIZE;
    if (new_section) {
        region_size = heap_end - region;
    }
    if (mdr_end > region_size) {
        error_setg(errp, "sinit_mle_data with %d MDRs needs 0x%" PRIx64
                   " bytes, more than the 0x%" PRIx64 " byte section",
                   nr_ram, mdr_end, region_size);
        return false;
    }

    /*
     * A measured copy of the DMAR follows the MDRs.  Linux under tboot
     * reads VT-d configuration only from here, so without it an
     * intel-iommu guest panics with "Failed to initialize DMAR table".
     * A guest with no intel-iommu has no DMAR and needs none.
     */
    total_end = mdr_end;
    have_dmar = intel_txt_find_dmar(&dmar_addr, &dmar_len);
    if (have_dmar) {
        dmar_off = mdr_end;
        total_end = mdr_end + dmar_len;
        if (total_end > region_size) {
            error_setg(errp, "sinit_mle_data with %d MDRs and a 0x%x byte "
                       "DMAR needs 0x%" PRIx64 " bytes, more than the "
                       "0x%" PRIx64 " byte section",
                       nr_ram, dmar_len, total_end, region_size);
            return false;
        }
    }

    /*
     * Answer the RLP wake mechanism the MLE asked for.  GETSEC[WAKEUP]
     * is the fallback and needs no published address; MONITOR wake
     * additionally reports the location whose write releases the
     * parked RLPs.  An os_sinit_data too short to hold capabilities
     * predates the field and can only mean GETSEC[WAKEUP].
     */
    s->rlp_wake_monitor = false;
    if (os_sinit_sz >= sizeof(uint64_t) + OS_SINIT_CAPS_MIN_SIZE) {
        uint64_t os_sinit = s->heap_base + bios_sz + os_mle_sz +
                            sizeof(uint64_t);
        uint32_t caps;

        if (!intel_txt_gread_u32(os_sinit + OS_SINIT_OFF_CAPABILITIES,
                                 &caps, errp)) {
            return false;
        }
        s->rlp_wake_monitor = (caps & TXT_CAPS_RLP_WAKE_MONITOR) != 0;
        trace_txt_rlp_wake_mechanism(caps, s->rlp_wake_monitor ?
                                     "MONITOR" : "GETSEC[WAKEUP]");
    }

    /* total_end includes the loader's size prefix; the buffer does not. */
    buf = g_malloc0(total_end - sizeof(uint64_t));
    stl_le_p(buf + SINIT_MLE_OFF_VERSION, SINIT_MLE_VERSION);
    /*
     * rlp_wakeup_addr is only meaningful for MONITOR wake; it stays
     * zero for the GETSEC[WAKEUP] rendezvous.  The TPM 1.2 hash and
     * policy fields stay zero either way.
     */
    if (s->rlp_wake_monitor) {
        stl_le_p(buf + SINIT_MLE_OFF_RLP_WAKEUP_ADDR,
                 INTEL_TXT_PUBLIC_BASE + TXT_RLP_WAKEUP);
    }
    stl_le_p(buf + SINIT_MLE_OFF_NUM_MDRS, nr_ram);
    stl_le_p(buf + SINIT_MLE_OFF_MDRS_OFF, mdr_off);
    if (have_dmar) {
        stl_le_p(buf + SINIT_MLE_OFF_NUM_VTD_DMARS, 1);
        stl_le_p(buf + SINIT_MLE_OFF_VTD_DMARS_OFF, dmar_off);
    }

    {
        uint64_t off = mdr_off - sizeof(uint64_t);

        for (i = 0; i < nr_entries; i++) {
            uint64_t addr, len;

            if (!e820_get_entry(i, E820_RAM, &addr, &len)) {
                continue;
            }
            /* mem_type stays zero: MDR_MEMTYPE_GOOD */
            stq_le_p(buf + off + SINIT_MDR_OFF_BASE, addr);
            stq_le_p(buf + off + SINIT_MDR_OFF_LENGTH, len);
            off += SINIT_MDR_SIZE;
        }
    }

    if (have_dmar &&
        !intel_txt_gread(dmar_addr, buf + dmar_off - sizeof(uint64_t),
                         dmar_len, errp)) {
        g_free(buf);
        return false;
    }

    if (!intel_txt_gwrite(region + sizeof(uint64_t), buf,
                          total_end - sizeof(uint64_t), errp)) {
        g_free(buf);
        return false;
    }
    if (new_section) {
        uint8_t size_bytes[sizeof(uint64_t)];

        stq_le_p(size_bytes, total_end);
        if (!intel_txt_gwrite(region, size_bytes, sizeof(size_bytes), errp)) {
            g_free(buf);
            return false;
        }
    }

    trace_txt_sinit_mle_data((uint32_t)nr_ram, region - s->heap_base);
    g_free(buf);
    return true;
}

/*
 * Locate the guest's DMAR ACPI table so SENTER can stash a copy in
 * sinit_mle_data.  Real SINIT does this because the ACPI tables live in
 * memory that is not DMA protected: Linux under tboot deliberately
 * ignores the firmware DMAR and reads the measured copy out of the TXT
 * heap instead (arch/x86/kernel/tboot.c, tboot_get_dmar_table()).
 *
 * Returns the guest address in @addr and length in @len, or false when
 * no DMAR is present -- which is not an error: a guest without
 * intel-iommu legitimately has none.
 */
/*
 * True when the @len bytes at @addr sum to zero modulo 256, the
 * validity rule for every ACPI structure.  Without this any stray
 * "RSD PTR " string in the BIOS area would be taken for a real RSDP.
 */
static bool intel_txt_acpi_csum_ok(uint64_t addr, uint32_t len)
{
    g_autofree uint8_t *buf = NULL;
    uint8_t sum = 0;
    uint32_t i;

    if (len == 0 || len > INTEL_TXT_MAX_ACPI_TABLE) {
        return false;
    }
    buf = g_malloc(len);
    if (!intel_txt_gread(addr, buf, len, NULL)) {
        return false;
    }
    for (i = 0; i < len; i++) {
        sum += buf[i];
    }
    return sum == 0;
}

/* Find a checksum-valid RSDP in [@start, @start + @size). */
static uint64_t intel_txt_scan_rsdp(uint64_t start, uint64_t size)
{
    uint64_t scan;

    /* The ACPI spec requires 16 byte alignment for the signature. */
    for (scan = start; scan + 20 <= start + size; scan += 16) {
        uint8_t sig[8];
        uint8_t rev;
        uint32_t ext_len;

        if (!intel_txt_gread(scan, sig, sizeof(sig), NULL)) {
            return 0;
        }
        if (memcmp(sig, "RSD PTR ", sizeof(sig)) != 0) {
            continue;
        }
        /* ACPI 1.0 checksum covers the first 20 bytes. */
        if (!intel_txt_acpi_csum_ok(scan, 20)) {
            continue;
        }
        /* Revision 2+ adds an extended checksum over the whole table. */
        if (!intel_txt_gread(scan + 15, &rev, 1, NULL)) {
            return 0;
        }
        if (rev >= 2) {
            if (!intel_txt_gread_u32(scan + 20, &ext_len, NULL) ||
                ext_len < 20 || !intel_txt_acpi_csum_ok(scan, ext_len)) {
                continue;
            }
        }
        return scan;
    }
    return 0;
}

static bool intel_txt_find_dmar(uint64_t *addr, uint32_t *len)
{
    uint64_t rsdp, sdt;
    uint8_t sig[8];
    uint32_t sdt_len;
    bool xsdt;
    uint16_t ebda_seg = 0;

    /*
     * The RSDP lives either in the first KiB of the EBDA or in
     * 0xE0000-0xFFFFF (ACPI spec 5.2.5.1); check both, as tboot and
     * Linux do.  coreboot puts its tables high and the pointer in the
     * BIOS area, SeaBIOS uses the EBDA.
     */
    if (intel_txt_gread(0x40e, &ebda_seg, sizeof(ebda_seg), NULL)) {
        ebda_seg = le16_to_cpu(ebda_seg);
    }
    rsdp = ebda_seg ? intel_txt_scan_rsdp((uint64_t)ebda_seg << 4, 1024) : 0;
    if (rsdp == 0) {
        rsdp = intel_txt_scan_rsdp(0xe0000, 0x20000);
    }
    if (rsdp == 0) {
        return false;
    }

    /*
     * Revision 0 has only the 32-bit RSDT; revision 2+ adds the 64-bit
     * XSDT, which takes precedence when non-zero.
     */
    {
        uint8_t rev;
        uint32_t rsdt_addr = 0;
        uint64_t xsdt_addr = 0;

        if (!intel_txt_gread(rsdp + 15, &rev, 1, NULL) ||
            !intel_txt_gread_u32(rsdp + 16, &rsdt_addr, NULL)) {
            return false;
        }
        if (rev >= 2 &&
            !intel_txt_gread_u64(rsdp + 24, &xsdt_addr, NULL)) {
            return false;
        }
        if (rev >= 2 && xsdt_addr != 0) {
            sdt = xsdt_addr;
            xsdt = true;
        } else {
            sdt = rsdt_addr;
            xsdt = false;
        }
    }
    if (sdt == 0 || sdt >= INTEL_TXT_GUEST_32BIT_LIMIT) {
        return false;
    }

    if (!intel_txt_gread(sdt, sig, 4, NULL) ||
        !intel_txt_gread_u32(sdt + 4, &sdt_len, NULL)) {
        return false;
    }
    if (memcmp(sig, xsdt ? "XSDT" : "RSDT", 4) != 0 ||
        sdt_len < ACPI_TABLE_HEADER_SIZE ||
        sdt_len > INTEL_TXT_GUEST_32BIT_LIMIT - sdt ||
        !intel_txt_acpi_csum_ok(sdt, sdt_len)) {
        return false;
    }

    {
        uint32_t entry_size = xsdt ? 8 : 4;
        uint32_t i, nr = (sdt_len - ACPI_TABLE_HEADER_SIZE) / entry_size;

        for (i = 0; i < nr; i++) {
            uint64_t off = sdt + ACPI_TABLE_HEADER_SIZE +
                           (uint64_t)i * entry_size;
            uint64_t tbl = 0;
            uint32_t tbl_len;

            if (xsdt) {
                if (!intel_txt_gread_u64(off, &tbl, NULL)) {
                    return false;
                }
            } else {
                uint32_t tbl32 = 0;

                if (!intel_txt_gread_u32(off, &tbl32, NULL)) {
                    return false;
                }
                tbl = tbl32;
            }
            if (tbl == 0 || tbl >= INTEL_TXT_GUEST_32BIT_LIMIT) {
                continue;
            }
            if (!intel_txt_gread(tbl, sig, 4, NULL) ||
                !intel_txt_gread_u32(tbl + 4, &tbl_len, NULL)) {
                return false;
            }
            if (memcmp(sig, "DMAR", 4) != 0) {
                continue;
            }
            /*
             * A DMAR that does not validate is reported as absent
             * rather than copied: the MLE is told what was found, and
             * garbage here would be worse than nothing.  The trace
             * point keeps the rejection visible.
             */
            if (tbl_len < ACPI_TABLE_HEADER_SIZE ||
                tbl_len > INTEL_TXT_GUEST_32BIT_LIMIT - tbl ||
                tbl_len > INTEL_TXT_MAX_ACPI_TABLE ||
                !intel_txt_acpi_csum_ok(tbl, tbl_len)) {
                trace_txt_dmar_rejected(tbl, tbl_len);
                return false;
            }
            trace_txt_dmar_found(tbl, tbl_len);
            *addr = tbl;
            *len = tbl_len;
            return true;
        }
    }
    return false;
}

/*
 * SENTER precondition 3: check that @acm, the @size bytes at
 * TXT.SINIT_BASE, structurally describes a SINIT ACM for the
 * chipset TXT.DIDVID reports.  Returns 0 if it does, -1 with @errp
 * set otherwise; the caller turns that into
 * TXT_ERRORCODE_ACM_INVALID.
 *
 * The checks mirror tboot's is_acmod() / is_sinit_acmod() /
 * does_acmod_match_platform() (tboot/txt/acmod.c), which is what a
 * loader applies to the same blob before handing it to SENTER, so a
 * blob tboot accepts is accepted here too.
 *
 * What is deliberately not checked: the RSA signature and the
 * public-key hash in TXT.PUBLIC_KEY (QEMU authenticates nothing --
 * deviation 1 in docs/specs/intel-txt.rst), the processor id list
 * (there is no meaningful emulated platform id to match), and the
 * SINIT/MLE capability intersection and MLE_JOIN segment selectors,
 * which belong to the MLE-transfer slice that consumes them.
 */
static int intel_txt_validate_acm(IntelTxtState *s, const uint8_t *acm,
                                  uint64_t size, Error **errp)
{
    uint32_t hdr_size, header_len, scratch_size, entry_point;
    uint32_t seg_sel, gdt_limit;
    uint32_t info_off, id_list_off, count, i;
    uint16_t module_type, module_subtype;
    uint16_t vendor, device, revision;
    const uint8_t *info;

    /* The whole fixed header, and ACMs are sized in 64-byte units. */
    if (size < ACM_HDR_MIN_SIZE || (size % 64) != 0) {
        error_setg(errp, "SINIT ACM size 0x%" PRIx64 " is below the 0x%x "
                   "header minimum or not a multiple of 64 bytes", size,
                   ACM_HDR_MIN_SIZE);
        return -1;
    }
    /* The ACM must be page-aligned so SINIT can map it. */
    if (s->sinit_base & 0xfff) {
        error_setg(errp, "SINIT ACM base 0x%" PRIx64 " is not 4 KiB "
                   "aligned", s->sinit_base);
        return -1;
    }

    hdr_size = ldl_le_p(acm + ACM_HDR_OFF_SIZE);
    if ((uint64_t)hdr_size * 4 != size) {
        error_setg(errp, "SINIT ACM header size %u dwords (0x%" PRIx64
                   " bytes) does not match GETSEC[SENTER] ECX 0x%" PRIx64,
                   hdr_size, (uint64_t)hdr_size * 4, size);
        return -1;
    }

    module_type = lduw_le_p(acm + ACM_HDR_OFF_MODULE_TYPE);
    module_subtype = lduw_le_p(acm + ACM_HDR_OFF_MODULE_SUBTYPE);
    if (module_type != ACM_TYPE_CHIPSET) {
        error_setg(errp, "ACM module_type 0x%x is not a chipset ACM (0x%x)",
                   module_type, ACM_TYPE_CHIPSET);
        return -1;
    }
    /*
     * Subtype 1 is a reset ACM (ACM_SUBTYPE_RESET): it is entered on
     * the TXT reset path, not by SENTER, so pointing SINIT_BASE at
     * one is a loader error rather than a usable launch input.
     */
    if (module_subtype != ACM_SUBTYPE_SINIT) {
        error_setg(errp, "ACM module_subtype 0x%x is not a SINIT ACM "
                   "(0x%x)", module_subtype, ACM_SUBTYPE_SINIT);
        return -1;
    }
    if (ldl_le_p(acm + ACM_HDR_OFF_MODULE_VENDOR) != ACM_VENDOR_INTEL) {
        error_setg(errp, "ACM module_vendor 0x%x is not Intel (0x%x)",
                   ldl_le_p(acm + ACM_HDR_OFF_MODULE_VENDOR),
                   ACM_VENDOR_INTEL);
        return -1;
    }

    entry_point = ldl_le_p(acm + ACM_HDR_OFF_ENTRY_POINT);
    if (entry_point == 0 || entry_point >= size) {
        error_setg(errp, "ACM entry_point 0x%x is zero or outside the "
                   "0x%" PRIx64 " byte module", entry_point, size);
        return -1;
    }

    /*
     * The header also describes the GDT the module runs under, and
     * that description outlives the module: it is what the measured
     * environment is entered with, since the MLE is given a usable CS
     * and nothing else to bootstrap from.  So the selector has to be
     * a plausible one before it is ever loaded.
     *
     * Same three checks tboot makes (txt/acmod.c, verify_acmod()):
     * non-null, an offset into the GDT rather than the LDT and at
     * ring 0 (the low three bits clear), and far enough inside
     * gdt_limit for the descriptor to be there.  The data selector
     * the MLE guide pairs with it is seg_sel + 8, so that addition is
     * checked for wrap first; these fields all sit inside the
     * ACM_HDR_MIN_SIZE prefix already required above.
     */
    seg_sel = ldl_le_p(acm + ACM_HDR_OFF_SEG_SEL);
    gdt_limit = ldl_le_p(acm + ACM_HDR_OFF_GDT_LIMIT);
    if (seg_sel > UINT32_MAX - 8) {
        error_setg(errp, "ACM seg_sel 0x%x plus 8 overflows", seg_sel);
        return -1;
    }
    if (seg_sel == 0 || (seg_sel & 0x07) != 0) {
        error_setg(errp, "ACM seg_sel 0x%x is null, an LDT selector or "
                   "not ring 0", seg_sel);
        return -1;
    }
    if (seg_sel + 8 > gdt_limit) {
        error_setg(errp, "ACM seg_sel 0x%x does not fit in gdt_limit 0x%x",
                   seg_sel, gdt_limit);
        return -1;
    }

    /*
     * The info table follows the header and its scratch area.  Both
     * lengths come from the (untrusted) header, so compute the offset
     * in 64 bits and bound it against the module.
     */
    header_len = ldl_le_p(acm + ACM_HDR_OFF_HEADER_LEN);
    scratch_size = ldl_le_p(acm + ACM_HDR_OFF_SCRATCH_SIZE);
    if ((uint64_t)header_len + scratch_size > size / 4 ||
        ((uint64_t)header_len + scratch_size) * 4 + ACM_INFO_MIN_SIZE >
        size) {
        error_setg(errp, "ACM info table at dword %" PRIu64 " does not fit "
                   "in the 0x%" PRIx64 " byte module",
                   (uint64_t)header_len + scratch_size, size);
        return -1;
    }
    info_off = (header_len + scratch_size) * 4;
    info = acm + info_off;

    if (memcmp(info + ACM_INFO_OFF_UUID, intel_txt_acm_uuid,
               sizeof(intel_txt_acm_uuid)) != 0) {
        error_setg(errp, "no ACM info table UUID at offset 0x%x", info_off);
        return -1;
    }
    if (info[ACM_INFO_OFF_CHIPSET_ACM_TYPE] != ACM_CHIPSET_TYPE_SINIT) {
        error_setg(errp, "ACM chipset_acm_type 0x%x is not SINIT (0x%x)",
                   info[ACM_INFO_OFF_CHIPSET_ACM_TYPE],
                   ACM_CHIPSET_TYPE_SINIT);
        return -1;
    }
    if (info[ACM_INFO_OFF_VERSION] < ACM_INFO_MIN_VERSION) {
        error_setg(errp, "ACM info table version %u is below the minimum "
                   "%u", info[ACM_INFO_OFF_VERSION], ACM_INFO_MIN_VERSION);
        return -1;
    }

    /*
     * The chipset id list decides whether this ACM is for this
     * chipset at all: one entry must match TXT.DIDVID.
     */
    id_list_off = ldl_le_p(info + ACM_INFO_OFF_CHIPSET_ID_LIST);
    if ((uint64_t)id_list_off + ACM_CHIPSET_ID_LIST_HDR_SIZE > size) {
        error_setg(errp, "ACM chipset id list offset 0x%x is outside the "
                   "0x%" PRIx64 " byte module", id_list_off, size);
        return -1;
    }
    count = ldl_le_p(acm + id_list_off + ACM_CHIPSET_ID_LIST_OFF_COUNT);
    if (count == 0 ||
        (uint64_t)id_list_off + ACM_CHIPSET_ID_LIST_HDR_SIZE +
        (uint64_t)count * ACM_CHIPSET_ID_SIZE > size) {
        error_setg(errp, "ACM chipset id list of %u entries at 0x%x is "
                   "empty or does not fit in the module", count,
                   id_list_off);
        return -1;
    }

    vendor = s->didvid & 0xffff;
    device = (s->didvid >> 16) & 0xffff;
    revision = (s->didvid >> 32) & 0xffff;
    for (i = 0; i < count; i++) {
        const uint8_t *id = acm + id_list_off + ACM_CHIPSET_ID_LIST_HDR_SIZE +
                            (uint64_t)i * ACM_CHIPSET_ID_SIZE;
        uint32_t flags = ldl_le_p(id + ACM_CHIPSET_ID_OFF_FLAGS);
        uint16_t id_rev = lduw_le_p(id + ACM_CHIPSET_ID_OFF_REVISION);

        if (lduw_le_p(id + ACM_CHIPSET_ID_OFF_VENDOR) != vendor ||
            lduw_le_p(id + ACM_CHIPSET_ID_OFF_DEVICE) != device) {
            continue;
        }
        /*
         * flags bit 0 makes revision_id a mask (any common bit
         * matches); otherwise it is compared for equality.  Same rule
         * as tboot's does_acmod_match_platform().
         */
        if (flags & ACM_CHIPSET_ID_FLAG_REV_MASK) {
            if (revision & id_rev) {
                break;
            }
        } else if (revision == id_rev) {
            break;
        }
    }
    if (i == count) {
        error_setg(errp, "no ACM chipset id entry matches TXT.DIDVID "
                   "0x%" PRIx64 " (vendor 0x%x, device 0x%x, revision "
                   "0x%x)", s->didvid, vendor, device, revision);
        return -1;
    }

    trace_txt_acm_validated(size, entry_point, count);
    return 0;
}

void intel_txt_reject_aps(IntelTxtState *s)
{
    s->errorcode = TXT_ERRORCODE_APS_UNSUPPORTED;
    trace_txt_senter_errorcode(s->errorcode);
}

bool intel_txt_senter(IntelTxtState *s, uint32_t acm_base,
                      uint32_t acm_size, IntelTxtMleEntry *entry)
{
    uint64_t dpr_size, dpr_top, cs_addr, ds_addr;
    uint32_t gdt_off;
    uint32_t cs_flags, ds_flags;
    uint8_t *acm = NULL;
    IntelTxtPmrs pmrs;
    IntelTxtEventLog log = { 0 };
    uint64_t pmr_errorcode;
    CPUState *cpu;
    Error *err = NULL;
    int ret = 0;

    trace_txt_senter();

    /*
     * The CPU helper rendezvouses and parks each RLP on its own thread
     * before entering here; refuse to measure with any unparked AP.
     */
    CPU_FOREACH(cpu) {
        if (cpu != current_cpu && !cpu_env(cpu)->txt_ap_parked) {
            intel_txt_reject_aps(s);
            return false;
        }
    }

    /*
     * Precondition 2: EBX/ECX name the actual ACM, while firmware's
     * TXT.SINIT_BASE/SIZE describe a potentially larger reserved slot.
     * Limit the measured ACM (not the slot) to the GETSEC[PARAMETERS]
     * execution-area maximum, and bound it inside the reserved slot.
     */
    if (s->sinit_base == 0 || s->sinit_size == 0 ||
        s->sinit_base >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        s->sinit_size > INTEL_TXT_GUEST_32BIT_LIMIT - s->sinit_base ||
        acm_base != s->sinit_base || acm_size == 0 ||
        acm_size > s->sinit_size || acm_size > INTEL_TXT_MAX_ACM_SIZE) {
        goto fail_sinit_region;
    }

    /*
     * Precondition 2 (continued): the SINIT region must sit
     * entirely inside the DMA Protected Range.  DPR layout: bit 0
     * LOCK, bits [11:4] SIZE in 1 MiB blocks, bits [31:20] TOP; the
     * protected range is [TOP - SIZE*1MiB, TOP).  A zero DPR size
     * means no protected range, so the check fails.
     */
    dpr_size = (s->dpr >> 4) & 0xff;
    dpr_top = (s->dpr >> 20) & 0xfff;
    if (!(s->dpr & TXT_DPR_LOCK) || dpr_size == 0 ||
        dpr_size > dpr_top ||
        s->sinit_base < ((dpr_top - dpr_size) << 20) ||
        s->sinit_base + s->sinit_size > (dpr_top << 20)) {
        goto fail_sinit_dpr;
    }

    /*
     * Precondition 3: the region must actually hold a SINIT ACM for
     * this chipset.  Read it once here -- the same buffer is what
     * gets measured below, so validation and measurement cannot
     * disagree about the bytes even if the guest rewrites the region
     * in between.
     */
    acm = g_malloc(acm_size);
    if (address_space_read(&address_space_memory, acm_base,
                           MEMTXATTRS_UNSPECIFIED, acm,
                           acm_size) != MEMTX_OK) {
        error_setg(&err, "cannot read the SINIT ACM region at 0x%" PRIx64,
                   s->sinit_base);
        goto fail_measure;
    }
    if (intel_txt_validate_acm(s, acm, acm_size, &err) < 0) {
        goto fail_acm;
    }
    entry->gdt_limit = ldl_le_p(acm + ACM_HDR_OFF_GDT_LIMIT);
    entry->seg_sel = ldl_le_p(acm + ACM_HDR_OFF_SEG_SEL);
    /*
     * GDTBasePtr is not an address: the SDG's ACM header description
     * defines it as "an offset from the authenticated code module base
     * address", the same convention as EntryPoint.  So the GDT lives
     * inside the measured module -- every production SINIT ACM puts it
     * a few KiB in -- and the descriptors come out of the image while
     * the CPU gets the resolved address to load into GDTR.
     */
    gdt_off = ldl_le_p(acm + ACM_HDR_OFF_GDT_BASE);
    cs_addr = (uint64_t)gdt_off + entry->seg_sel;
    ds_addr = cs_addr + 8;
    if ((uint64_t)gdt_off + entry->gdt_limit >= acm_size ||
        ds_addr + 8 > acm_size) {
        error_setg(&err, "ACM GDT at module offset 0x%x (limit 0x%x, "
                   "selector 0x%x) does not fit in the 0x%x byte module",
                   gdt_off, entry->gdt_limit, entry->seg_sel, acm_size);
        goto fail_acm;
    }
    entry->gdt_base = acm_base + gdt_off;
    entry->cs_desc = ldq_le_p(acm + cs_addr);
    entry->ds_desc = ldq_le_p(acm + ds_addr);
    cs_flags = entry->cs_desc >> 32;
    ds_flags = entry->ds_desc >> 32;
    /*
     * Require present, ring-0, 32-bit code and writable data GDT
     * entries. Installing unvalidated descriptors in the CPU cache
     * would turn a malformed ACM into a post-measurement triple fault.
     */
    if (entry->gdt_limit > UINT16_MAX ||
        (cs_flags & 0x0040f800) != 0x00409800 ||
        (ds_flags & 0x0040fa00) != 0x00409200 ||
        (cs_flags & 0x00200000)) {
        error_setg(&err, "ACM GDT does not contain 32-bit ring-0 code "
                   "and writable data descriptors");
        goto fail_acm;
    }

    /*
     * Precondition 4: TXT.HEAP_BASE/SIZE set, the region below
     * 4 GiB.  The heap contents are parsed by step c below.
     */
    if (s->heap_base == 0 || s->heap_size == 0 ||
        s->heap_base >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        s->heap_size > INTEL_TXT_GUEST_32BIT_LIMIT - s->heap_base ||
        s->heap_base < ((dpr_top - dpr_size) << 20) ||
        s->heap_base >= (dpr_top << 20) ||
        s->heap_size > (dpr_top << 20) - s->heap_base) {
        goto fail_heap;
    }

    if (!intel_txt_validate_pmrs(s, &pmrs, &pmr_errorcode, &err)) {
        goto fail_pmr;
    }
    /* Check log bounds and supported active banks before any PCR is reset. */
    if (!intel_txt_event_log_prepare(s, &log, &err)) {
        goto fail_event_log;
    }
    for (unsigned i = 0; i < TXT_LOG_NR_BANKS; i++) {
        g_autofree uint8_t *digest = NULL;
        size_t len = 0;

        if (!(log.banks & BIT(i))) {
            continue;
        }
        if (qcrypto_hash_bytes(intel_txt_log_banks[i].crypto,
                               (char *)acm, acm_size,
                               &digest, &len, &err) < 0) {
            goto fail_event_log;
        }
        g_assert(len == intel_txt_log_banks[i].len);
        memcpy(log.acm[i], digest, len);
    }

    /*
     * Engage SMI inhibition once every precondition has passed and
     * before any DRTM PCR is reset below: an SMI must not preempt a
     * launch while the measured environment is being established.
     * Arriving SMIs are held per CPU and redelivered by SEXIT or
     * GETSEC[SMCTRL].  A rejected launch never reaches this point,
     * so its SMIs keep flowing normally.
     */
    bql_lock();
    s->smi_inhibit = true;
    bql_unlock();
    trace_txt_smi_inhibit();

    /*
     * Program the VT-d Protected Memory Regions before the DRTM
     * measurement below, so a programming failure cannot leave PCRs
     * 17-22 half-measured.  On hardware the chipset programs the PMRs
     * during SINIT setup; in this model the values are known from
     * os_sinit_data, so SENTER applies them itself.
     *
     * The PMR has to be able to deny DMA on every device path: fail
     * closed when there is no VT-d device, or when a host device
     * caches mappings outside the IOMMU (see
     * intel_iommu_set_txt_pmr()).  Each SENTER starts from a released
     * PMR so a retry re-programs exactly the validated window.
     */
    {
        X86IOMMUState *x86_iommu = x86_iommu_get_default();
        Object *iommu = x86_iommu ?
            object_dynamic_cast(OBJECT(&x86_iommu->busdev),
                                TYPE_INTEL_IOMMU_DEVICE) : NULL;

        if (!iommu) {
            error_setg(&err, "no VT-d (intel-iommu) device to protect "
                                 "the MLE against DMA");
            goto fail_pmr_program;
        }
        intel_iommu_clear_txt_pmr(INTEL_IOMMU_DEVICE(iommu));
        if (!intel_iommu_set_txt_pmr(INTEL_IOMMU_DEVICE(iommu),
                                     pmrs.lo_base, pmrs.lo_size,
                                     pmrs.hi_base, pmrs.hi_size, &err)) {
            goto fail_pmr_program;
        }
    }

    /*
     * Steps a and d, as one hardware-faithful sequence.
     *
     * The DRTM PCRs are established with the TIS _TPM_Hash_Start /
     * _TPM_Hash_Data / _TPM_Hash_End signals: _TPM_Hash_Start resets
     * PCRs 17-22 and _TPM_Hash_End extends PCR 17 with the hash of
     * everything fed in between, in every active bank.  TPM2_PCR_Reset
     * cannot be used for step a -- it answers TPM_RC_LOCALITY (0x907)
     * for the DRTM PCRs even at locality 4 -- so this sequence is not
     * merely more faithful, it is the only mechanism that works.  See
     * docs/plans/intel-txt-m3-plan.md §3.7.
     *
     * The TPM does the hashing here, exactly as on real hardware where
     * the chipset streams bytes at it rather than presenting a digest.
     *
     * This is only the first component of the eventual PCR 17 value;
     * launch-context digests are not yet extended, so PCR 17 is not
     * final or attestable.  PCR 18 receives the MLE hash below.
     */
    ret = intel_txt_drtm_hash_measure(s, acm, acm_size, &err);
    if (ret < 0) {
        goto fail_measure;
    }
    /*
     * The TPM computed that digest internally and does not return it,
     * so recompute it host-side purely for the trace.  A mismatch
     * against a PCR replay would mean the backend hashed something
     * other than what was handed to it.
     */
    if (trace_event_get_state_backends(TRACE_TXT_DRTM_DIGEST)) {
        g_autofree uint8_t *a1 = NULL;
        g_autofree uint8_t *a256 = NULL;
        size_t a1_len = 0, a256_len = 0;

        if (qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA1, (char *)acm,
                               acm_size, &a1, &a1_len, NULL) == 0 &&
            qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA256, (char *)acm,
                               acm_size, &a256, &a256_len, NULL) == 0) {
            intel_txt_trace_digest("ACM", a1, a1_len, a256, a256_len);
        }
    }

    /*
     * Step c: measure the MLE into PCR 18.  Ordered after the hash
     * sequence because _TPM_Hash_Start zeroes PCR 18 as well, so doing
     * it the other way round would discard this extend.
     */
    ret = intel_txt_measure_mle(s, entry, &log, &err);
    if (ret < 0) {
        goto fail_measure;
    }
    /*
     * The remaining launch-context extends, in the order the log
     * records them.  Must follow the MLE measurement: it supplies the
     * digest PCR 17 takes here.
     */
    if (intel_txt_extend_context(s, &log, &err) < 0) {
        ret = -1;
        goto fail_measure;
    }
    if (!intel_txt_write_sinit_mle_data(s, &err) ||
        !intel_txt_event_log_publish(&log, &err)) {
        goto fail_heap_data;
    }

    g_free(acm);
    s->errorcode = 0;
    s->sts |= TXT_STS_SENTER_DONE | TXT_STS_MEM_CONFIG_LOCK |
              TXT_STS_PRIVATE_OPEN;
    return true;

fail_sinit_region:
    s->errorcode = TXT_ERRORCODE_SINIT_REGION_INVALID;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
fail_sinit_dpr:
    s->errorcode = TXT_ERRORCODE_SINIT_NOT_IN_DPR;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
fail_pmr:
    error_report_err(err);
    g_free(acm);
    s->errorcode = pmr_errorcode;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
fail_event_log:
    error_report_err(err);
    g_free(acm);
    s->errorcode = TXT_ERRORCODE_HEAP_INVALID;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
fail_pmr_program:
    error_report_err(err);
    intel_txt_release_smis(s);
    g_free(acm);
    s->errorcode = TXT_ERRORCODE_PMR_PROGRAM_FAILED;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
fail_heap_data:
    error_report_err(err);
    intel_txt_release_smis(s);
fail_heap:
    g_free(acm);
    s->errorcode = TXT_ERRORCODE_HEAP_INVALID;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
fail_acm:
    /*
     * A precondition failure, so nothing has been measured: report
     * which structural check the blob failed and leave the PCRs
     * alone.
     */
    error_report_err(err);
    g_free(acm);
    s->errorcode = TXT_ERRORCODE_ACM_INVALID;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
fail_measure:
    /*
     * Measurement or MLE image/entry validation failed (TPM backend
     * error, malformed MLE header or page table, ...).
     */
    error_report_err(err);
    intel_txt_release_smis(s);
    g_free(acm);
    s->errorcode = TXT_ERRORCODE_MEASURE_FAILED;
    trace_txt_senter_errorcode(s->errorcode);
    return false;
}

bool intel_txt_smi_inhibited(IntelTxtState *s)
{
    return s->smi_inhibit;
}

void intel_txt_hold_smi(CPUState *cs)
{
    cpu_env(cs)->smi_held = true;
    trace_txt_smi_held(cs->cpu_index);
}

void intel_txt_release_smis(IntelTxtState *s)
{
    CPUState *cs;
    int pending = 0;

    /*
     * GETSEC helpers run without the BQL.  Serialize the inhibit
     * transition with SMI consumption on other vCPU threads; the
     * flag must be cleared atomically with draining held SMIs.
     */
    bql_lock();
    if (!s->smi_inhibit) {
        bql_unlock();
        return;
    }
    s->smi_inhibit = false;
    CPU_FOREACH(cs) {
        /*
         * Several SMIs held on one CPU collapse into a single
         * redelivery; no SMM handler in this model depends on the
         * count.
         */
        if (cpu_env(cs)->smi_held) {
            cpu_env(cs)->smi_held = false;
            cpu_interrupt(cs, CPU_INTERRUPT_SMI);
            pending++;
        }
    }
    bql_unlock();
    trace_txt_smi_released(pending);
}

bool intel_txt_smctrl(IntelTxtState *s, uint32_t control)
{
    if (control == 0 && (s->sts & TXT_STS_SENTER_DONE)) {
        /*
         * GETSEC[SMCTRL] with EBX=0 releases the SMI inhibition that
         * SENTER engaged: held SMIs are redelivered and new ones flow
         * normally until SEXIT.
         */
        intel_txt_release_smis(s);
        return true;
    }
    return false;
}

bool intel_txt_sexit(IntelTxtState *s)
{
    if (!(s->sts & TXT_STS_SENTER_DONE)) {
        /* Not in a measured environment: the SDM requires #GP. */
        return false;
    }

    /*
     * Leave the measured environment.  SEXIT is *not* a platform
     * reset: execution continues at the instruction after GETSEC, and
     * tboot's txt_shutdown() prints "measured environment torn down"
     * there before handing off to the OS, so a reset would make the
     * whole handoff unreachable.
     *
     * An MLE normally reaches this having already issued
     * CMD_NO_SECRETS, CMD_UNLOCK_MEM_CONFIG and CMD_CLOSE_PRIVATE
     * itself (tboot/txt/txt.c), so most of the below is idempotent;
     * do it anyway, because SEXIT must be sufficient on its own.
     */
    s->e2sts &= ~TXT_E2STS_SECRET_STS;
    s->sts &= ~(TXT_STS_SENTER_DONE | TXT_STS_MEM_CONFIG_LOCK |
                TXT_STS_PRIVATE_OPEN | TXT_STS_LOCALITY1_OPEN |
                TXT_STS_LOCALITY2_OPEN);
    s->sts |= TXT_STS_SEXIT_DONE;

    /*
     * Release the VT-d PMR protection along with the measured
     * environment: the OS takes over with ordinary DMA and its own
     * VT-d driver (if any).  A later SENTER re-programs the PMRs.
     */
    {
        X86IOMMUState *x86_iommu = x86_iommu_get_default();
        Object *iommu = x86_iommu ?
            object_dynamic_cast(OBJECT(&x86_iommu->busdev),
                                TYPE_INTEL_IOMMU_DEVICE) : NULL;

        if (iommu) {
            intel_iommu_clear_txt_pmr(INTEL_IOMMU_DEVICE(iommu));
        }
    }

    /*
     * Release the SMI inhibition together with the measured
     * environment: SMIs held during the launch are redelivered, and
     * new ones flow normally to the firmware/OS that takes over.
     */
    intel_txt_release_smis(s);

    /*
     * SINIT_BASE/SIZE, HEAP_BASE/SIZE and DPR deliberately stay
     * programmed: that is what allows a further SENTER in the same
     * power cycle.  Only a TXT reset clears them.
     */
    trace_txt_sexit(s->sts);
    return true;
}

static bool intel_txt_join_desc(uint32_t base, uint32_t limit,
                                uint32_t selector, uint64_t *desc)
{
    uint32_t offset = selector & ~7u;

    if (selector & 4 || offset == 0 || offset + 7 > limit) {
        return false;
    }
    return intel_txt_gread_u64((uint64_t)base + offset, desc, NULL);
}

bool intel_txt_wakeup(IntelTxtState *s, IntelTxtRlpEntry *rlp)
{
    uint64_t addr = s->mle_join;
    uint32_t cs_flags, ds_flags;

    if (!(s->sts & TXT_STS_SENTER_DONE) || !addr || (addr & 3) ||
        addr > INTEL_TXT_GUEST_32BIT_LIMIT - 16) {
        trace_txt_wakeup_rejected("unlaunched or invalid MLE_JOIN pointer");
        return false;
    }
    /* mle_join_t is four little-endian u32s in tboot config_regs.h. */
    if (!intel_txt_gread_u32(addr, &rlp->gdt_limit, NULL) ||
        !intel_txt_gread_u32(addr + 4, &rlp->gdt_base, NULL) ||
        !intel_txt_gread_u32(addr + 8, &rlp->seg_sel, NULL) ||
        !intel_txt_gread_u32(addr + 12, &rlp->entry_point, NULL)) {
        trace_txt_wakeup_rejected("unreadable MLE_JOIN");
        return false;
    }
    trace_txt_wakeup_join(rlp->gdt_base, rlp->gdt_limit, rlp->seg_sel,
                          rlp->entry_point);
    if (rlp->gdt_limit < 23 || rlp->gdt_limit > UINT16_MAX ||
        !rlp->gdt_base ||
        (uint64_t)rlp->gdt_base + rlp->gdt_limit >=
            INTEL_TXT_GUEST_32BIT_LIMIT) {
        trace_txt_wakeup_rejected("MLE_JOIN GDT base/limit out of range");
        return false;
    }
    if (!rlp->entry_point) {
        trace_txt_wakeup_rejected("MLE_JOIN entry point is zero");
        return false;
    }
    if (rlp->seg_sel > UINT16_MAX - 8) {
        trace_txt_wakeup_rejected("MLE_JOIN segment selector out of range");
        return false;
    }
    if (!intel_txt_join_desc(rlp->gdt_base, rlp->gdt_limit,
                             rlp->seg_sel, &rlp->cs_desc) ||
        !intel_txt_join_desc(rlp->gdt_base, rlp->gdt_limit,
                             rlp->seg_sel + 8, &rlp->ds_desc)) {
        trace_txt_wakeup_rejected("MLE_JOIN CS/DS descriptor not in the GDT");
        return false;
    }
    cs_flags = rlp->cs_desc >> 32;
    ds_flags = rlp->ds_desc >> 32;
    /*
     * Ring-0 present flat 32-bit CS and writable DS; the tboot entry
     * uses CS-relative addressing before loading its own GDT.
     */
    if ((cs_flags & 0x0040f800) != 0x00409800 ||
        (cs_flags & 0x00200000)) {
        trace_txt_wakeup_rejected("MLE_JOIN CS is not a present 32-bit "
                                  "ring-0 code descriptor");
        return false;
    }
    if ((ds_flags & 0x0040fa00) != 0x00409200) {
        trace_txt_wakeup_rejected("MLE_JOIN DS is not a present 32-bit "
                                  "ring-0 writable data descriptor");
        return false;
    }
    if (((rlp->cs_desc >> 16) & 0xffff) != 0 ||
        (cs_flags & 0xff000000) != 0 ||
        (cs_flags & 0xff) != 0) {
        trace_txt_wakeup_rejected("MLE_JOIN CS base is not flat");
        return false;
    }
    trace_txt_wakeup_entry(rlp->entry_point, rlp->seg_sel,
                           rlp->gdt_base, rlp->gdt_limit);
    return true;
}

/*
 * The SINIT ACM txt-firmware=on places: a header, info table, chipset
 * id list and GDT that pass intel_txt_validate_acm() and the loaders'
 * checks (GRUB's and tboot's acmod.c), and no code, as SENTER never
 * runs it.  Unsigned, like every ACM this model accepts.
 */
#define FW_ACM_SIZE                 0x8000
#define FW_ACM_HEADER_LEN           161     /* dwords, RSA-2048 header */
#define FW_ACM_SCRATCH_SIZE         143     /* dwords */
#define FW_ACM_INFO_OFF             ((FW_ACM_HEADER_LEN + \
                                      FW_ACM_SCRATCH_SIZE) * 4)
#define FW_ACM_ID_LIST_OFF          (FW_ACM_INFO_OFF + ACM_INFO_MIN_SIZE)
#define FW_ACM_GDT_OFF              (FW_ACM_ID_LIST_OFF + \
                                     ACM_CHIPSET_ID_LIST_HDR_SIZE + \
                                     ACM_CHIPSET_ID_SIZE)
#define FW_ACM_ENTRY_POINT          0x1000

#define ACM_HDR_OFF_DATE            0x14    /* u32, BCD */
#define ACM_HDR_OFF_KEY_SIZE        0x78    /* u32, dwords */
#define ACM_INFO_OFF_LENGTH         0x12    /* u16 */
#define ACM_INFO_OFF_OS_SINIT_VER   0x18    /* u32 */
#define ACM_INFO_OFF_MIN_MLE_VER    0x1c    /* u32 */
#define ACM_INFO_OFF_CAPABILITIES   0x20    /* u32 */

/*
 * SINIT capabilities (txt_caps_t): both RLP wake methods, the TPM 1.2
 * PCR usage bits a TPM 2.0 SINIT also sets, the MTRR physical address
 * width and the TPM 2.0 event log format
 */
#define FW_ACM_CAPABILITIES         (TXT_CAPS_RLP_WAKE_GETSEC | \
                                     TXT_CAPS_RLP_WAKE_MONITOR | \
                                     BIT(4) | BIT(5) | BIT(8) | BIT(9))

static void intel_txt_fw_build_acm(IntelTxtState *s, uint8_t *acm)
{
    uint8_t *info = acm + FW_ACM_INFO_OFF;
    uint8_t *id = acm + FW_ACM_ID_LIST_OFF + ACM_CHIPSET_ID_LIST_HDR_SIZE;
    uint8_t *gdt = acm + FW_ACM_GDT_OFF;

    memset(acm, 0, FW_ACM_SIZE);
    stw_le_p(acm + ACM_HDR_OFF_MODULE_TYPE, ACM_TYPE_CHIPSET);
    stw_le_p(acm + ACM_HDR_OFF_MODULE_SUBTYPE, ACM_SUBTYPE_SINIT);
    stl_le_p(acm + ACM_HDR_OFF_HEADER_LEN, FW_ACM_HEADER_LEN);
    stl_le_p(acm + ACM_HDR_OFF_MODULE_VENDOR, ACM_VENDOR_INTEL);
    stl_le_p(acm + ACM_HDR_OFF_DATE, 0x20260101);
    stl_le_p(acm + ACM_HDR_OFF_SIZE, FW_ACM_SIZE / 4);
    stl_le_p(acm + ACM_HDR_OFF_GDT_LIMIT, 3 * 8 - 1);
    stl_le_p(acm + ACM_HDR_OFF_GDT_BASE, FW_ACM_GDT_OFF);
    stl_le_p(acm + ACM_HDR_OFF_SEG_SEL, 0x08);
    stl_le_p(acm + ACM_HDR_OFF_ENTRY_POINT, FW_ACM_ENTRY_POINT);
    stl_le_p(acm + ACM_HDR_OFF_KEY_SIZE, 256 / 4);
    stl_le_p(acm + ACM_HDR_OFF_SCRATCH_SIZE, FW_ACM_SCRATCH_SIZE);

    /* Version 3: no processor id list for a loader to match */
    memcpy(info + ACM_INFO_OFF_UUID, intel_txt_acm_uuid,
           sizeof(intel_txt_acm_uuid));
    info[ACM_INFO_OFF_CHIPSET_ACM_TYPE] = ACM_CHIPSET_TYPE_SINIT;
    info[ACM_INFO_OFF_VERSION] = ACM_INFO_MIN_VERSION;
    stw_le_p(info + ACM_INFO_OFF_LENGTH, ACM_INFO_MIN_SIZE);
    stl_le_p(info + ACM_INFO_OFF_CHIPSET_ID_LIST, FW_ACM_ID_LIST_OFF);
    stl_le_p(info + ACM_INFO_OFF_OS_SINIT_VER, 7);
    stl_le_p(info + ACM_INFO_OFF_MIN_MLE_VER, 0x00020000);
    stl_le_p(info + ACM_INFO_OFF_CAPABILITIES, FW_ACM_CAPABILITIES);

    /* One entry, this chipset's TXT.DIDVID */
    stl_le_p(acm + FW_ACM_ID_LIST_OFF + ACM_CHIPSET_ID_LIST_OFF_COUNT, 1);
    stw_le_p(id + ACM_CHIPSET_ID_OFF_VENDOR, s->didvid & 0xffff);
    stw_le_p(id + ACM_CHIPSET_ID_OFF_DEVICE, (s->didvid >> 16) & 0xffff);
    stw_le_p(id + ACM_CHIPSET_ID_OFF_REVISION, (s->didvid >> 32) & 0xffff);

    /* Null, flat 32-bit ring 0 code, flat writable data */
    stq_le_p(gdt + 0x08, 0x00cf9b000000ffffULL);
    stq_le_p(gdt + 0x10, 0x00cf93000000ffffULL);
}

/* BIOS data (txt_bios_data_t) version 6, the TPM 2.0 one */
#define FW_BIOS_DATA_VERSION        6
#define FW_BIOS_DATA_SIZE           0x24
#define FW_HEAP_EXT_END_SIZE        8

/*
 * Leave the platform as TXT firmware leaves it before the first guest
 * instruction: what a BIOS ACM and coreboot's TXT setup would do.  Runs
 * in the reset exit phase, after the CPU reset has cleared
 * IA32_FEATURE_CONTROL in hold.
 */
static void intel_txt_fw_setup(IntelTxtState *s)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    uint64_t sinit = s->fw_dpr_base + INTEL_TXT_FW_SINIT_OFFSET;
    uint64_t heap = s->fw_dpr_base + INTEL_TXT_FW_HEAP_OFFSET;
    uint64_t dpr_top = s->fw_dpr_base + INTEL_TXT_FW_DPR_SIZE;
    g_autofree uint8_t *dpr = g_malloc0(INTEL_TXT_FW_DPR_SIZE);
    uint8_t *bios = dpr + INTEL_TXT_FW_HEAP_OFFSET;
    CPUState *cs;

    intel_txt_fw_build_acm(s, dpr + INTEL_TXT_FW_SINIT_OFFSET);

    /* The heap's first section, its u64 size counting itself */
    stq_le_p(bios, 8 + FW_BIOS_DATA_SIZE + FW_HEAP_EXT_END_SIZE);
    bios += 8;
    stl_le_p(bios + 0x00, FW_BIOS_DATA_VERSION);
    stl_le_p(bios + 0x04, FW_ACM_SIZE);         /* bios_sinit_size */
    stl_le_p(bios + 0x18, ms->smp.cpus);        /* num_logical_procs */
    /* An END element after the fixed part, as from version 4 */
    stl_le_p(bios + FW_BIOS_DATA_SIZE + 4, FW_HEAP_EXT_END_SIZE);

    address_space_write(&address_space_memory, s->fw_dpr_base,
                        MEMTXATTRS_UNSPECIFIED, dpr, INTEL_TXT_FW_DPR_SIZE);

    s->sinit_base = sinit;
    s->sinit_size = INTEL_TXT_FW_SINIT_SIZE;
    s->heap_base = heap;
    s->heap_size = INTEL_TXT_FW_HEAP_SIZE;
    intel_txt_reg_write64(s, TXT_DPR, (dpr_top & ~0xfffffULL) |
                          (INTEL_TXT_FW_DPR_SIZE / MiB) << 4 | TXT_DPR_LOCK);
    if (!(s->dpr & TXT_DPR_LOCK)) {
        error_report("txt-firmware=on cannot lock the DPR, it needs "
                     "-device intel-iommu");
        exit(1);
    }

    /* Locked, so with the bits the firmware would otherwise set too */
    CPU_FOREACH(cs) {
        X86CPU *cpu = X86_CPU(cs);

        cpu->env.msr_ia32_feature_control =
            fw_cfg_feature_control_bits(cpu) |
            FEATURE_CONTROL_LOCKED |
            FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX |
            FEATURE_CONTROL_SENTER_LOCAL_ENABLE |
            FEATURE_CONTROL_SENTER_GLOBAL_ENABLE;
    }
    trace_txt_firmware_setup(s->fw_dpr_base, sinit, heap);
}

#endif /* CONFIG_TPM */

uint64_t intel_txt_fw_dpr_base(uint64_t below_4g, uint64_t tseg,
                               Error **errp)
{
    uint64_t below = tseg + INTEL_TXT_FW_GAP + INTEL_TXT_FW_DPR_SIZE;

    /* Leave the firmware and the OS at least 256 MiB of RAM below it */
    if (below_4g < below + 256 * MiB) {
        error_setg(errp, "txt-firmware=on needs at least %" PRIu64
                   " MiB of RAM below 4 GiB", (below + 256 * MiB) / MiB);
        return 0;
    }
    /* DPR is in 1 MiB units */
    return (below_4g - below) & ~(MiB - 1);
}

static const MemoryRegionOps intel_txt_private_ops = {
    .read = intel_txt_private_read,
    .write = intel_txt_private_write,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
        .unaligned = false,
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void intel_txt_reset_hold(Object *obj, ResetType type)
{
    IntelTxtState *s = INTEL_TXT(obj);

    /*
     * TXT_RESET_STS is preserved so that boot firmware can detect
     * a TXT reset after the fact.  QEMU routes every reset through
     * this handler (it has no distinct power-on reset), so the bit
     * survives all machine resets in practice and is only clearable
     * by software via the ESTS write-one-to-clear path.
     */
    uint64_t txt_reset_sts = s->ests & TXT_ESTS_TXT_RESET_STS;

    s->sts = 0;
    s->ests = txt_reset_sts;
    s->errorcode = 0;
    s->spad = 0;
    s->sinit_base = 0;
    s->sinit_size = 0;
    s->mle_join = 0;
    s->heap_base = 0;
    s->heap_size = 0;
    s->mseg_base = 0;
    s->mseg_size = 0;
    s->biosacm_errorcode = 0;
    qatomic_set(&s->dpr, 0);
#ifdef CONFIG_TPM
    {
        IntelIOMMUState *iommu = intel_txt_iommu();

        if (iommu) {
            intel_iommu_clear_txt_dpr(iommu);
        }
    }
#endif
    s->e2sts = 0;
    s->smi_inhibit = false;
    s->rlp_wake_monitor = false;
}

static void intel_txt_reset_exit(Object *obj, ResetType type)
{
#ifdef CONFIG_TPM
    IntelTxtState *s = INTEL_TXT(obj);

    if (s->fw_dpr_base) {
        intel_txt_fw_setup(s);
    }
#endif
}

static void intel_txt_realize(DeviceState *dev, Error **errp)
{
    IntelTxtState *s = INTEL_TXT(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

#ifdef CONFIG_TPM
    /*
     * The DRTM measurements run through the TPM backend.  The q35
     * machine refuses txt=on without one, so this cannot fail in
     * practice; the guard keeps the API safe if the device is ever
     * realized some other way.
     */
    s->tpm = qemu_find_tpm_be_any();
    if (s->tpm == NULL) {
        error_setg(errp, "txt=on requires a TPM backend "
                   "(-tpmdev ..., -device tpm-tis,...)");
        return;
    }

    /*
     * Only the emulator backend honours TPMBackendCmd::locty --
     * tpm_emulator_handle_request() issues CMD_SET_LOCALITY from it.
     * tpm_passthrough_handle_request() ignores the field entirely and
     * forwards to the host TPM at whatever locality the guest last
     * opened, so the DRTM measurements would silently run outside
     * locality 4 and defeat spec step d.  Refuse rather than measure
     * into the wrong locality.
     */
    if (!tpm_backend_has_hash_sequence(s->tpm)) {
        error_setg(errp, "txt=on requires -tpmdev emulator: the DRTM "
                   "measurements need the TIS _TPM_Hash_* signals and "
                   "per-command TPM locality 4, which only the emulator "
                   "backend provides");
        return;
    }
#endif

    memory_region_init_io(&s->mmio_public, OBJECT(s),
                          &intel_txt_public_ops, s,
                          TYPE_INTEL_TXT ".public",
                          INTEL_TXT_SPACE_SIZE);
    sysbus_init_mmio(sbd, &s->mmio_public);
    sysbus_mmio_map(sbd, 0, INTEL_TXT_PUBLIC_BASE);

    memory_region_init_io(&s->mmio_private, OBJECT(s),
                          &intel_txt_private_ops, s,
                          TYPE_INTEL_TXT ".private",
                          INTEL_TXT_SPACE_SIZE);
    sysbus_init_mmio(sbd, &s->mmio_private);
    sysbus_mmio_map(sbd, 1, INTEL_TXT_PRIVATE_BASE);
}

static const Property intel_txt_properties[] = {
    DEFINE_PROP_UINT64("didvid", IntelTxtState, didvid,
                      INTEL_TXT_DIDVID_DEFAULT),
    /* Set by the machine for txt-firmware=on */
    DEFINE_PROP_UINT64("firmware-dpr-base", IntelTxtState, fw_dpr_base, 0),
};

#ifdef CONFIG_TPM
static int intel_txt_post_load(void *opaque, int version_id)
{
    IntelTxtState *s = opaque;
    IntelIOMMUState *iommu = intel_txt_iommu();
    uint64_t base, top;
    Error *err = NULL;

    if (intel_txt_dpr_range(s->dpr, &base, &top)) {
        if (!iommu || !intel_iommu_set_txt_dpr(iommu, base, top, &err)) {
            if (err) {
                error_report_err(err);
            }
            return -EINVAL;
        }
    } else if ((s->dpr & TXT_DPR_LOCK) && ((s->dpr >> 4) & 0xff)) {
        /* Never restore an invalid, locked DPR as an unprotected one. */
        return -EINVAL;
    } else if (iommu) {
        intel_iommu_clear_txt_dpr(iommu);
    }
    return 0;
}
#endif

static const VMStateDescription vmstate_intel_txt = {
#ifdef CONFIG_TPM
    .post_load = intel_txt_post_load,
#endif
    .name = TYPE_INTEL_TXT,
    .version_id = 3,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(sts, IntelTxtState),
        VMSTATE_UINT64(ests, IntelTxtState),
        VMSTATE_UINT64(errorcode, IntelTxtState),
        VMSTATE_UINT64(spad, IntelTxtState),
        VMSTATE_UINT64(sinit_base, IntelTxtState),
        VMSTATE_UINT64(sinit_size, IntelTxtState),
        VMSTATE_UINT64(mle_join, IntelTxtState),
        VMSTATE_UINT64(heap_base, IntelTxtState),
        VMSTATE_UINT64(heap_size, IntelTxtState),
        VMSTATE_UINT64(mseg_base, IntelTxtState),
        VMSTATE_UINT64(mseg_size, IntelTxtState),
        VMSTATE_UINT64(biosacm_errorcode, IntelTxtState),
        VMSTATE_UINT64(dpr, IntelTxtState),
        VMSTATE_UINT64(e2sts, IntelTxtState),
        VMSTATE_BOOL_V(smi_inhibit, IntelTxtState, 2),
        VMSTATE_BOOL_V(rlp_wake_monitor, IntelTxtState, 3),
        VMSTATE_END_OF_LIST()
    },
};

static void intel_txt_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    dc->realize = intel_txt_realize;
    dc->vmsd = &vmstate_intel_txt;
    device_class_set_props(dc, intel_txt_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    rc->phases.hold = intel_txt_reset_hold;
    rc->phases.exit = intel_txt_reset_exit;
}

static const TypeInfo intel_txt_info = {
    .name          = TYPE_INTEL_TXT,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(IntelTxtState),
    .class_init    = intel_txt_class_init,
};

static void intel_txt_register_types(void)
{
    type_register_static(&intel_txt_info);
}

type_init(intel_txt_register_types)
