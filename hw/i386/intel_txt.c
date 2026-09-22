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

#include "hw/i386/intel_txt.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/sysbus.h"
#include "migration/vmstate.h"
#include "qemu/main-loop.h"
#include "system/runstate.h"
#include "system/tpm_util.h"
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

    /* TXT.DIDVID, configurable for experimentation (see spec) */
    uint64_t didvid;

#ifdef CONFIG_TPM
    /*
     * TPM backend the DRTM measurements are submitted through.
     * Resolved at realize; a device link, not migratable state.
     */
    TPMBackend *tpm;
#endif
};

/*
 * All TXT configuration registers are 64 bits wide and must be
 * accessed with aligned quadword reads and writes; other access
 * sizes are rejected by the memory core, like on real hardware.
 */

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
        s->dpr = val & TXT_DPR_MASK;
        if (s->dpr & TXT_DPR_LOCK) {
            trace_txt_dpr_locked(s->dpr);
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

static uint64_t intel_txt_public_read(void *opaque, hwaddr addr,
                                      unsigned size)
{
    IntelTxtState *s = INTEL_TXT(opaque);
    uint64_t val = intel_txt_reg_read64(s, addr);

    trace_txt_reg_read("public", addr, val);
    return val;
}

static void intel_txt_public_write(void *opaque, hwaddr addr,
                                   uint64_t val, unsigned size)
{
    IntelTxtState *s = INTEL_TXT(opaque);

    trace_txt_reg_write("public", addr, val);
    intel_txt_reg_write64(s, addr, val);
}

static uint64_t intel_txt_private_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    IntelTxtState *s = INTEL_TXT(opaque);
    uint64_t val = intel_txt_reg_read64(s, addr);

    trace_txt_reg_read("private", addr, val);
    return val;
}

static void intel_txt_private_write(void *opaque, hwaddr addr,
                                    uint64_t val, unsigned size)
{
    /*
     * The private space is writable only by the SINIT ACM on real
     * hardware.  In the semantic model nothing runs inside it, so
     * all writes are ignored (see docs/specs/intel-txt.rst,
     * "TXT private config space").
     */
    trace_txt_reg_write_ignored("private", addr, val);
}

static const MemoryRegionOps intel_txt_public_ops = {
    .read = intel_txt_public_read,
    .write = intel_txt_public_write,
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 8,
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
 * Max ACM size, in bytes: the value GETSEC[PARAMETERS] reports
 * (0x8000 in 32-byte units).  Bounds the SINIT region read rather
 * than allocating whatever the guest asked for.
 */
#define INTEL_TXT_MAX_ACM_SIZE 0x8000

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
static int intel_txt_tpm_send(IntelTxtState *s, const uint8_t *cmd,
                              uint32_t cmd_len, Error **errp)
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
    if (s->tpm->cmd != NULL) {
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
    }
    g_free(resp);
    return ret;
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
        if ((digests[i].alg != TPM2_ALG_SHA1 || digests[i].len != 20) &&
            (digests[i].alg != TPM2_ALG_SHA256 || digests[i].len != 32)) {
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
    if (s->tpm->cmd != NULL) {
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

void intel_txt_senter(IntelTxtState *s)
{
    uint64_t dpr_size;
    uint64_t dpr_top;
    uint8_t *acm = NULL;
    Error *err = NULL;
    int ret = 0;

    trace_txt_senter();

    /*
     * Precondition 2: TXT.SINIT_BASE/SIZE.  Non-zero, the region
     * entirely below 4 GiB (which also bounds the read below), and
     * not larger than the max ACM size GETSEC[PARAMETERS] reports.
     */
    if (s->sinit_base == 0 || s->sinit_size == 0 ||
        s->sinit_base >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        s->sinit_size > INTEL_TXT_GUEST_32BIT_LIMIT - s->sinit_base ||
        s->sinit_size > INTEL_TXT_MAX_ACM_SIZE) {
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
    if (dpr_size == 0 ||
        s->sinit_base < (dpr_top << 20) - dpr_size * 0x100000ull ||
        s->sinit_base + s->sinit_size > (dpr_top << 20)) {
        goto fail_sinit_dpr;
    }

    /*
     * Precondition 3 (ACM header sanity) is deliberately not checked
     * here: it needs the synthetic SINIT ACM fixture, which is a
     * later slice (docs/plans/intel-txt-m3-plan.md section 3.5).
     *
     * Precondition 4: TXT.HEAP_BASE/SIZE set, the region below
     * 4 GiB.  The heap contents are not parsed yet (spec steps c/e).
     */
    if (s->heap_base == 0 || s->heap_size == 0 ||
        s->heap_base >= INTEL_TXT_GUEST_32BIT_LIMIT ||
        s->heap_size > INTEL_TXT_GUEST_32BIT_LIMIT - s->heap_base) {
        goto fail_heap;
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
     * This is still only the first component of the eventual PCR 17
     * value: steps c/e (MLE hash, sinit_mle_data) extend more in later
     * slices, so it is not final or attestable.  PCR 18 is untouched;
     * its content is the MLE hash, which needs the heap parsing of
     * step c.
     */
    acm = g_malloc(s->sinit_size);
    if (address_space_read(&address_space_memory, s->sinit_base,
                           MEMTXATTRS_UNSPECIFIED, acm,
                           s->sinit_size) != MEMTX_OK) {
        error_setg(&err, "cannot read the SINIT ACM region at 0x%" PRIx64,
                   s->sinit_base);
        goto fail_measure;
    }

    ret = intel_txt_drtm_hash_measure(s, acm, s->sinit_size, &err);
    if (ret < 0) {
        goto fail_measure;
    }

    g_free(acm);
    s->errorcode = TXT_ERRORCODE_LAUNCH_INCOMPLETE;
    trace_txt_senter_errorcode(s->errorcode);
    return;

fail_sinit_region:
    s->errorcode = TXT_ERRORCODE_SINIT_REGION_INVALID;
    trace_txt_senter_errorcode(s->errorcode);
    return;
fail_sinit_dpr:
    s->errorcode = TXT_ERRORCODE_SINIT_NOT_IN_DPR;
    trace_txt_senter_errorcode(s->errorcode);
    return;
fail_heap:
    s->errorcode = TXT_ERRORCODE_HEAP_INVALID;
    trace_txt_senter_errorcode(s->errorcode);
    return;
fail_measure:
    /*
     * The launch inputs validated but the measurement itself failed
     * (TPM backend error, in-flight request, ...).  This gets its own
     * code rather than reusing LAUNCH_INCOMPLETE: sharing one value
     * makes a rejected measurement look identical to a staged launch
     * that measured successfully, which is precisely how a broken
     * PCR_Reset went unnoticed behind a passing test.
     */
    error_report_err(err);
    g_free(acm);
    s->errorcode = TXT_ERRORCODE_MEASURE_FAILED;
    trace_txt_senter_errorcode(s->errorcode);
}

#endif /* CONFIG_TPM */

static const MemoryRegionOps intel_txt_private_ops = {
    .read = intel_txt_private_read,
    .write = intel_txt_private_write,
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 8,
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
    s->dpr = 0;
    s->e2sts = 0;
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
};

static const VMStateDescription vmstate_intel_txt = {
    .name = TYPE_INTEL_TXT,
    .version_id = 1,
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
