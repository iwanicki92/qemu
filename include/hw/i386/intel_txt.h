/*
 * QEMU Intel TXT (Trusted Execution Technology) chipset device
 *
 * Copyright (c) 2026 Michał Kopeć <michal@nozomi.space>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_I386_INTEL_TXT_H
#define HW_I386_INTEL_TXT_H

#include "exec/hwaddr.h"
#include "qapi/error.h"
#include "qom/object.h"

#define TYPE_INTEL_TXT "intel-txt"

/*
 * Fixed TXT platform addresses, matching real Intel TXT chipsets
 * (coreboot src/security/intel/txt/txt_register.h, tboot
 * include/txt/config_regs.h).  See docs/specs/intel-txt.rst.
 */
#define INTEL_TXT_PRIVATE_BASE   0xfed20000
#define INTEL_TXT_PUBLIC_BASE    0xfed30000
#define INTEL_TXT_SPACE_SIZE     0x10000

/*
 * Register offsets, common to the public and private spaces.
 */
#define TXT_STS                 0x000
#define TXT_ESTS                0x008
#define TXT_ERRORCODE           0x030
#define TXT_CMD_RESET           0x038
#define TXT_CMD_CLOSE_PRIVATE   0x048
#define TXT_SPAD                0x0a0
#define TXT_VER_FSBIF           0x100
#define TXT_DIDVID              0x110
#define TXT_CAPABILITIES        0x200
#define TXT_CMD_UNLOCK_MEM      0x218
#define TXT_SINIT_BASE          0x270
#define TXT_SINIT_SIZE          0x278
#define TXT_MLE_JOIN            0x290
#define TXT_HEAP_BASE           0x300
#define TXT_HEAP_SIZE           0x308
#define TXT_MSEG_BASE           0x310
#define TXT_MSEG_SIZE           0x318
#define TXT_BIOSACM_ERRORCODE   0x328
#define TXT_DPR                 0x330
#define TXT_CMD_OPEN_LOCALITY1  0x380
#define TXT_CMD_CLOSE_LOCALITY1 0x388
#define TXT_CMD_OPEN_LOCALITY2  0x390
#define TXT_CMD_CLOSE_LOCALITY2 0x398
#define TXT_PUBLIC_KEY          0x400
#define TXT_CMD_SECRETS         0x8e0
#define TXT_CMD_NO_SECRETS      0x8e8
#define TXT_E2STS               0x8f0

/* TXT.STS bits */
#define TXT_STS_SENTER_DONE       BIT_ULL(0)
#define TXT_STS_SEXIT_DONE        BIT_ULL(1)
#define TXT_STS_MEM_CONFIG_LOCK   BIT_ULL(6)
#define TXT_STS_PRIVATE_OPEN      BIT_ULL(7)
#define TXT_STS_LOCALITY1_OPEN    BIT_ULL(15)
#define TXT_STS_LOCALITY2_OPEN    BIT_ULL(16)

/* TXT.ESTS bits */
#define TXT_ESTS_TXT_RESET_STS    BIT_ULL(0)
#define TXT_ESTS_WAKE_ERROR_STS   BIT_ULL(6)
#define TXT_ESTS_W1C_MASK         (TXT_ESTS_TXT_RESET_STS | \
                                   TXT_ESTS_WAKE_ERROR_STS)

/* TXT.VER.FSBIF bits */
#define TXT_VER_FSBIF_PROD_FUSED  BIT_ULL(31)

/* TXT.CAPABILITIES bits */
#define TXT_CAPABILITIES_DPR      BIT_ULL(26)

/* TXT.E2STS bits */
#define TXT_E2STS_SECRET_STS      BIT_ULL(1)

/* TXT.DPR: lock/size/top occupy the low 32 bits, the rest is reserved */
#define TXT_DPR_LOCK            BIT_ULL(0)
#define TXT_DPR_MASK            0xffffffffull

/*
 * QEMU-specific TXT.ERRORCODE values, in the ACMERROR layout
 * documented in docs/specs/intel-txt.rst ("TXT.ERRORCODE
 * (ACMERROR) layout"): bit 31 VALID, bit 30 EXTERNAL (0 = processor
 * / SINIT), [3:0] TYPE_CODE (1 = SINIT ACM); the reason goes in the
 * [23:16] PROGRESS_CODE field.  See the table in the spec.
 */
#define TXT_ERRORCODE_VALID            BIT_ULL(31)
#define TXT_ERRORCODE_TYPE_SINIT       BIT_ULL(0)

#define TXT_ERRORCODE_PROGRESS_CODE(n) \
    (((uint64_t)(n) & 0xff) << 16)

/* SENTER precondition: TXT.SINIT_BASE/SIZE zero, not below 4 GiB,
   overflowing, or larger than the max ACM size. */
#define TXT_ERRORCODE_SINIT_REGION_INVALID \
    (TXT_ERRORCODE_VALID | TXT_ERRORCODE_TYPE_SINIT | \
     TXT_ERRORCODE_PROGRESS_CODE(0x01))
/* SENTER precondition: the SINIT region is not entirely inside the
   DPR range (which is empty when DPR SIZE is zero). */
#define TXT_ERRORCODE_SINIT_NOT_IN_DPR \
    (TXT_ERRORCODE_VALID | TXT_ERRORCODE_TYPE_SINIT | \
     TXT_ERRORCODE_PROGRESS_CODE(0x02))
/* SENTER precondition: TXT.HEAP_BASE/SIZE zero or not below 4 GiB. */
#define TXT_ERRORCODE_HEAP_INVALID \
    (TXT_ERRORCODE_VALID | TXT_ERRORCODE_TYPE_SINIT | \
     TXT_ERRORCODE_PROGRESS_CODE(0x03))
/* Historical staged-launch error code; no longer issued on success. */
#define TXT_ERRORCODE_LAUNCH_INCOMPLETE \
    (TXT_ERRORCODE_VALID | TXT_ERRORCODE_TYPE_SINIT | \
     TXT_ERRORCODE_PROGRESS_CODE(0x04))
/* SENTER: DRTM measurement failed or the MLE image/entry is invalid. */
#define TXT_ERRORCODE_MEASURE_FAILED \
    (TXT_ERRORCODE_VALID | TXT_ERRORCODE_TYPE_SINIT | \
     TXT_ERRORCODE_PROGRESS_CODE(0x05))
/* APs cannot be released safely until GETSEC[WAKEUP] is implemented. */
#define TXT_ERRORCODE_APS_UNSUPPORTED \
    (TXT_ERRORCODE_VALID | TXT_ERRORCODE_TYPE_SINIT | \
     TXT_ERRORCODE_PROGRESS_CODE(0x07))
/*
 * SENTER precondition: the region TXT.SINIT_BASE/SIZE points at does
 * not describe a SINIT ACM for this chipset -- bad ACM header,
 * missing or malformed info table, or a chipset id list that does
 * not cover TXT.DIDVID.  On real hardware the ACM is also
 * cryptographically authenticated; QEMU only checks the structure
 * (see the deviations in docs/specs/intel-txt.rst).
 */
#define TXT_ERRORCODE_ACM_INVALID \
    (TXT_ERRORCODE_VALID | TXT_ERRORCODE_TYPE_SINIT | \
     TXT_ERRORCODE_PROGRESS_CODE(0x06))

/*
 * Placeholder for TXT.PUBLIC_KEY (on real hardware, a hash of
 * Intel's ACM signing public key).  QEMU performs no ACM signature
 * verification, so this is a fixed non-zero marker standing in for
 * "the key the semantic SENTER trusts" (see docs/specs/intel-txt.rst).
 */
#define TXT_PUBLIC_KEY_PLACEHOLDER 0x00545854554d4551ull /* "QEMUTXT" */

/*
 * Placeholder TXT DIDVID: Intel vendor id, Q35 MCH device id,
 * revision 0.  The exact value a TXT-capable chipset reports (and
 * guest SINIT ACMs match against their chipset id lists) is still
 * to be pinned; exposed as a device property for experimentation.
 */
#define INTEL_TXT_DIDVID_DEFAULT \
    ((uint64_t)0x29c0 << 16 | 0x8086)

typedef struct IntelTxtState IntelTxtState;
DECLARE_INSTANCE_CHECKER(IntelTxtState, INTEL_TXT,
                         TYPE_INTEL_TXT)

#ifdef CONFIG_TPM
/*
 * TPM2 hash algorithm tags for the DRTM digests (TCG TPM 2.0
 * Library Specification, Part 2: Structures, Table 22).
 */
#define TPM2_ALG_SHA1   0x0004   /* 20-byte digest */
#define TPM2_ALG_SHA256 0x000b   /* 32-byte digest */

/*
 * One hash-algorithm/digest pair, as passed to
 * intel_txt_drtm_extend_pcr().
 */
typedef struct TPMDigestValue {
    uint16_t alg;        /* TPM2_ALG_SHA1 or TPM2_ALG_SHA256 */
    const uint8_t *digest;
    size_t len;          /* 20 or 32 bytes, matching alg */
} TPMDigestValue;


/*
 * Extend PCR @pcr with the @n digests in @digests at TIS locality
 * 4, standing in for the SINIT ACM (see docs/specs/intel-txt.rst,
 * "Steps performed by QEMU" step d).  Returns 0 on success, -1
 * with @errp set otherwise.
 */
int intel_txt_drtm_extend_pcr(IntelTxtState *s, uint32_t pcr,
                              const TPMDigestValue *digests, size_t n,
                              Error **errp);

/* CPU state handed to the BSP after a successful measured launch. */
typedef struct IntelTxtMleEntry {
    uint32_t entry_phys, ptab;
    uint32_t gdt_base, gdt_limit, seg_sel;
    uint64_t cs_desc, ds_desc;
} IntelTxtMleEntry;

/*
 * Validate and measure the launch, populate the SINIT-MLE heap data,
 * and return true with the BSP entry state on success.  A rejected
 * launch records TXT.ERRORCODE and returns false without transferring.
 */
bool intel_txt_senter(IntelTxtState *s, uint32_t acm_base,
                      uint32_t acm_size, IntelTxtMleEntry *entry);
/* Post-launch SMCTRL; SMI masking is not modeled. */
bool intel_txt_smctrl(IntelTxtState *s, uint32_t control);
/* WAKEUP has no AP work in the supported single-vCPU launch. */
bool intel_txt_wakeup(IntelTxtState *s);
#endif /* CONFIG_TPM */

#endif /* HW_I386_INTEL_TXT_H */
