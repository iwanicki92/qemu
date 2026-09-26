/*
 * AMD Secure Processor
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_MISC_AMD_PSP_H
#define HW_MISC_AMD_PSP_H

#include "hw/pci/pci_device.h"
#include "qapi/qapi-types-misc-i386.h"
#include "qemu/timer.h"
#include "qom/object.h"

#define TYPE_AMD_PSP "amd-psp"
OBJECT_DECLARE_SIMPLE_TYPE(AmdPspState, AMD_PSP)

/* The Turin generation's CCP/ASP. */
#define AMD_PSP_DEFAULT_ID 0x156e

/*
 * The register block. Turin firmware puts it on BAR 2 at 0xcc200000 with the
 * next BAR a megabyte above, so a megabyte is the size. Older parts differ:
 * an AMD OSRR names BAR 3 of NBIF0 function 2.
 */
#define AMD_PSP_BAR_INDEX 2
#define AMD_PSP_BAR_SIZE 0x100000

/*
 * The C2PMSG mailboxes, four bytes each from this offset. 58453 appendix
 * G.2 puts C2PMSG_72 at 0x10A20 on Milan and Genoa, which is this base.
 */
#define AMD_PSP_C2PMSG_BASE 0x10900
#define AMD_PSP_C2PMSG_COUNT 128

/*
 * The ASP feature register, which Linux reads at 0x109fc, and the DRTM
 * service's command and response register (_58453, section 3.1_).
 */
#define AMD_PSP_C2PMSG_FEATURE 63
#define AMD_PSP_C2PMSG_DRTM 72

/* The argument and result registers of the DRTM service (58453, 3.1). */
#define AMD_PSP_C2PMSG_DRTM_ARG0 93
#define AMD_PSP_C2PMSG_DRTM_ARG1 94
#define AMD_PSP_C2PMSG_DRTM_ARG2 95

/*
 * C2PMSG_72: bit 31 the ready bit, which the service sets when a command
 * is done and x86 clears to issue one, 27:24 the TMR index, 23:16 the
 * command and 15:0 the status.
 */
#define AMD_PSP_DRTM_READY (1u << 31)
#define AMD_PSP_DRTM_TMR_INDEX_SHIFT 24
#define AMD_PSP_DRTM_TMR_INDEX_MASK 0xf
#define AMD_PSP_DRTM_CMD_SHIFT 16
#define AMD_PSP_DRTM_CMD_MASK 0xff
#define AMD_PSP_DRTM_STATUS_MASK 0xffff

#define AMD_PSP_DRTM_CMD(cmd, index) \
    (((cmd) << AMD_PSP_DRTM_CMD_SHIFT) | \
     ((index) << AMD_PSP_DRTM_TMR_INDEX_SHIFT))

enum {
    AMD_PSP_DRTM_CMD_GET_CAPABILITY = 0x1,
    AMD_PSP_DRTM_CMD_TMR_SETUP = 0x2,
    AMD_PSP_DRTM_CMD_TMR_RELEASE = 0x3,
    AMD_PSP_DRTM_CMD_LAUNCH = 0x4,
    AMD_PSP_DRTM_CMD_GET_TCG_LOGS = 0x7,
    AMD_PSP_DRTM_CMD_TPM_LOCALITY_ACCESS = 0x8,
    AMD_PSP_DRTM_CMD_GET_TMR_DESCRIPTORS = 0x9,
    AMD_PSP_DRTM_CMD_ALLOCATE_SHARED_MEMORY = 0xa,
    AMD_PSP_DRTM_CMD_EXTEND_OSSL_DIGEST = 0xb,
    AMD_PSP_DRTM_CMD_GET_IVRS_TABLE_INFO = 0xc,
};

enum {
    AMD_PSP_DRTM_NO_ERROR = 0x0,
    AMD_PSP_DRTM_NOT_SUPPORTED = 0x1,
    AMD_PSP_DRTM_LAUNCH_ERROR = 0x2,
    AMD_PSP_DRTM_TMR_SETUP_FAILED_ERROR = 0x3,
    AMD_PSP_DRTM_TMR_DESTROY_FAILED_ERROR = 0x4,
    AMD_PSP_DRTM_GET_TCG_LOGS_FAILED_ERROR = 0x7,
    AMD_PSP_DRTM_OUT_OF_RESOURCES_ERROR = 0x8,
    AMD_PSP_DRTM_GENERIC_ERROR = 0x9,
    AMD_PSP_DRTM_INVALID_SERVICE_ID_ERROR = 0xa,
    AMD_PSP_DRTM_MEMORY_UNALIGNED_ERROR = 0xb,
    AMD_PSP_DRTM_MINIMUM_SIZE_ERROR = 0xc,
    AMD_PSP_DRTM_GET_TMR_DESCRIPTOR_FAILED = 0xd,
    AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED = 0xe,
    AMD_PSP_DRTM_TMR_SETUP_NOT_ALLOWED = 0xf,
    AMD_PSP_DRTM_GET_IVRS_TABLE_FAILED = 0x10,
};

/*
 * The event log GET_TCG_LOGS hands out: a TCG2 log in a region of the
 * device's own, with the event types the board's log showed.
 */
#define AMD_PSP_TCG_LOG_BASE        0xfedb0000ULL
#define AMD_PSP_TCG_LOG_SIZE        0x1000
#define AMD_PSP_EV_SL_IMAGE         0x8001
#define AMD_PSP_EV_SPLT_VERSION     0x8002
#define AMD_PSP_EV_FUSE_STATE       0x8003
#define AMD_PSP_EV_KEY_TOKEN        0x8004
#define AMD_PSP_EV_SEC_PATCH_LEVEL  0x8005
#define AMD_PSP_EV_OS_SL_LOAD       0x8006
#define AMD_PSP_EV_AMD_SL_SEPARATOR 0x8007

/*
 * The regions the other post-launch commands answer with, beside the log:
 * a copy of the IVRS, the TMR descriptors, and the buffer
 * ALLOCATE_SHARED_MEMORY grants, the only one the guest may write.
 */
#define AMD_PSP_IVRS_BASE           0xfedb1000ULL
#define AMD_PSP_IVRS_SIZE           0x1000
#define AMD_PSP_TMR_DESC_BASE       0xfedb2000ULL
#define AMD_PSP_TMR_DESC_SIZE       0x1000
#define AMD_PSP_TMR_DESC_LEN        12
#define AMD_PSP_SHARED_BASE         0xfedc0000ULL
#define AMD_PSP_SHARED_SIZE         0x10000

/* The MLE EXTEND_OSSL_DIGEST takes: this aligned, at most this long */
#define AMD_PSP_MLE_ALIGN           0x4000000ULL

/* GET_CAPABILITY: C2PMSG_93 flags, _94 the version, _95 alignment and count */
#define AMD_PSP_DRTM_CAP_ENABLED (1u << 0)
#define AMD_PSP_DRTM_CAP_TSME (1u << 1)
#define AMD_PSP_DRTM_CAP_ANTI_ROLLBACK (1u << 2)
#define AMD_PSP_DRTM_VERSION 1
#define AMD_PSP_DRTM_CAP_TMR_COUNT_SHIFT 24
#define AMD_PSP_DRTM_CAP_TMR_ALIGNMENT_MASK 0xffffff

/* The SLB the launch checks is 64 KiB, as SKINIT defines it */
#define AMD_PSP_SLB_SIZE 0x10000

/* A TMR's size comes in these units, up to this many TMRs exist */
#define AMD_PSP_DRTM_TMR_UNIT 0x10000
#define AMD_PSP_DRTM_TMR_MAX 8

/*
 * The window the ASPT declares, which is the register block seen from
 * 0x10000 in. It is outside PCI enumeration on hardware, so it sits here
 * beside the address amd-iommu uses rather than in the PCI hole, where a
 * BAR assignment could land on it.
 */
#define AMD_PSP_ASPT_BASE 0xfeda0000ULL
#define AMD_PSP_ASPT_WINDOW 0x10000
#define AMD_PSP_ASPT_SIZE 0x1000

typedef struct TPMIf TPMIf;

typedef struct AmdPspTmr {
    bool set;
    uint64_t base;
    uint64_t len;
} AmdPspTmr;

typedef struct AmdDrtmPlatform AmdDrtmPlatform;

struct AmdPspState {
    PCIDevice parent_obj;

    uint16_t device_id;
    bool drtm_ready;
    bool aspt;
    bool drtm_device;

    /* The DRTM service and its knobs */
    bool drtm_service;
    uint8_t tmr_count;
    uint32_t tmr_alignment;
    uint32_t splt_version;
    bool verify;
    uint32_t command_delay;
    uint8_t delayed_command;
    bool locality_locks;
    uint32_t min_spl;

    MemoryRegion mmio;
    MemoryRegion window;
    uint32_t c2pmsg[AMD_PSP_C2PMSG_COUNT];

    /*
     * The service's state. A command runs in a bottom half after the write
     * that issued it, and the status is published when the delay timer
     * fires, or at once without a delay.
     */
    AmdDrtmPlatform *platform;
    TPMIf *tpm;
    uint64_t tcg_log_base;
    MemoryRegion tcg_log;
    uint32_t tcg_log_len;
    bool tcg_log_full;
    uint64_t ivrs_base;
    MemoryRegion ivrs_mr;
    uint64_t tmr_desc_base;
    MemoryRegion tmr_desc;
    uint64_t shared_base;
    MemoryRegion shared;
    /* The IVRS the machine's ACPI carries, NULL when it has none */
    GByteArray *ivrs;
    bool kicked;
    bool busy;
    uint8_t command;
    uint16_t status;
    AmdPspLaunchState launch;
    AmdPspSignatureResult signature;
    uint8_t locks;
    AmdPspTmr tmr[AMD_PSP_DRTM_TMR_MAX];
    QEMUBH *bh;
    QEMUTimer *delay_timer;
};

/*
 * The IVRS the BIOS would hand the PSP: ACPI building passes the table it
 * makes, or @len 0 when it makes none. The checksum is the firmware's to
 * fill in, so the copy gets the one the guest's table will carry.
 */
static inline void amd_psp_set_ivrs(AmdPspState *s, const void *table,
                                    size_t len)
{
    uint8_t sum = 0;
    size_t i;

    if (s->ivrs) {
        g_byte_array_unref(s->ivrs);
        s->ivrs = NULL;
    }
    if (!len) {
        return;
    }
    s->ivrs = g_byte_array_sized_new(len);
    g_byte_array_append(s->ivrs, table, len);
    s->ivrs->data[9] = 0;
    for (i = 0; i < len; i++) {
        sum += s->ivrs->data[i];
    }
    s->ivrs->data[9] = -sum;
}

#endif
