/*
 * AMD dynamic launch platform state
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_I386_AMD_DRTM_H
#define HW_I386_AMD_DRTM_H

#include "hw/core/sysbus.h"
#include "qapi/qapi-types-misc-i386.h"
#include "qemu/queue.h"
#include "qemu/rcu.h"
#include "qom/object.h"
#include "system/memory.h"

#define TYPE_AMD_DRTM_PLATFORM "amd-drtm-platform"
OBJECT_DECLARE_SIMPLE_TYPE(AmdDrtmPlatform, AMD_DRTM_PLATFORM)

typedef struct TPMIf TPMIf;

/* The block SKINIT places over the whole SLB, and its size. */
#define AMD_DRTM_SL_DEV_BLOCK "sl_dev"
#define AMD_DRTM_SLB_SIZE 0x10000

/*
 * One named range that device DMA is kept out of. The region answers every
 * access with a decode error, and sits in the IOMMU's view when there is
 * one. With @fetch an alias of it sits in the view of the IOMMU's own
 * accesses too. Freed after a grace period, as a stale flat view may
 * still name it.
 */
typedef struct AmdDrtmBlock {
    char *name;
    hwaddr base;
    uint64_t len;
    MemoryRegion mr;
    MemoryRegion fetch_mr;
    bool fetch;
    bool enforced;
    QLIST_ENTRY(AmdDrtmBlock) next;
    struct rcu_head rcu;
} AmdDrtmBlock;

/*
 * The one record of a launch, shared by the CPU, the APIC path, the
 * northbridge stub and the IOMMU. Found by type, so at most one exists.
 */
struct AmdDrtmPlatform {
    SysBusDevice parent_obj;

    bool launched;
    hwaddr slb_base;
    uint16_t slb_length;
    bool sl_dev;
    AmdDrtmHashResult hash;
    QLIST_HEAD(, AmdDrtmBlock) blocks;

    bool strict;
    TPMIf *tpm;
    DeviceState *iommu;
};

/* NULL unless exactly one platform object exists. */
AmdDrtmPlatform *amd_drtm_platform_find(void);

/*
 * A rule of the launch the guest broke, one hardware would let through.
 * Logged as a guest error, and with strict=on the VM stops on it.
 */
void amd_drtm_guest_error(AmdDrtmPlatform *p, const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

/*
 * Record the SLB SKINIT is entering and measure it into PCR 17. The CPU
 * calls it after the core reset, with the image already in guest memory.
 */
void amd_drtm_launch(AmdDrtmPlatform *p, hwaddr base, uint16_t length);

bool amd_drtm_launched(AmdDrtmPlatform *p);

/* The northbridge saw the release bit of MEMPROT_CR written. */
void amd_drtm_sl_dev_release(AmdDrtmPlatform *p);

/*
 * The one seam for every DMA protection the AMD path has: SL_DEV, the
 * IOMMU exclusion range, a PSP TMR. A name identifies each block. @fetch
 * says whether it also stops the IOMMU's own table, command and log
 * accesses, as SL_DEV does and a TMR does not. Enforced through amd-iommu
 * when the machine has one, recorded otherwise.
 */
void amd_drtm_block_dma(AmdDrtmPlatform *p, hwaddr base, uint64_t len,
                        const char *name, bool fetch);
void amd_drtm_unblock_dma(AmdDrtmPlatform *p, const char *name);

#endif
