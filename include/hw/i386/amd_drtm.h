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
#include "qom/object.h"

#define TYPE_AMD_DRTM_PLATFORM "amd-drtm-platform"
OBJECT_DECLARE_SIMPLE_TYPE(AmdDrtmPlatform, AMD_DRTM_PLATFORM)

typedef struct TPMIf TPMIf;

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

    TPMIf *tpm;
    DeviceState *iommu;
};

/* NULL unless exactly one platform object exists. */
AmdDrtmPlatform *amd_drtm_platform_find(void);

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
 * IOMMU exclusion range, later a PSP TMR. A name identifies each block.
 */
void amd_drtm_block_dma(AmdDrtmPlatform *p, hwaddr base, uint64_t len,
                        const char *name);
void amd_drtm_unblock_dma(AmdDrtmPlatform *p, const char *name);

#endif
