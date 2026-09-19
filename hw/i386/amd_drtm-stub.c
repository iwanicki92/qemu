/*
 * Stubs for the AMD dynamic launch platform state
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/i386/amd_drtm.h"

AmdDrtmPlatform *amd_drtm_platform_find(void)
{
    return NULL;
}

void amd_drtm_launch(AmdDrtmPlatform *p, hwaddr base, uint16_t length)
{
}

bool amd_drtm_launched(AmdDrtmPlatform *p)
{
    return false;
}

void amd_drtm_sl_dev_release(AmdDrtmPlatform *p)
{
}

void amd_drtm_block_dma(AmdDrtmPlatform *p, hwaddr base, uint64_t len,
                        const char *name)
{
}

void amd_drtm_unblock_dma(AmdDrtmPlatform *p, const char *name)
{
}
