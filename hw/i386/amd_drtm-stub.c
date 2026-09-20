/*
 * Stubs for the AMD dynamic launch platform state
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/i386/amd_drtm.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-i386.h"
#include "qemu/log.h"

AmdDrtmPlatform *amd_drtm_platform_find(void)
{
    return NULL;
}

void amd_drtm_guest_error(AmdDrtmPlatform *p, const char *fmt, ...)
{
    g_autofree char *rule = NULL;
    va_list ap;

    va_start(ap, fmt);
    rule = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    qemu_log_mask(LOG_GUEST_ERROR, "%s\n", rule);
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

AmdDrtmInfo *qmp_query_amd_drtm(Error **errp)
{
    error_setg(errp, "%s is not built in", TYPE_AMD_DRTM_PLATFORM);
    return NULL;
}

void qmp_x_amd_drtm_launch(uint64_t base, uint16_t length, Error **errp)
{
    error_setg(errp, "%s is not built in", TYPE_AMD_DRTM_PLATFORM);
}
