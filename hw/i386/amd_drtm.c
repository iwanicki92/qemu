/*
 * AMD dynamic launch platform state
 *
 * One record of a SKINIT launch, so the CPU, the APIC path, the northbridge
 * stub and the IOMMU share it instead of reaching into each other.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/i386/amd_drtm.h"
#include "qapi/error.h"
#include "qemu/module.h"

AmdDrtmPlatform *amd_drtm_platform_find(void)
{
    Object *obj = object_resolve_path_type("", TYPE_AMD_DRTM_PLATFORM, NULL);

    return obj ? AMD_DRTM_PLATFORM(obj) : NULL;
}

void amd_drtm_launch(AmdDrtmPlatform *p, hwaddr base, uint16_t length)
{
    p->launched = true;
    p->slb_base = base;
    p->slb_length = length;
    p->sl_dev = true;
}

bool amd_drtm_launched(AmdDrtmPlatform *p)
{
    return p->launched;
}

void amd_drtm_sl_dev_release(AmdDrtmPlatform *p)
{
    p->sl_dev = false;
}

void amd_drtm_block_dma(AmdDrtmPlatform *p, hwaddr base, uint64_t len,
                        const char *name)
{
}

void amd_drtm_unblock_dma(AmdDrtmPlatform *p, const char *name)
{
}

static void amd_drtm_platform_realize(DeviceState *dev, Error **errp)
{
    bool ambiguous;

    object_resolve_path_type("", TYPE_AMD_DRTM_PLATFORM, &ambiguous);
    if (ambiguous) {
        error_setg(errp, "at most one %s is permitted", TYPE_AMD_DRTM_PLATFORM);
    }
}

static void amd_drtm_platform_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = amd_drtm_platform_realize;
    dc->desc = "AMD dynamic launch platform state";
    dc->user_creatable = true;
    dc->hotpluggable = false;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo amd_drtm_platform_info = {
    .name          = TYPE_AMD_DRTM_PLATFORM,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AmdDrtmPlatform),
    .class_init    = amd_drtm_platform_class_init,
};

static void amd_drtm_register_types(void)
{
    type_register_static(&amd_drtm_platform_info);
}

type_init(amd_drtm_register_types)
