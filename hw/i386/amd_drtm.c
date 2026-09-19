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
#include "amd_iommu.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-i386.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "system/address-spaces.h"
#include "system/tpm.h"
#include "trace.h"

AmdDrtmPlatform *amd_drtm_platform_find(void)
{
    Object *obj = object_resolve_path_type("", TYPE_AMD_DRTM_PLATFORM, NULL);

    return obj ? AMD_DRTM_PLATFORM(obj) : NULL;
}

/*
 * The locality 4 transfer: the first slb_length bytes of the SLB, read after
 * the core reset so the image measured is the one entered. The TPM is looked
 * up here rather than at realize because it may be created after this device.
 */
static void amd_drtm_hash(AmdDrtmPlatform *p)
{
    g_autofree uint8_t *image = g_malloc(p->slb_length);
    MemTxResult res;
    int ret;

    p->tpm = tpm_find();
    if (!p->tpm) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "amd-drtm: SKINIT with no TPM to measure the SLB at 0x%"
                      HWADDR_PRIx ", PCR 17 stays unmeasured\n", p->slb_base);
        p->hash = AMD_DRTM_HASH_RESULT_UNSUPPORTED;
        goto out;
    }

    res = address_space_read(&address_space_memory, p->slb_base,
                             MEMTXATTRS_UNSPECIFIED, image, p->slb_length);
    if (res != MEMTX_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "amd-drtm: SLB at 0x%" HWADDR_PRIx " length %u is not "
                      "readable memory, PCR 17 stays unmeasured\n",
                      p->slb_base, p->slb_length);
        p->hash = AMD_DRTM_HASH_RESULT_FAILED;
        goto out;
    }

    ret = tpm_hash_image(p->tpm, image, p->slb_length);
    if (ret == 0) {
        p->hash = AMD_DRTM_HASH_RESULT_OK;
    } else if (ret == -ENOTSUP) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "amd-drtm: the TPM has no locality 4 path (tpm-tis on a "
                      "swtpm with hashing is needed), PCR 17 stays "
                      "unmeasured\n");
        p->hash = AMD_DRTM_HASH_RESULT_UNSUPPORTED;
    } else {
        warn_report("amd-drtm: TPM hash of the SLB failed: %s",
                    strerror(-ret));
        p->hash = AMD_DRTM_HASH_RESULT_FAILED;
    }

out:
    trace_amd_drtm_hash(p->slb_base, p->slb_length,
                        AmdDrtmHashResult_str(p->hash));
}

void amd_drtm_launch(AmdDrtmPlatform *p, hwaddr base, uint16_t length)
{
    trace_amd_drtm_launch(base, length);
    p->launched = true;
    p->slb_base = base;
    p->slb_length = length;
    p->sl_dev = true;
    amd_drtm_block_dma(p, base, AMD_DRTM_SLB_SIZE, AMD_DRTM_SL_DEV_BLOCK);
    amd_drtm_hash(p);
}

bool amd_drtm_launched(AmdDrtmPlatform *p)
{
    return p->launched;
}

void amd_drtm_sl_dev_release(AmdDrtmPlatform *p)
{
    trace_amd_drtm_sl_dev_release(p->launched, p->sl_dev);
    if (!p->launched) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "amd-drtm: SL_DEV released with no launch active\n");
    }
    p->sl_dev = false;
    amd_drtm_unblock_dma(p, AMD_DRTM_SL_DEV_BLOCK);
}

static AmdDrtmBlock *amd_drtm_find_block(AmdDrtmPlatform *p, const char *name)
{
    AmdDrtmBlock *b;

    QLIST_FOREACH(b, &p->blocks, next) {
        if (!strcmp(b->name, name)) {
            return b;
        }
    }
    return NULL;
}

/* Recorded only. Nothing keeps DMA out of the range yet. */
void amd_drtm_block_dma(AmdDrtmPlatform *p, hwaddr base, uint64_t len,
                        const char *name)
{
    AmdDrtmBlock *b = amd_drtm_find_block(p, name);

    trace_amd_drtm_block_dma(name, base, len);
    if (!b) {
        b = g_new0(AmdDrtmBlock, 1);
        b->name = g_strdup(name);
        QLIST_INSERT_HEAD(&p->blocks, b, next);
    }
    b->base = base;
    b->len = len;
}

void amd_drtm_unblock_dma(AmdDrtmPlatform *p, const char *name)
{
    AmdDrtmBlock *b = amd_drtm_find_block(p, name);

    trace_amd_drtm_unblock_dma(name, b != NULL);
    if (b) {
        QLIST_REMOVE(b, next);
        g_free(b->name);
        g_free(b);
    }
}

static void amd_drtm_clear_blocks(AmdDrtmPlatform *p)
{
    while (!QLIST_EMPTY(&p->blocks)) {
        amd_drtm_unblock_dma(p, QLIST_FIRST(&p->blocks)->name);
    }
}

AmdDrtmInfo *qmp_query_amd_drtm(Error **errp)
{
    AmdDrtmPlatform *p = amd_drtm_platform_find();
    AmdDrtmDmaBlockList **tail;
    AmdDrtmInfo *info;
    AmdDrtmBlock *b;

    if (!p) {
        error_setg(errp, "no %s device", TYPE_AMD_DRTM_PLATFORM);
        return NULL;
    }
    info = g_new0(AmdDrtmInfo, 1);
    info->launched = p->launched;
    info->slb_base = p->slb_base;
    info->slb_length = p->slb_length;
    info->sl_dev = p->sl_dev;
    info->hash = p->hash;
    tail = &info->dma_blocks;
    QLIST_FOREACH(b, &p->blocks, next) {
        AmdDrtmDmaBlock *block = g_new0(AmdDrtmDmaBlock, 1);

        block->name = g_strdup(b->name);
        block->base = b->base;
        block->len = b->len;
        QAPI_LIST_APPEND(tail, block);
    }
    return info;
}

void qmp_x_amd_drtm_launch(uint64_t base, uint16_t length, Error **errp)
{
    AmdDrtmPlatform *p = amd_drtm_platform_find();

    if (!p) {
        error_setg(errp, "no %s device", TYPE_AMD_DRTM_PLATFORM);
        return;
    }
    amd_drtm_launch(p, base, length);
}

static void amd_drtm_platform_realize(DeviceState *dev, Error **errp)
{
    bool ambiguous;

    object_resolve_path_type("", TYPE_AMD_DRTM_PLATFORM, &ambiguous);
    if (ambiguous) {
        error_setg(errp, "at most one %s is permitted", TYPE_AMD_DRTM_PLATFORM);
    }
}

/* Everything a launch left behind goes. The links to other devices stay. */
static void amd_drtm_platform_reset_hold(Object *obj, ResetType type)
{
    AmdDrtmPlatform *p = AMD_DRTM_PLATFORM(obj);

    p->launched = false;
    p->slb_base = 0;
    p->slb_length = 0;
    p->sl_dev = false;
    p->hash = AMD_DRTM_HASH_RESULT_NONE;
    amd_drtm_clear_blocks(p);
}

static const VMStateDescription vmstate_amd_drtm_platform = {
    .name = TYPE_AMD_DRTM_PLATFORM,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(launched, AmdDrtmPlatform),
        VMSTATE_UINT64(slb_base, AmdDrtmPlatform),
        VMSTATE_UINT16(slb_length, AmdDrtmPlatform),
        VMSTATE_BOOL(sl_dev, AmdDrtmPlatform),
        VMSTATE_END_OF_LIST()
    }
};

static const Property amd_drtm_platform_properties[] = {
    /* Where SL_DEV and the TMR will be enforced. Nothing reads it yet. */
    DEFINE_PROP_LINK("iommu", AmdDrtmPlatform, iommu, TYPE_AMD_IOMMU_DEVICE,
                     DeviceState *),
};

static void amd_drtm_platform_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize = amd_drtm_platform_realize;
    dc->vmsd = &vmstate_amd_drtm_platform;
    dc->desc = "AMD dynamic launch platform state";
    dc->user_creatable = true;
    dc->hotpluggable = false;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, amd_drtm_platform_properties);
    rc->phases.hold = amd_drtm_platform_reset_hold;
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
