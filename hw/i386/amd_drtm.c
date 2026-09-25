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
#include "hw/core/cpu.h"
#include "target/i386/cpu.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-i386.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "system/address-spaces.h"
#include "system/runstate.h"
#include "system/tpm.h"
#include "trace.h"

AmdDrtmPlatform *amd_drtm_platform_find(void)
{
    Object *obj = object_resolve_path_type("", TYPE_AMD_DRTM_PLATFORM, NULL);

    return obj ? AMD_DRTM_PLATFORM(obj) : NULL;
}

void amd_drtm_guest_error(AmdDrtmPlatform *p, const char *fmt, ...)
{
    g_autofree char *rule = NULL;
    bool strict = p && p->strict;
    va_list ap;

    va_start(ap, fmt);
    rule = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    qemu_log_mask(LOG_GUEST_ERROR, "%s\n", rule);
    trace_amd_drtm_guest_error(rule, strict);

    if (strict) {
        GuestPanicInformation *info = g_new0(GuestPanicInformation, 1);
        bool locked = bql_locked();

        info->type = GUEST_PANIC_INFORMATION_TYPE_AMD_DRTM;
        info->u.amd_drtm.rule = g_steal_pointer(&rule);
        /* The CPU's own rule checks arrive without the lock */
        if (!locked) {
            bql_lock();
        }
        qemu_system_guest_panicked(info);
        if (!locked) {
            bql_unlock();
        }
    }
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
        amd_drtm_guest_error(p, "amd-drtm: SKINIT with no TPM to measure the "
                             "SLB at 0x%" HWADDR_PRIx ", PCR 17 stays "
                             "unmeasured", p->slb_base);
        p->hash = AMD_DRTM_HASH_RESULT_UNSUPPORTED;
        goto out;
    }

    res = address_space_read(&address_space_memory, p->slb_base,
                             MEMTXATTRS_UNSPECIFIED, image, p->slb_length);
    if (res != MEMTX_OK) {
        amd_drtm_guest_error(p, "amd-drtm: SLB at 0x%" HWADDR_PRIx " length "
                             "%u is not readable memory, PCR 17 stays "
                             "unmeasured", p->slb_base, p->slb_length);
        p->hash = AMD_DRTM_HASH_RESULT_FAILED;
        goto out;
    }

    ret = tpm_hash_image(p->tpm, image, p->slb_length);
    if (ret == 0) {
        p->hash = AMD_DRTM_HASH_RESULT_OK;
    } else if (ret == -ENOTSUP) {
        amd_drtm_guest_error(p, "amd-drtm: the TPM has no locality 4 path "
                             "(tpm-tis on a swtpm with hashing is needed), "
                             "PCR 17 stays unmeasured");
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
    amd_drtm_block_dma(p, base, AMD_DRTM_SLB_SIZE, AMD_DRTM_SL_DEV_BLOCK,
                       true);
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
        amd_drtm_guest_error(p, "amd-drtm: SL_DEV released with no launch "
                             "active");
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

/* The link property when set, else the one amd-iommu the machine has */
static AMDVIState *amd_drtm_iommu(AmdDrtmPlatform *p)
{
    Object *obj = OBJECT(p->iommu);
    bool ambiguous;

    if (!obj) {
        obj = object_resolve_path_type("", TYPE_AMD_IOMMU_DEVICE, &ambiguous);
        if (ambiguous) {
            obj = NULL;
        }
    }
    return obj ? AMD_IOMMU_DEVICE(obj) : NULL;
}

/* What a device gets from a blocked range: a target abort, no data */
static MemTxResult amd_drtm_block_read(void *opaque, hwaddr addr,
                                       uint64_t *data, unsigned size,
                                       MemTxAttrs attrs)
{
    AmdDrtmBlock *b = opaque;

    trace_amd_drtm_dma_blocked(b->name, b->base + addr, size, false);
    *data = 0;
    return MEMTX_DECODE_ERROR;
}

static MemTxResult amd_drtm_block_write(void *opaque, hwaddr addr,
                                        uint64_t data, unsigned size,
                                        MemTxAttrs attrs)
{
    AmdDrtmBlock *b = opaque;

    trace_amd_drtm_dma_blocked(b->name, b->base + addr, size, true);
    return MEMTX_DECODE_ERROR;
}

static const MemoryRegionOps amd_drtm_block_ops = {
    .read_with_attrs = amd_drtm_block_read,
    .write_with_attrs = amd_drtm_block_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

static void amd_drtm_free_block(struct rcu_head *rcu)
{
    AmdDrtmBlock *b = container_of(rcu, AmdDrtmBlock, rcu);

    g_free(b->name);
    g_free(b);
}

void amd_drtm_block_dma(AmdDrtmPlatform *p, hwaddr base, uint64_t len,
                        const char *name, bool fetch)
{
    AMDVIState *iommu = amd_drtm_iommu(p);
    AmdDrtmBlock *b;

    /* A block placed again moves, so the old region goes first */
    amd_drtm_unblock_dma(p, name);

    b = g_new0(AmdDrtmBlock, 1);
    b->name = g_strdup(name);
    b->base = base;
    b->len = len;
    b->fetch = fetch;
    memory_region_init_io(&b->mr, OBJECT(p), &amd_drtm_block_ops, b, name,
                          len);
    if (fetch) {
        g_autofree char *fetch_name = g_strdup_printf("%s-fetch", name);

        memory_region_init_alias(&b->fetch_mr, OBJECT(p), fetch_name, &b->mr,
                                 0, len);
    }
    if (iommu) {
        amdvi_add_dma_block(iommu, &b->mr, fetch ? &b->fetch_mr : NULL, base);
        b->enforced = true;
    }
    QLIST_INSERT_HEAD(&p->blocks, b, next);
    trace_amd_drtm_block_dma(name, base, len, fetch, b->enforced);
}

void amd_drtm_unblock_dma(AmdDrtmPlatform *p, const char *name)
{
    AmdDrtmBlock *b = amd_drtm_find_block(p, name);

    trace_amd_drtm_unblock_dma(name, b != NULL);
    if (!b) {
        return;
    }
    if (b->enforced) {
        amdvi_del_dma_block(amd_drtm_iommu(p), &b->mr,
                            b->fetch ? &b->fetch_mr : NULL);
    }
    if (b->fetch) {
        object_unparent(OBJECT(&b->fetch_mr));
    }
    object_unparent(OBJECT(&b->mr));
    QLIST_REMOVE(b, next);
    call_rcu1(&b->rcu, amd_drtm_free_block);
}

uint32_t amd_drtm_cpu_signature(void)
{
    return X86_CPU(first_cpu)->env.cpuid_version;
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
        block->enforced = b->enforced;
        QAPI_LIST_APPEND(tail, block);
    }
    if (p->psp_query) {
        info->psp = p->psp_query(p->psp);
    }
    return info;
}

void amd_drtm_set_psp(AmdDrtmPlatform *p, AmdPspDrtmInfo *(*query)(void *),
                      void *psp)
{
    p->psp_query = query;
    p->psp = psp;
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

/* The DMA blocks live in the IOMMU's views, which a migration does not carry */
static const VMStateDescription vmstate_amd_drtm_platform = {
    .name = TYPE_AMD_DRTM_PLATFORM,
    .unmigratable = 1,
};

static const Property amd_drtm_platform_properties[] = {
    /* The IOMMU that enforces the blocks. Found by type when unset. */
    DEFINE_PROP_LINK("iommu", AmdDrtmPlatform, iommu, TYPE_AMD_IOMMU_DEVICE,
                     DeviceState *),
    /* Every guest error the launch logs also stops the VM as a panic */
    DEFINE_PROP_BOOL("strict", AmdDrtmPlatform, strict, false),
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
