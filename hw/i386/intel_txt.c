/*
 * QEMU Intel TXT (Trusted Execution Technology) chipset device
 *
 * Emulates the TXT public and private configuration spaces at
 * 0xFED30000 / 0xFED20000 on the q35 machine ("-machine txt=on").
 *
 * This is the M1 skeleton: register storage, defaults, command
 * register semantics and write-once DPR locking.  The measured
 * launch flow (GETSEC[SENTER] standing in for the SINIT ACM) is a
 * later milestone.  See docs/specs/intel-txt.rst for the register
 * map and the overall design.
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
#include "system/runstate.h"
#include "trace.h"

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
