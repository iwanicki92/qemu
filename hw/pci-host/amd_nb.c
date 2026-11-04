/*
 * AMD northbridge function 0
 *
 * The host bridge function at 00:18.0 of a family 17h or later node,
 * reduced to what the Secure Kernel Loader touches after SKINIT: the
 * identity its node walk reads, and MEMPROT_CR, where clearing bit 0 lifts
 * SL_DEV protection of the Secure Loader Block.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/pci-host/amd_nb.h"
#include "hw/core/qdev-properties.h"
#include "hw/i386/amd_drtm.h"
#include "qemu/module.h"
#include "qemu/range.h"
#include "trace.h"

/*
 * SKL reads the register and writes it back with MEMPROT_EN clear, so the
 * release is any write that leaves the bit clear, not a transition.
 */
static void amd_nb_write_config(PCIDevice *d, uint32_t addr, uint32_t val,
                                int len)
{
    AmdDrtmPlatform *p;
    uint32_t memprot;

    pci_default_write_config(d, addr, val, len);

    if (!ranges_overlap(addr, len, AMD_NB_MEMPROT_CR, 4)) {
        return;
    }
    memprot = pci_get_long(d->config + AMD_NB_MEMPROT_CR);
    p = amd_drtm_platform_find();
    trace_amd_nb_memprot_write(memprot, p != NULL);
    if (p && !(memprot & AMD_NB_MEMPROT_EN)) {
        amd_drtm_sl_dev_release(p);
    }
}

static void amd_nb_reset(DeviceState *dev)
{
    PCIDevice *d = PCI_DEVICE(dev);

    pci_set_long(d->config + AMD_NB_MEMPROT_CR, 0);
}

static void amd_nb_realize(PCIDevice *d, Error **errp)
{
    AmdNbState *s = AMD_NB(d);

    pci_set_word(d->config + PCI_DEVICE_ID, s->device_id);
    /* Bit 0 is all SKL writes. The other bits read zero and stay so. */
    pci_set_long(d->wmask + AMD_NB_MEMPROT_CR, AMD_NB_MEMPROT_EN);
}

/* Node 0's slot unless addr says otherwise, so SKL's walk starts here. */
static void amd_nb_init(Object *obj)
{
    PCI_DEVICE(obj)->devfn = AMD_NB_DEVFN;
}

static const Property amd_nb_properties[] = {
    DEFINE_PROP_UINT16("device-id", AmdNbState, device_id, AMD_NB_DEFAULT_ID),
};

static void amd_nb_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = amd_nb_realize;
    k->config_write = amd_nb_write_config;
    k->vendor_id = PCI_VENDOR_ID_AMD;
    k->device_id = AMD_NB_DEFAULT_ID;
    k->class_id = PCI_CLASS_BRIDGE_HOST;
    dc->desc = "AMD northbridge function 0 (MEMPROT_CR only), at 00:18.0";
    device_class_set_legacy_reset(dc, amd_nb_reset);
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    device_class_set_props(dc, amd_nb_properties);
}

static const TypeInfo amd_nb_info = {
    .name          = TYPE_AMD_NB,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(AmdNbState),
    .instance_init = amd_nb_init,
    .class_init    = amd_nb_class_init,
    /*
     * MEMPROT_CR sits beyond the 256 bytes of conventional configuration
     * space, and only an Express function gets 4 KiB of it here.
     */
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void amd_nb_register_types(void)
{
    type_register_static(&amd_nb_info);
}

type_init(amd_nb_register_types)
