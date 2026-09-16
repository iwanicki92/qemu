/*
 * AMD Secure Processor
 *
 * So far only the identity: a PCI function answering with an AMD Secure
 * Processor's vendor and device ID, with no BARs and no mailbox. Enough for
 * software that looks for a PSP in configuration space, not for anything
 * that talks to one.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/pci/pci_device.h"
#include "hw/core/qdev-properties.h"
#include "qemu/module.h"
#include "qom/object.h"

#define TYPE_AMD_PSP "amd-psp"
OBJECT_DECLARE_SIMPLE_TYPE(AmdPspState, AMD_PSP)

/* The Turin generation's CCP/ASP. */
#define AMD_PSP_DEFAULT_ID 0x156e

struct AmdPspState {
    PCIDevice parent_obj;
    uint16_t device_id;
};

static void amd_psp_realize(PCIDevice *pci_dev, Error **errp)
{
    AmdPspState *s = AMD_PSP(pci_dev);

    pci_set_word(pci_dev->config + PCI_DEVICE_ID, s->device_id);
}

static const Property amd_psp_properties[] = {
    DEFINE_PROP_UINT16("device-id", AmdPspState, device_id,
                       AMD_PSP_DEFAULT_ID),
};

static void amd_psp_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = amd_psp_realize;
    k->vendor_id = PCI_VENDOR_ID_AMD;
    k->device_id = AMD_PSP_DEFAULT_ID;
    k->class_id = PCI_CLASS_CRYPT_OTHER;
    dc->desc = "AMD Secure Processor (identity only, no mailbox)";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, amd_psp_properties);
}

static const TypeInfo amd_psp_info = {
    .name          = TYPE_AMD_PSP,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(AmdPspState),
    .class_init    = amd_psp_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void amd_psp_register_types(void)
{
    type_register_static(&amd_psp_info);
}

type_init(amd_psp_register_types)
