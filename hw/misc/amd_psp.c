/*
 * AMD Secure Processor
 *
 * A PCI function answering with an AMD Secure Processor's vendor and device
 * ID, its C2PMSG mailbox registers, and the second window an ASPT declares
 * for them. Reads answer, writes are dropped: the command protocol is a
 * launch, not something software checking a platform does.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/misc/amd_psp.h"
#include "hw/core/qdev-properties.h"
#include "qemu/module.h"
#include "system/address-spaces.h"

static uint64_t amd_psp_read(void *opaque, hwaddr addr, unsigned size)
{
    AmdPspState *s = opaque;
    hwaddr offset = addr - AMD_PSP_C2PMSG_BASE;

    if (addr < AMD_PSP_C2PMSG_BASE || offset >= sizeof(s->c2pmsg)) {
        return 0;
    }
    return s->c2pmsg[offset / sizeof(s->c2pmsg[0])];
}

/*
 * Dropped rather than stored. A write is how x86 issues a command, and
 * answering one would mean implementing the service behind it.
 */
static void amd_psp_write(void *opaque, hwaddr addr, uint64_t value,
                          unsigned size)
{
}

static const MemoryRegionOps amd_psp_mmio_ops = {
    .read = amd_psp_read,
    .write = amd_psp_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void amd_psp_realize(PCIDevice *pci_dev, Error **errp)
{
    AmdPspState *s = AMD_PSP(pci_dev);

    pci_set_word(pci_dev->config + PCI_DEVICE_ID, s->device_id);

    /*
     * Nothing here runs the service, so the register holds the state a
     * board with one would leave between commands. Whether real firmware
     * leaves it ready before SKINIT is not known, which is what the
     * property is for.
     */
    if (s->drtm_ready) {
        s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = AMD_PSP_DRTM_READY;
    }

    memory_region_init_io(&s->mmio, OBJECT(s), &amd_psp_mmio_ops, s,
                          "amd-psp-mmio", AMD_PSP_BAR_SIZE);
    pci_register_bar(pci_dev, AMD_PSP_BAR_INDEX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

    /*
     * The same registers again, where the ASPT says they are. Firmware
     * leaves this function's memory decode off on at least one board, so
     * this window is the only route software can take without changing the
     * platform first.
     */
    memory_region_init_alias(&s->window, OBJECT(s), "amd-psp-aspt", &s->mmio,
                             AMD_PSP_ASPT_WINDOW, AMD_PSP_ASPT_SIZE);
    memory_region_add_subregion(get_system_memory(), AMD_PSP_ASPT_BASE,
                                &s->window);
}

static void amd_psp_exit(PCIDevice *pci_dev)
{
    AmdPspState *s = AMD_PSP(pci_dev);

    memory_region_del_subregion(get_system_memory(), &s->window);
}

static const Property amd_psp_properties[] = {
    DEFINE_PROP_UINT16("device-id", AmdPspState, device_id,
                       AMD_PSP_DEFAULT_ID),
    DEFINE_PROP_BOOL("drtm-ready", AmdPspState, drtm_ready, true),
    DEFINE_PROP_BOOL("aspt", AmdPspState, aspt, true),
};

static void amd_psp_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = amd_psp_realize;
    k->exit = amd_psp_exit;
    k->vendor_id = PCI_VENDOR_ID_AMD;
    k->device_id = AMD_PSP_DEFAULT_ID;
    k->class_id = PCI_CLASS_CRYPT_OTHER;
    dc->desc = "AMD Secure Processor (mailbox registers, no service)";
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
