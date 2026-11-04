/*
 * AMD FCH power management registers, as far as AMD's Secure Loader reads
 *
 * The FCH's ACPI MMIO block puts its PMIO registers at 0xfed80300. AMD's SL
 * reads AcpiPmTmrBlk there (PMIO 0x64) for the ACPI PM timer's port and
 * times its delays on it. This window answers that register with the
 * ICH9's PM timer, PMBASE + 8 as firmware set PMBASE, and keeps every other
 * byte as plain storage. It sits above the amd-iommu's fixed MMIO at
 * 0xfed80000, which uses nothing in this range.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/isa/isa.h"
#include "hw/pci/pci_device.h"
#include "hw/southbridge/ich9.h"
#include "qemu/module.h"
#include "qom/object.h"
#include "system/address-spaces.h"
#include "trace.h"

#define TYPE_AMD_FCH_PMIO "amd-fch-pmio"
OBJECT_DECLARE_SIMPLE_TYPE(AmdFchPmioState, AMD_FCH_PMIO)

#define FCH_PMIO_BASE 0xfed80300
#define FCH_PMIO_SIZE 0x100
#define FCH_PMIO_ACPI_PM_TMR_BLK 0x64
#define ICH9_PMIO_PM_TMR 0x08

struct AmdFchPmioState {
    ISADevice parent_obj;

    MemoryRegion mmio;
    uint8_t regs[FCH_PMIO_SIZE];
};

/* The ICH9's PM timer port, or 0 before firmware enables PMBASE. */
static uint16_t fch_pmio_pm_timer(void)
{
    Object *lpc = object_resolve_path_type("", TYPE_ICH9_LPC_DEVICE, NULL);
    uint32_t base;

    if (!lpc) {
        return 0;
    }
    base = pci_get_long(PCI_DEVICE(lpc)->config + ICH9_LPC_PMBASE) &
           ICH9_LPC_PMBASE_BASE_ADDRESS_MASK;
    return base ? base + ICH9_PMIO_PM_TMR : 0;
}

static uint64_t fch_pmio_read(void *opaque, hwaddr addr, unsigned size)
{
    AmdFchPmioState *s = opaque;
    uint8_t bytes[8] = { 0 };
    uint16_t timer = fch_pmio_pm_timer();
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < size && addr + i < FCH_PMIO_SIZE; i++) {
        bytes[i] = s->regs[addr + i];
        if (addr + i == FCH_PMIO_ACPI_PM_TMR_BLK) {
            bytes[i] = timer;
        } else if (addr + i == FCH_PMIO_ACPI_PM_TMR_BLK + 1) {
            bytes[i] = timer >> 8;
        }
    }
    for (i = 0; i < size; i++) {
        value |= (uint64_t)bytes[i] << (8 * i);
    }
    trace_amd_fch_pmio_read(addr, size, value);
    return value;
}

static void fch_pmio_write(void *opaque, hwaddr addr, uint64_t value,
                           unsigned size)
{
    AmdFchPmioState *s = opaque;
    unsigned i;

    trace_amd_fch_pmio_write(addr, size, value);
    for (i = 0; i < size && addr + i < FCH_PMIO_SIZE; i++) {
        s->regs[addr + i] = value >> (8 * i);
    }
}

static const MemoryRegionOps fch_pmio_ops = {
    .read = fch_pmio_read,
    .write = fch_pmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void fch_pmio_realize(DeviceState *dev, Error **errp)
{
    AmdFchPmioState *s = AMD_FCH_PMIO(dev);

    memory_region_init_io(&s->mmio, OBJECT(dev), &fch_pmio_ops, s,
                          TYPE_AMD_FCH_PMIO, FCH_PMIO_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), FCH_PMIO_BASE,
                                        &s->mmio, 1);
}

static void fch_pmio_reset(DeviceState *dev)
{
    AmdFchPmioState *s = AMD_FCH_PMIO(dev);

    memset(s->regs, 0, sizeof(s->regs));
}

static void fch_pmio_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = fch_pmio_realize;
    device_class_set_legacy_reset(dc, fch_pmio_reset);
    dc->desc = "AMD FCH PMIO registers at 0xfed80300, AcpiPmTmrBlk only";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo fch_pmio_info = {
    .name          = TYPE_AMD_FCH_PMIO,
    .parent        = TYPE_ISA_DEVICE,
    .instance_size = sizeof(AmdFchPmioState),
    .class_init    = fch_pmio_class_init,
};

static void fch_pmio_register_types(void)
{
    type_register_static(&fch_pmio_info);
}

type_init(fch_pmio_register_types)
