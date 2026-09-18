/*
 * AMD Secure Processor
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_MISC_AMD_PSP_H
#define HW_MISC_AMD_PSP_H

#include "hw/pci/pci_device.h"
#include "qom/object.h"

#define TYPE_AMD_PSP "amd-psp"
OBJECT_DECLARE_SIMPLE_TYPE(AmdPspState, AMD_PSP)

/* The Turin generation's CCP/ASP. */
#define AMD_PSP_DEFAULT_ID 0x156e

/*
 * The register block. Turin firmware puts it on BAR 2 at 0xcc200000 with the
 * next BAR a megabyte above, so a megabyte is the size. Older parts differ:
 * an AMD OSRR names BAR 3 of NBIF0 function 2.
 */
#define AMD_PSP_BAR_INDEX 2
#define AMD_PSP_BAR_SIZE 0x100000

/*
 * The C2PMSG mailboxes, four bytes each from this offset. 58453 appendix
 * G.2 puts C2PMSG_72 at 0x10A20 on Milan and Genoa, which is this base.
 */
#define AMD_PSP_C2PMSG_BASE 0x10900
#define AMD_PSP_C2PMSG_COUNT 128

/*
 * The ASP feature register, which Linux reads at 0x109fc, and the DRTM
 * service's command and response register (_58453, section 3.1_).
 */
#define AMD_PSP_C2PMSG_FEATURE 63
#define AMD_PSP_C2PMSG_DRTM 72

/* Bit 31, which the service sets when it is ready for a command. */
#define AMD_PSP_DRTM_READY (1u << 31)

/*
 * The window the ASPT declares, which is the register block seen from
 * 0x10000 in. It is outside PCI enumeration on hardware, so it sits here
 * beside the address amd-iommu uses rather than in the PCI hole, where a
 * BAR assignment could land on it.
 */
#define AMD_PSP_ASPT_BASE 0xfeda0000ULL
#define AMD_PSP_ASPT_WINDOW 0x10000
#define AMD_PSP_ASPT_SIZE 0x1000

struct AmdPspState {
    PCIDevice parent_obj;

    uint16_t device_id;
    bool drtm_ready;
    bool aspt;
    bool drtm_device;

    MemoryRegion mmio;
    MemoryRegion window;
    uint32_t c2pmsg[AMD_PSP_C2PMSG_COUNT];
};

#endif
