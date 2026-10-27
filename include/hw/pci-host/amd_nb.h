/*
 * AMD northbridge function 0
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_PCI_HOST_AMD_NB_H
#define HW_PCI_HOST_AMD_NB_H

#include "hw/pci/pci_device.h"
#include "qom/object.h"

#define TYPE_AMD_NB "amd-nb"
OBJECT_DECLARE_SIMPLE_TYPE(AmdNbState, AMD_NB)

/* Function 0 of a Turin node's Data Fabric. */
#define AMD_NB_DEFAULT_ID 0x12c0

/* Node 0 is device 0x18 on bus 0, node n is device 0x18 + n. */
#define AMD_NB_DEVFN PCI_DEVFN(0x18, 0)

/*
 * The family 17h memory protection control register and its enable bit,
 * which SKL clears to lift SL_DEV protection of the Secure Loader Block.
 * Defined by SKL's include/dev.h and by no public AMD document.
 */
#define AMD_NB_MEMPROT_CR 0x384
#define AMD_NB_MEMPROT_EN (1u << 0)

struct AmdNbState {
    PCIDevice parent_obj;

    uint16_t device_id;
};

#endif
