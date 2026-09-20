/*
 * AMD Secure Processor
 *
 * A PCI function answering with an AMD Secure Processor's vendor and device
 * ID, its C2PMSG mailbox registers, and the second window an ASPT declares
 * for them. With drtm-service=on the DRTM service AMD's publication 58453
 * specifies answers behind the mailbox, as far as the TrenchBoot fork
 * drives it. Without it reads answer and writes are dropped.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/misc/amd_psp.h"
#include "hw/core/qdev-properties.h"
#include "hw/i386/amd_drtm.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "system/address-spaces.h"
#include "trace.h"

static const char *amd_psp_tmr_name(unsigned index)
{
    static const char *const names[AMD_PSP_DRTM_TMR_MAX] = {
        "tmr0", "tmr1", "tmr2", "tmr3", "tmr4", "tmr5", "tmr6", "tmr7",
    };

    return names[index];
}

static void amd_psp_tmr_release(AmdPspState *s, unsigned index)
{
    AmdPspTmr *tmr = &s->tmr[index];

    if (!tmr->set) {
        return;
    }
    trace_amd_psp_drtm_tmr_release(index, tmr->base, tmr->len);
    amd_drtm_unblock_dma(s->platform, amd_psp_tmr_name(index));
    tmr->set = false;
}

static uint16_t amd_psp_cmd_get_capability(AmdPspState *s)
{
    /* The board's values: DRTM enabled, TSME off, anti-rollback set */
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0] = AMD_PSP_DRTM_CAP_ENABLED |
                                          AMD_PSP_DRTM_CAP_ANTI_ROLLBACK;
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1] = AMD_PSP_DRTM_VERSION;
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2] =
        (s->tmr_alignment & AMD_PSP_DRTM_CAP_TMR_ALIGNMENT_MASK) |
        ((uint32_t)s->tmr_count << AMD_PSP_DRTM_CAP_TMR_COUNT_SHIFT);
    return AMD_PSP_DRTM_NO_ERROR;
}

/*
 * C2PMSG_93 the size in 64 KiB units, _94 and _95 the base. A size of zero
 * is accepted, as the board accepted GRUB's, and only recorded: a launch
 * inside such a TMR cannot pass, hence the guest error.
 */
static uint16_t amd_psp_cmd_tmr_setup(AmdPspState *s, unsigned index)
{
    uint64_t units = s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0];
    uint64_t base = s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1] |
                    (uint64_t)s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2] << 32;
    uint64_t len = units * AMD_PSP_DRTM_TMR_UNIT;
    AmdPspTmr *tmr;

    if (s->launch == AMD_PSP_LAUNCH_OK) {
        return AMD_PSP_DRTM_TMR_SETUP_NOT_ALLOWED;
    }
    if (index >= s->tmr_count) {
        return AMD_PSP_DRTM_TMR_SETUP_FAILED_ERROR;
    }
    if (base & (s->tmr_alignment - 1)) {
        return AMD_PSP_DRTM_MEMORY_UNALIGNED_ERROR;
    }
    if (base + len < base) {
        return AMD_PSP_DRTM_TMR_SETUP_FAILED_ERROR;
    }
    if (!len) {
        amd_drtm_guest_error(s->platform, "amd-psp: TMR %u at 0x%" PRIx64
                             " has zero size, a launch inside it will fail",
                             index, base);
    }

    amd_psp_tmr_release(s, index);
    tmr = &s->tmr[index];
    tmr->set = true;
    tmr->base = base;
    tmr->len = len;
    trace_amd_psp_drtm_tmr_setup(index, base, len);
    if (len) {
        amd_drtm_block_dma(s->platform, base, len, amd_psp_tmr_name(index),
                           false);
    }
    return AMD_PSP_DRTM_NO_ERROR;
}

static uint16_t amd_psp_cmd_tmr_release(AmdPspState *s)
{
    unsigned i;

    for (i = 0; i < AMD_PSP_DRTM_TMR_MAX; i++) {
        amd_psp_tmr_release(s, i);
    }
    return AMD_PSP_DRTM_NO_ERROR;
}

static uint16_t amd_psp_cmd_launch(AmdPspState *s)
{
    if (!amd_drtm_launched(s->platform)) {
        amd_drtm_guest_error(s->platform, "amd-psp: LAUNCH with no SKINIT "
                             "recorded, no SKL address to read");
        return AMD_PSP_DRTM_LAUNCH_ERROR;
    }
    return AMD_PSP_DRTM_LAUNCH_ERROR;
}

static uint16_t amd_psp_dispatch(AmdPspState *s, uint8_t cmd, unsigned index)
{
    switch (cmd) {
    case AMD_PSP_DRTM_CMD_GET_CAPABILITY:
        return amd_psp_cmd_get_capability(s);
    case AMD_PSP_DRTM_CMD_TMR_SETUP:
        return amd_psp_cmd_tmr_setup(s, index);
    case AMD_PSP_DRTM_CMD_TMR_RELEASE:
        return amd_psp_cmd_tmr_release(s);
    case AMD_PSP_DRTM_CMD_LAUNCH:
        return amd_psp_cmd_launch(s);
    case AMD_PSP_DRTM_CMD_EXTEND_OSSL_DIGEST:
    case AMD_PSP_DRTM_CMD_TPM_LOCALITY_ACCESS:
        /* The guide's "DRTM has not launched yet" row, appendix A */
        return AMD_PSP_DRTM_NOT_SUPPORTED;
    case AMD_PSP_DRTM_CMD_GET_TCG_LOGS:
    case AMD_PSP_DRTM_CMD_GET_TMR_DESCRIPTORS:
    case AMD_PSP_DRTM_CMD_ALLOCATE_SHARED_MEMORY:
    case AMD_PSP_DRTM_CMD_GET_IVRS_TABLE_INFO:
        /* The four the fork never issues, not modelled */
        return AMD_PSP_DRTM_NOT_SUPPORTED;
    default:
        return AMD_PSP_DRTM_INVALID_SERVICE_ID_ERROR;
    }
}

static void amd_psp_publish(AmdPspState *s)
{
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = AMD_PSP_DRTM_READY | s->status;
    s->busy = false;
    trace_amd_psp_drtm_status(s->command, s->status);
}

static void amd_psp_delay_expired(void *opaque)
{
    amd_psp_publish(opaque);
}

/* The command the last write issued, run once the write has returned */
static void amd_psp_run_command(void *opaque)
{
    AmdPspState *s = opaque;
    uint32_t word = s->c2pmsg[AMD_PSP_C2PMSG_DRTM];
    unsigned index = (word >> AMD_PSP_DRTM_TMR_INDEX_SHIFT) &
                     AMD_PSP_DRTM_TMR_INDEX_MASK;

    s->command = (word >> AMD_PSP_DRTM_CMD_SHIFT) & AMD_PSP_DRTM_CMD_MASK;
    s->status = amd_psp_dispatch(s, s->command, index);

    if (s->command_delay) {
        trace_amd_psp_drtm_ready_held(s->command_delay);
        timer_mod(s->delay_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + s->command_delay);
    } else {
        amd_psp_publish(s);
    }
}

/*
 * A write to C2PMSG_72. Zero is the kick the service needs before it
 * answers anything, as GRUB's comment records. Until it arrives a command
 * leaves the ready bit clear, which is what the guest's timeout is for.
 * One command runs at a time, and one arriving meanwhile is dropped.
 */
static void amd_psp_command_write(AmdPspState *s, uint32_t value)
{
    uint32_t word = value & ~AMD_PSP_DRTM_READY;

    if (s->busy) {
        amd_drtm_guest_error(s->platform, "amd-psp: write 0x%x to C2PMSG_72 "
                             "while command 0x%x is in flight, dropped",
                             value, s->command);
        return;
    }
    if (!word) {
        trace_amd_psp_drtm_kick();
        s->kicked = true;
        s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = AMD_PSP_DRTM_READY;
        return;
    }
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = word;
    if (!s->kicked) {
        amd_drtm_guest_error(s->platform, "amd-psp: command 0x%x before the "
                             "service was kicked, no answer until a zero "
                             "write", word);
        return;
    }
    s->busy = true;
    s->command = (word >> AMD_PSP_DRTM_CMD_SHIFT) & AMD_PSP_DRTM_CMD_MASK;
    trace_amd_psp_drtm_command(s->command,
                               (word >> AMD_PSP_DRTM_TMR_INDEX_SHIFT) &
                               AMD_PSP_DRTM_TMR_INDEX_MASK,
                               s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0],
                               s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1],
                               s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2]);
    qemu_bh_schedule(s->bh);
}

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
 * Without the service a write is dropped rather than stored: a write is
 * how x86 issues a command, and answering one means running the service.
 */
static void amd_psp_write(void *opaque, hwaddr addr, uint64_t value,
                          unsigned size)
{
    AmdPspState *s = opaque;
    hwaddr offset = addr - AMD_PSP_C2PMSG_BASE;
    unsigned reg;

    if (!s->drtm_service || addr < AMD_PSP_C2PMSG_BASE ||
        offset >= sizeof(s->c2pmsg)) {
        return;
    }
    reg = offset / sizeof(s->c2pmsg[0]);
    switch (reg) {
    case AMD_PSP_C2PMSG_DRTM:
        amd_psp_command_write(s, value);
        break;
    case AMD_PSP_C2PMSG_DRTM_ARG0:
    case AMD_PSP_C2PMSG_DRTM_ARG1:
    case AMD_PSP_C2PMSG_DRTM_ARG2:
        s->c2pmsg[reg] = value;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps amd_psp_mmio_ops = {
    .read = amd_psp_read,
    .write = amd_psp_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/*
 * Everything the service did goes, its TMR blocks included. swtpm resets
 * at the same point, so there is nothing for a surviving state to
 * protect. The registers return to what drtm-ready says.
 */
static void amd_psp_reset(DeviceState *dev)
{
    AmdPspState *s = AMD_PSP(dev);
    unsigned i;

    if (s->drtm_service) {
        trace_amd_psp_drtm_reset();
        timer_del(s->delay_timer);
        qemu_bh_cancel(s->bh);
        for (i = 0; i < AMD_PSP_DRTM_TMR_MAX; i++) {
            amd_psp_tmr_release(s, i);
        }
    }
    s->kicked = false;
    s->busy = false;
    s->command = 0;
    s->status = 0;
    s->launch = AMD_PSP_LAUNCH_NONE;
    memset(s->c2pmsg, 0, sizeof(s->c2pmsg));
    /*
     * Whether real firmware leaves the register ready before SKINIT is
     * not known, which is what the property is for.
     */
    if (s->drtm_ready) {
        s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = AMD_PSP_DRTM_READY;
    }
}

static void amd_psp_realize(PCIDevice *pci_dev, Error **errp)
{
    AmdPspState *s = AMD_PSP(pci_dev);

    pci_set_word(pci_dev->config + PCI_DEVICE_ID, s->device_id);

    if (s->drtm_service) {
        s->platform = amd_drtm_platform_find();
        if (!s->platform) {
            error_setg(errp, "drtm-service=on needs one %s, which holds "
                       "the launch the service checks and the DMA blocks "
                       "its TMRs are", TYPE_AMD_DRTM_PLATFORM);
            return;
        }
        if (!s->tmr_count || s->tmr_count > AMD_PSP_DRTM_TMR_MAX) {
            error_setg(errp, "tmr-count must be 1 to %d", AMD_PSP_DRTM_TMR_MAX);
            return;
        }
        if (!is_power_of_2(s->tmr_alignment) ||
            s->tmr_alignment > AMD_PSP_DRTM_CAP_TMR_ALIGNMENT_MASK) {
            error_setg(errp, "tmr-alignment must be a power of two below "
                       "2^24");
            return;
        }
        s->bh = qemu_bh_new_guarded(amd_psp_run_command, s,
                                    &DEVICE(s)->mem_reentrancy_guard);
        s->delay_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                      amd_psp_delay_expired, s);
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
    if (s->drtm_service) {
        timer_free(s->delay_timer);
        qemu_bh_delete(s->bh);
    }
}

static const Property amd_psp_properties[] = {
    DEFINE_PROP_UINT16("device-id", AmdPspState, device_id,
                       AMD_PSP_DEFAULT_ID),
    DEFINE_PROP_BOOL("drtm-ready", AmdPspState, drtm_ready, true),
    DEFINE_PROP_BOOL("aspt", AmdPspState, aspt, true),
    /*
     * The DRTM ACPI device is firmware's on hardware, behind a setup option
     * of its own, and rides on this device here because it is the AMD one a
     * guest asking for any of this already has.
     */
    DEFINE_PROP_BOOL("drtm-device", AmdPspState, drtm_device, false),
    /* The service behind the mailbox, and what it reports and checks */
    DEFINE_PROP_BOOL("drtm-service", AmdPspState, drtm_service, false),
    DEFINE_PROP_UINT8("tmr-count", AmdPspState, tmr_count, 1),
    DEFINE_PROP_UINT32("tmr-alignment", AmdPspState, tmr_alignment,
                       AMD_PSP_DRTM_TMR_UNIT),
    DEFINE_PROP_UINT32("splt-version", AmdPspState, splt_version, 0),
    DEFINE_PROP_BOOL("verify", AmdPspState, verify, true),
    /* Milliseconds the ready bit stays clear after each command */
    DEFINE_PROP_UINT32("command-delay", AmdPspState, command_delay, 0),
    DEFINE_PROP_BOOL("locality-locks", AmdPspState, locality_locks, true),
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
    dc->desc = "AMD Secure Processor (mailbox registers, DRTM service)";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_legacy_reset(dc, amd_psp_reset);
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
