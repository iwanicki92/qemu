/*
 * QTest for the AMD dynamic launch platform object
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "hw/i386/amd_iommu.h"
#include "hw/pci-host/amd_nb.h"
#include "hw/pci-host/q35.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"

#define SLB_BASE    0x200000
#define SLB_LENGTH  0x1234

/*
 * Where SKL keeps the IOMMU's command buffer, event log and the word a
 * COMPLETION_WAIT stores to: inside the SLB, behind SL_DEV.
 */
#define CMDBUF_BASE     (SLB_BASE + 0x2000)
#define CMDBUF_LEN      8 /* 256 commands */
#define EVTLOG_BASE     (SLB_BASE + 0x3000)
#define EVTLOG_LEN      8 /* 256 entries */
#define DONE_ADDR       (SLB_BASE + 0x4000)
#define DONE_DATA       0x656e6f64 /* "done" */

#define MMCFG_BASE MCH_HOST_BRIDGE_PCIEXBAR_DEFAULT
#define MMCFG_ADDR(devfn, offset) \
    (MMCFG_BASE + ((uint32_t)(devfn) << 12) + (offset))

static QDict *query_amd_drtm(QTestState *s)
{
    return qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-amd-drtm' }");
}

static bool block_enforced(QDict *info)
{
    QList *blocks = qdict_get_qlist(info, "dma-blocks");
    QDict *block;

    g_assert_cmpuint(qlist_size(blocks), ==, 1);
    block = qobject_to(QDict, qlist_peek(blocks));
    g_assert_cmpstr(qdict_get_str(block, "name"), ==, "sl_dev");
    return qdict_get_bool(block, "enforced");
}

static void check_cleared(QDict *info)
{
    g_assert_false(qdict_get_bool(info, "launched"));
    g_assert_cmpuint(qdict_get_int(info, "slb-base"), ==, 0);
    g_assert_cmpuint(qdict_get_int(info, "slb-length"), ==, 0);
    g_assert_false(qdict_get_bool(info, "sl-dev"));
    g_assert_cmpstr(qdict_get_str(info, "hash"), ==, "none");
    g_assert_cmpuint(qlist_size(qdict_get_qlist(info, "dma-blocks")), ==, 0);
}

static void test_launch(void)
{
    QTestState *s = qtest_init("-M q35 -device amd-drtm-platform");
    uint8_t image[SLB_LENGTH];
    QDict *info, *block;
    QList *blocks;
    int i;

    info = query_amd_drtm(s);
    check_cleared(info);
    qobject_unref(info);

    for (i = 0; i < SLB_LENGTH; i++) {
        image[i] = i;
    }
    qtest_memwrite(s, SLB_BASE, image, sizeof(image));

    qtest_qmp_assert_success(s, "{ 'execute': 'x-amd-drtm-launch', "
                             "'arguments': { 'base': %d, 'length': %d } }",
                             SLB_BASE, SLB_LENGTH);

    info = query_amd_drtm(s);
    g_assert_true(qdict_get_bool(info, "launched"));
    g_assert_cmpuint(qdict_get_int(info, "slb-base"), ==, SLB_BASE);
    g_assert_cmpuint(qdict_get_int(info, "slb-length"), ==, SLB_LENGTH);
    g_assert_true(qdict_get_bool(info, "sl-dev"));
    /* no TPM on this command line */
    g_assert_cmpstr(qdict_get_str(info, "hash"), ==, "unsupported");
    blocks = qdict_get_qlist(info, "dma-blocks");
    g_assert_cmpuint(qlist_size(blocks), ==, 1);
    block = qobject_to(QDict, qlist_peek(blocks));
    g_assert_cmpstr(qdict_get_str(block, "name"), ==, "sl_dev");
    g_assert_cmpuint(qdict_get_int(block, "base"), ==, SLB_BASE);
    g_assert_cmpuint(qdict_get_int(block, "len"), ==, 0x10000);
    /* no IOMMU on this command line */
    g_assert_false(qdict_get_bool(block, "enforced"));
    qobject_unref(info);

    qtest_system_reset(s);

    info = query_amd_drtm(s);
    check_cleared(info);
    qobject_unref(info);

    qtest_quit(s);
}

static uint64_t amdvi_readq(QTestState *s, uint64_t offset)
{
    return qtest_readq(s, AMDVI_BASE_ADDR + offset);
}

static void amdvi_writeq(QTestState *s, uint64_t offset, uint64_t val)
{
    qtest_writeq(s, AMDVI_BASE_ADDR + offset, val);
}

/* SKL's iommu_init(): tables in the SLB, then enable and send commands */
static void iommu_program(QTestState *s)
{
    amdvi_writeq(s, AMDVI_MMIO_COMMAND_BASE,
                 CMDBUF_BASE | ((uint64_t)CMDBUF_LEN << 56));
    amdvi_writeq(s, AMDVI_MMIO_EVENT_BASE,
                 EVTLOG_BASE | ((uint64_t)EVTLOG_LEN << 56));
    amdvi_writeq(s, AMDVI_MMIO_EVENT_HEAD, 0);
    amdvi_writeq(s, AMDVI_MMIO_EVENT_TAIL, 0);
    amdvi_writeq(s, AMDVI_MMIO_STATUS, AMDVI_MMIO_STATUS_EVENT_INT);
    amdvi_writeq(s, AMDVI_MMIO_CONTROL,
                 AMDVI_MMIO_CONTROL_CMDBUFLEN | AMDVI_MMIO_CONTROL_EVENTLOGEN);
    amdvi_writeq(s, AMDVI_MMIO_CONTROL,
                 AMDVI_MMIO_CONTROL_CMDBUFLEN | AMDVI_MMIO_CONTROL_EVENTLOGEN |
                 AMDVI_MMIO_CONTROL_AMDVIEN);
}

/* A COMPLETION_WAIT that stores DONE_DATA at DONE_ADDR, at slot @idx */
static void iommu_completion_wait(QTestState *s, int idx)
{
    uint64_t cmd[2] = {
        cpu_to_le64(((uint64_t)AMDVI_CMD_COMPLETION_WAIT << 60) |
                    DONE_ADDR | 1),
        cpu_to_le64(DONE_DATA),
    };

    qtest_memwrite(s, CMDBUF_BASE + idx * AMDVI_COMMAND_SIZE, cmd,
                   sizeof(cmd));
    amdvi_writeq(s, AMDVI_MMIO_COMMAND_TAIL, (idx + 1) * AMDVI_COMMAND_SIZE);
}

/*
 * With amd-iommu present the block stands in the IOMMU's own view too, so
 * SKL's first iommu_init() sees what hardware shows it: the command fetch
 * from the SLB fails, EventLogInt rises, and neither the event nor the
 * completion word reaches the SLB. After the northbridge release the same
 * command completes.
 */
static void test_sl_dev(void)
{
    const uint32_t memprot = MMCFG_ADDR(AMD_NB_DEVFN, AMD_NB_MEMPROT_CR);
    uint8_t zeros[AMDVI_EVENT_LEN] = { 0 };
    uint8_t event[AMDVI_EVENT_LEN];
    QTestState *s;
    QPCIBus *bus;
    QPCIDevice *mch;
    QDict *info;
    uint32_t done;

    if (!qtest_has_device("amd-iommu")) {
        g_test_skip("amd-iommu not available");
        return;
    }

    s = qtest_init("-M q35 -device amd-drtm-platform -device amd-nb "
                   "-device amd-iommu");
    bus = qpci_new_pc(s, NULL);
    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    g_assert_nonnull(mch);
    qpci_config_writel(mch, MCH_HOST_BRIDGE_PCIEXBAR + 4, 0);
    qpci_config_writel(mch, MCH_HOST_BRIDGE_PCIEXBAR,
                       MMCFG_BASE | MCH_HOST_BRIDGE_PCIEXBAR_LENGTH_256M |
                       MCH_HOST_BRIDGE_PCIEXBAREN);

    qtest_qmp_assert_success(s, "{ 'execute': 'x-amd-drtm-launch', "
                             "'arguments': { 'base': %d, 'length': %d } }",
                             SLB_BASE, SLB_LENGTH);
    info = query_amd_drtm(s);
    g_assert_true(block_enforced(info));
    qobject_unref(info);

    iommu_program(s);
    g_assert_cmphex(amdvi_readq(s, AMDVI_MMIO_STATUS) &
                    AMDVI_MMIO_STATUS_EVENT_INT, ==, 0);
    iommu_completion_wait(s, 0);
    g_assert_cmphex(amdvi_readq(s, AMDVI_MMIO_STATUS) &
                    AMDVI_MMIO_STATUS_EVENT_INT, ==,
                    AMDVI_MMIO_STATUS_EVENT_INT);
    qtest_memread(s, DONE_ADDR, &done, sizeof(done));
    g_assert_cmphex(done, ==, 0);
    qtest_memread(s, EVTLOG_BASE, event, sizeof(event));
    g_assert_cmpmem(event, sizeof(event), zeros, sizeof(zeros));

    /* SKL's release, then its second iommu_init() */
    qtest_writel(s, memprot, qtest_readl(s, memprot) & ~AMD_NB_MEMPROT_EN);
    info = query_amd_drtm(s);
    g_assert_false(qdict_get_bool(info, "sl-dev"));
    g_assert_cmpuint(qlist_size(qdict_get_qlist(info, "dma-blocks")), ==, 0);
    qobject_unref(info);

    iommu_program(s);
    iommu_completion_wait(s, 1);
    g_assert_cmphex(amdvi_readq(s, AMDVI_MMIO_STATUS) &
                    AMDVI_MMIO_STATUS_EVENT_INT, ==, 0);
    qtest_memread(s, DONE_ADDR, &done, sizeof(done));
    g_assert_cmphex(le32_to_cpu(done), ==, DONE_DATA);

    g_free(mch);
    qpci_free_pc(bus);
    qtest_quit(s);
}

/*
 * strict=on turns the guest error a launch without a TPM logs into a
 * guest panic carrying the rule, and the VM stops. Off, it runs on.
 */
static void test_strict(void)
{
    QTestState *s;
    QDict *event, *data, *info, *status;
    const char *rule;

    s = qtest_init("-M q35 -device amd-drtm-platform,strict=on"
                   " -action panic=pause");
    qtest_qmp_assert_success(s, "{ 'execute': 'x-amd-drtm-launch', "
                             "'arguments': { 'base': %d, 'length': %d } }",
                             SLB_BASE, SLB_LENGTH);

    event = qtest_qmp_eventwait_ref(s, "GUEST_PANICKED");
    data = qdict_get_qdict(event, "data");
    g_assert_cmpstr(qdict_get_str(data, "action"), ==, "pause");
    info = qdict_get_qdict(data, "info");
    g_assert_cmpstr(qdict_get_str(info, "type"), ==, "amd-drtm");
    rule = qdict_get_str(info, "rule");
    g_assert_nonnull(strstr(rule, "no TPM"));
    qobject_unref(event);

    status = qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-status' }");
    g_assert_cmpstr(qdict_get_str(status, "status"), ==, "guest-panicked");
    qobject_unref(status);
    qtest_quit(s);

    s = qtest_init("-M q35 -device amd-drtm-platform");
    qtest_qmp_assert_success(s, "{ 'execute': 'x-amd-drtm-launch', "
                             "'arguments': { 'base': %d, 'length': %d } }",
                             SLB_BASE, SLB_LENGTH);
    status = qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-status' }");
    g_assert_cmpstr(qdict_get_str(status, "status"), ==, "running");
    qobject_unref(status);
    qtest_quit(s);
}

static void test_second_instance_rejected(void)
{
    QTestState *s = qtest_init_ext(NULL, "-M q35 -device amd-drtm-platform "
                                   "-device amd-drtm-platform", NULL, false);

    qtest_set_expected_status(s, 1);
    qtest_wait_qemu(s);
    qtest_quit(s);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    if (!qtest_has_machine("q35")) {
        g_test_skip("q35 machine not available");
        return g_test_run();
    }

    qtest_add_func("/q35/amd-drtm/launch", test_launch);
    qtest_add_func("/q35/amd-drtm/sl-dev", test_sl_dev);
    qtest_add_func("/q35/amd-drtm/strict", test_strict);
    qtest_add_func("/q35/amd-drtm/second-instance-rejected",
                   test_second_instance_rejected);
    return g_test_run();
}
