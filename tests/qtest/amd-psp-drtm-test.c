/*
 * QTest for the DRTM service behind the amd-psp mailbox
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "libqos/qos-iommu-testdev.h"
#include "hw/misc/amd_psp.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"

/* The mailbox through the ASPT window, which needs no BAR assignment */
#define MBOX(reg) \
    (AMD_PSP_ASPT_BASE + AMD_PSP_C2PMSG_BASE + 4 * (reg) - AMD_PSP_ASPT_WINDOW)
#define MBOX_CMD    MBOX(AMD_PSP_C2PMSG_DRTM)
#define MBOX_ARG0   MBOX(AMD_PSP_C2PMSG_DRTM_ARG0)
#define MBOX_ARG1   MBOX(AMD_PSP_C2PMSG_DRTM_ARG1)
#define MBOX_ARG2   MBOX(AMD_PSP_C2PMSG_DRTM_ARG2)

#define PSP_DEVFN   PCI_DEVFN(8, 0)
#define TESTDEV_DEVFN PCI_DEVFN(9, 0)

#define PLATFORM "-M q35 -device amd-drtm-platform "
#define PSP "-device amd-psp,addr=8.0,drtm-service=on"

/* Every guest polls the ready bit, and each read lets the service run */
static uint32_t mbox_wait_ready(QTestState *s)
{
    uint32_t val;
    int i;

    for (i = 0; i < 100; i++) {
        val = qtest_readl(s, MBOX_CMD);
        if (val & AMD_PSP_DRTM_READY) {
            return val;
        }
    }
    g_assert_not_reached();
}

/* A command word, and the status the service answers it with */
static uint32_t mbox_command(QTestState *s, uint32_t word)
{
    uint32_t val;

    qtest_writel(s, MBOX_CMD, word);
    val = mbox_wait_ready(s);
    /* the command field is zeroed with the status */
    g_assert_cmphex(val & ~AMD_PSP_DRTM_READY & ~AMD_PSP_DRTM_STATUS_MASK, ==,
                    0);
    return val & AMD_PSP_DRTM_STATUS_MASK;
}

static void mbox_kick(QTestState *s)
{
    qtest_writel(s, MBOX_CMD, 0);
    mbox_wait_ready(s);
}

static uint32_t tmr_setup(QTestState *s, unsigned index, uint64_t base,
                          uint32_t units)
{
    qtest_writel(s, MBOX_ARG0, units);
    qtest_writel(s, MBOX_ARG1, base);
    qtest_writel(s, MBOX_ARG2, base >> 32);
    return mbox_command(s, AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_TMR_SETUP,
                                            index));
}

static QList *dma_blocks(QTestState *s, QDict **info)
{
    *info = qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-amd-drtm' }");
    return qdict_get_qlist(*info, "dma-blocks");
}

static void assert_one_block(QTestState *s, const char *name, uint64_t base,
                             uint64_t len, bool enforced)
{
    QDict *info, *block;
    QList *blocks = dma_blocks(s, &info);

    g_assert_cmpuint(qlist_size(blocks), ==, 1);
    block = qobject_to(QDict, qlist_peek(blocks));
    g_assert_cmpstr(qdict_get_str(block, "name"), ==, name);
    g_assert_cmphex(qdict_get_int(block, "base"), ==, base);
    g_assert_cmphex(qdict_get_int(block, "len"), ==, len);
    g_assert_cmpint(qdict_get_bool(block, "enforced"), ==, enforced);
    qobject_unref(info);
}

static void assert_no_blocks(QTestState *s)
{
    QDict *info;

    g_assert_cmpuint(qlist_size(dma_blocks(s, &info)), ==, 0);
    qobject_unref(info);
}

/* With the service off the device is what it was: writes are dropped */
static void test_service_off(void)
{
    QTestState *s = qtest_init(PLATFORM "-device amd-psp");

    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);
    qtest_writel(s, MBOX_CMD, AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_CAPABILITY,
                                               0));
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);
    qtest_writel(s, MBOX_ARG0, 0x1234);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==, 0);
    qtest_quit(s);
}

/* The service needs the platform object, since the TMRs are its blocks */
static void test_needs_platform(void)
{
    QTestState *s = qtest_init_ext(NULL, "-M q35 " PSP, NULL, false);

    qtest_set_expected_status(s, 1);
    qtest_wait_qemu(s);
    qtest_quit(s);
}

/*
 * GRUB's kick: nothing is answered before a zero write, and the capability
 * afterwards is the board's.
 */
static void test_kick_and_capability(void)
{
    const uint32_t cap = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_CAPABILITY, 0);
    QTestState *s = qtest_init(PLATFORM PSP);
    int i;

    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);

    /* A command before the kick holds the ready bit clear for good */
    qtest_writel(s, MBOX_CMD, cap);
    for (i = 0; i < 20; i++) {
        g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, cap);
    }
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==, 0);

    mbox_kick(s);
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);

    g_assert_cmphex(mbox_command(s, cap), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==,
                    AMD_PSP_DRTM_CAP_ENABLED | AMD_PSP_DRTM_CAP_ANTI_ROLLBACK);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG1), ==, AMD_PSP_DRTM_VERSION);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG2), ==,
                    (1 << AMD_PSP_DRTM_CAP_TMR_COUNT_SHIFT) | 0x10000);
    qtest_quit(s);

    /* The capability reports the properties */
    s = qtest_init(PLATFORM PSP ",tmr-count=8,tmr-alignment=0x1000");
    mbox_kick(s);
    g_assert_cmphex(mbox_command(s, cap), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG2), ==,
                    (8 << AMD_PSP_DRTM_CAP_TMR_COUNT_SHIFT) | 0x1000);
    qtest_quit(s);
}

/* The mailbox through BAR 2, the route GRUB's discovery takes */
static void test_bar(void)
{
    QTestState *s = qtest_init(PLATFORM PSP);
    QPCIBus *bus = qpci_new_pc(s, NULL);
    QPCIDevice *psp = qpci_device_find(bus, PSP_DEVFN);
    QPCIBar bar;
    uint64_t size;
    uint32_t val;
    int i;

    g_assert_nonnull(psp);
    qpci_device_enable(psp);
    bar = qpci_iomap(psp, AMD_PSP_BAR_INDEX, &size);
    g_assert_cmphex(size, ==, AMD_PSP_BAR_SIZE);

    qpci_io_writel(psp, bar, AMD_PSP_C2PMSG_BASE + 4 * AMD_PSP_C2PMSG_DRTM, 0);
    for (i = 0; i < 100; i++) {
        val = qpci_io_readl(psp, bar,
                            AMD_PSP_C2PMSG_BASE + 4 * AMD_PSP_C2PMSG_DRTM);
        if (val & AMD_PSP_DRTM_READY) {
            break;
        }
    }
    g_assert_cmphex(val, ==, AMD_PSP_DRTM_READY);

    qpci_io_writel(psp, bar, AMD_PSP_C2PMSG_BASE + 4 * AMD_PSP_C2PMSG_DRTM,
                   AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_CAPABILITY, 0));
    /* Both routes are the same registers */
    g_assert_cmphex(mbox_wait_ready(s), ==, AMD_PSP_DRTM_READY);
    g_assert_cmphex(qpci_io_readl(psp, bar, AMD_PSP_C2PMSG_BASE +
                                  4 * AMD_PSP_C2PMSG_DRTM_ARG1), ==,
                    AMD_PSP_DRTM_VERSION);

    g_free(psp);
    qpci_free_pc(bus);
    qtest_quit(s);
}

/* The four commands the fork never issues, and every value that is none */
static void test_unsupported(void)
{
    static const uint8_t unsupported[] = {
        AMD_PSP_DRTM_CMD_GET_TCG_LOGS, AMD_PSP_DRTM_CMD_GET_TMR_DESCRIPTORS,
        AMD_PSP_DRTM_CMD_ALLOCATE_SHARED_MEMORY,
        AMD_PSP_DRTM_CMD_GET_IVRS_TABLE_INFO,
    };
    static const uint8_t before_launch[] = {
        AMD_PSP_DRTM_CMD_EXTEND_OSSL_DIGEST,
        AMD_PSP_DRTM_CMD_TPM_LOCALITY_ACCESS,
    };
    static const uint8_t invalid[] = { 0x5, 0x6, 0xd, 0x10, 0xff };
    QTestState *s = qtest_init(PLATFORM PSP);
    int i;

    mbox_kick(s);
    for (i = 0; i < ARRAY_SIZE(unsupported); i++) {
        g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(unsupported[i], 0)),
                        ==, AMD_PSP_DRTM_NOT_SUPPORTED);
    }
    for (i = 0; i < ARRAY_SIZE(before_launch); i++) {
        g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(before_launch[i], 0)),
                        ==, AMD_PSP_DRTM_NOT_SUPPORTED);
    }
    for (i = 0; i < ARRAY_SIZE(invalid); i++) {
        g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(invalid[i], 0)), ==,
                        AMD_PSP_DRTM_INVALID_SERVICE_ID_ERROR);
    }

    /* LAUNCH with no SKINIT recorded is the guide's first failed step */
    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH,
                                                     0)),
                    ==, AMD_PSP_DRTM_LAUNCH_ERROR);
    qtest_quit(s);
}

/*
 * TMRs: each one a block on the platform that device DMA cannot enter,
 * checked with a DMA from the IOMMU test device through the amd-iommu.
 */
static void test_tmr(void)
{
    QTestState *s;
    QPCIBus *bus;
    QPCIDevice *dev;
    QPCIBar bar;

    if (!qtest_has_device("amd-iommu") ||
        !qtest_has_device("iommu-testdev")) {
        g_test_skip("amd-iommu or iommu-testdev not available");
        return;
    }

    s = qtest_init(PLATFORM "-device amd-iommu -device iommu-testdev,addr=9.0 "
                   PSP ",tmr-count=2");
    bus = qpci_new_pc(s, NULL);
    dev = qpci_device_find(bus, TESTDEV_DEVFN);
    g_assert_nonnull(dev);
    qpci_device_enable(dev);
    bar = qpci_iomap(dev, 0, NULL);

    mbox_kick(s);
    assert_no_blocks(s);
    g_assert_cmphex(qos_iommu_testdev_trigger_dma(dev, bar, 0x120000,
                                                  0x120000, 4, 0), ==, 0);

    /* GRUB's TMR 0, here over four units from 1 MiB */
    g_assert_cmphex(tmr_setup(s, 0, 0x100000, 4), ==, AMD_PSP_DRTM_NO_ERROR);
    assert_one_block(s, "tmr0", 0x100000, 0x40000, true);
    g_assert_cmphex(qos_iommu_testdev_trigger_dma(dev, bar, 0x120000,
                                                  0x120000, 4, 0), ==,
                    ITD_DMA_ERR_TX_FAIL);
    g_assert_cmphex(qos_iommu_testdev_trigger_dma(dev, bar, 0x140000,
                                                  0x140000, 4, 0), ==, 0);

    /* Setting the same index again moves it */
    g_assert_cmphex(tmr_setup(s, 0, 0x200000, 1), ==, AMD_PSP_DRTM_NO_ERROR);
    assert_one_block(s, "tmr0", 0x200000, 0x10000, true);
    g_assert_cmphex(qos_iommu_testdev_trigger_dma(dev, bar, 0x120000,
                                                  0x120000, 4, 0), ==, 0);
    g_assert_cmphex(qos_iommu_testdev_trigger_dma(dev, bar, 0x20fffc,
                                                  0x20fffc, 4, 0), ==,
                    ITD_DMA_ERR_TX_FAIL);

    /* The index must be below the count, the base aligned */
    g_assert_cmphex(tmr_setup(s, 2, 0x300000, 1), ==,
                    AMD_PSP_DRTM_TMR_SETUP_FAILED_ERROR);
    g_assert_cmphex(tmr_setup(s, 1, 0x301000, 1), ==,
                    AMD_PSP_DRTM_MEMORY_UNALIGNED_ERROR);
    assert_one_block(s, "tmr0", 0x200000, 0x10000, true);

    /* A second TMR above 4 GiB, and one of zero size the board accepted */
    g_assert_cmphex(tmr_setup(s, 1, 0x100000000ULL, 1), ==,
                    AMD_PSP_DRTM_NO_ERROR);
    {
        QDict *info;
        QList *blocks = dma_blocks(s, &info);

        g_assert_cmpuint(qlist_size(blocks), ==, 2);
        qobject_unref(info);
    }
    g_assert_cmphex(tmr_setup(s, 1, 0x100000000ULL, 0), ==,
                    AMD_PSP_DRTM_NO_ERROR);
    assert_one_block(s, "tmr0", 0x200000, 0x10000, true);

    /* Release takes every TMR, and is fine with none */
    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(
                                     AMD_PSP_DRTM_CMD_TMR_RELEASE, 0)),
                    ==, AMD_PSP_DRTM_NO_ERROR);
    assert_no_blocks(s);
    g_assert_cmphex(qos_iommu_testdev_trigger_dma(dev, bar, 0x20fffc,
                                                  0x20fffc, 4, 0), ==, 0);
    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(
                                     AMD_PSP_DRTM_CMD_TMR_RELEASE, 0)),
                    ==, AMD_PSP_DRTM_NO_ERROR);

    g_free(dev);
    qpci_free_pc(bus);
    qtest_quit(s);
}

/*
 * command-delay holds the ready bit on the virtual clock, and a command
 * arriving meanwhile is dropped rather than queued.
 */
static void test_busy_and_delay(void)
{
    const uint32_t cap = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_CAPABILITY, 0);
    const uint32_t release = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_TMR_RELEASE, 0);
    QTestState *s = qtest_init(PLATFORM PSP ",command-delay=100");
    int i;

    /* The kick is answered at once */
    mbox_kick(s);

    qtest_writel(s, MBOX_CMD, cap);
    for (i = 0; i < 20; i++) {
        g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, cap);
    }
    qtest_writel(s, MBOX_CMD, release);
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, cap);

    qtest_clock_step(s, 50 * SCALE_MS);
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, cap);
    qtest_clock_step(s, 50 * SCALE_MS);
    g_assert_cmphex(mbox_wait_ready(s), ==, AMD_PSP_DRTM_READY);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG1), ==, AMD_PSP_DRTM_VERSION);
    qtest_quit(s);
}

/* Reset takes the kick, the TMRs and the registers back to the start */
static void test_reset(void)
{
    const uint32_t cap = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_CAPABILITY, 0);
    QTestState *s = qtest_init(PLATFORM PSP);
    int i;

    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0x100000, 4), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(mbox_command(s, cap), ==, AMD_PSP_DRTM_NO_ERROR);

    qtest_system_reset(s);
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==, 0);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG1), ==, 0);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG2), ==, 0);
    assert_no_blocks(s);

    qtest_writel(s, MBOX_CMD, cap);
    for (i = 0; i < 20; i++) {
        g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, cap);
    }
    mbox_kick(s);
    g_assert_cmphex(mbox_command(s, cap), ==, AMD_PSP_DRTM_NO_ERROR);
    qtest_quit(s);

    /* drtm-ready=off is the register at reset too */
    s = qtest_init(PLATFORM PSP ",drtm-ready=off");
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, 0);
    mbox_kick(s);
    g_assert_cmphex(mbox_command(s, cap), ==, AMD_PSP_DRTM_NO_ERROR);
    qtest_system_reset(s);
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, 0);
    qtest_quit(s);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    if (!qtest_has_machine("q35") || !qtest_has_device("amd-psp")) {
        g_test_skip("q35 or amd-psp not available");
        return g_test_run();
    }

    qtest_add_func("/amd-psp/drtm/service-off", test_service_off);
    qtest_add_func("/amd-psp/drtm/needs-platform", test_needs_platform);
    qtest_add_func("/amd-psp/drtm/kick-and-capability",
                   test_kick_and_capability);
    qtest_add_func("/amd-psp/drtm/bar", test_bar);
    qtest_add_func("/amd-psp/drtm/unsupported", test_unsupported);
    qtest_add_func("/amd-psp/drtm/tmr", test_tmr);
    qtest_add_func("/amd-psp/drtm/busy-and-delay", test_busy_and_delay);
    qtest_add_func("/amd-psp/drtm/reset", test_reset);

    return g_test_run();
}
