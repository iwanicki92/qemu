/*
 * QTest testcase for the AMD northbridge stub
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "hw/pci/pci_regs.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci-host/amd_nb.h"
#include "hw/pci-host/q35.h"
#include "qobject/qdict.h"

/*
 * SKL reaches MEMPROT_CR through MMCONFIG, which q35 maps from PCIEXBAR.
 * The port 0xcf8 route only carries the low byte of the offset.
 */
#define MMCFG_BASE MCH_HOST_BRIDGE_PCIEXBAR_DEFAULT
#define MMCFG_ADDR(devfn, offset) \
    (MMCFG_BASE + ((uint32_t)(devfn) << 12) + (offset))

static void enable_mmcfg(QPCIDevice *mch)
{
    qpci_config_writel(mch, MCH_HOST_BRIDGE_PCIEXBAR + 4, 0);
    qpci_config_writel(mch, MCH_HOST_BRIDGE_PCIEXBAR,
                       MMCFG_BASE | MCH_HOST_BRIDGE_PCIEXBAR_LENGTH_256M |
                       MCH_HOST_BRIDGE_PCIEXBAREN);
}

static bool sl_dev_armed(QTestState *qts)
{
    QDict *resp = qtest_qmp(qts, "{ 'execute': 'query-amd-drtm' }");
    QDict *ret = qdict_get_qdict(resp, "return");
    bool armed;

    g_assert_nonnull(ret);
    armed = qdict_get_bool(ret, "sl-dev");
    qobject_unref(resp);
    return armed;
}

static void test_memprot(void)
{
    const uint32_t memprot = MMCFG_ADDR(AMD_NB_DEVFN, AMD_NB_MEMPROT_CR);
    QTestState *qts;
    QPCIBus *bus;
    QPCIDevice *mch;
    QPCIDevice *nb;

    qts = qtest_init("-M q35 -device amd-drtm-platform -device amd-nb");
    bus = qpci_new_pc(qts, NULL);

    /* What SKL's node walk reads at 00:18.0, and the end of the walk. */
    nb = qpci_device_find(bus, AMD_NB_DEVFN);
    g_assert_nonnull(nb);
    g_assert_cmphex(qpci_config_readw(nb, PCI_VENDOR_ID), ==,
                    PCI_VENDOR_ID_AMD);
    g_assert_cmphex(qpci_config_readw(nb, PCI_DEVICE_ID), ==,
                    AMD_NB_DEFAULT_ID);
    g_assert_cmphex(qpci_config_readw(nb, PCI_CLASS_DEVICE), ==,
                    PCI_CLASS_BRIDGE_HOST);
    g_assert_cmphex(qpci_config_readb(nb, PCI_HEADER_TYPE) & 0x7f, ==,
                    PCI_HEADER_TYPE_NORMAL);
    g_assert_cmphex(qpci_config_readb(nb, PCI_INTERRUPT_PIN), ==, 0);
    g_assert_cmphex(bus->config_readl(bus, PCI_DEVFN(0x19, 0),
                                      PCI_VENDOR_ID), ==, 0xffffffff);

    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    g_assert_nonnull(mch);
    enable_mmcfg(mch);
    g_assert_cmphex(qtest_readl(qts, memprot), ==, 0);

    qtest_qmp_assert_success(qts, "{ 'execute': 'x-amd-drtm-launch',"
                             " 'arguments': { 'base': 1048576,"
                             " 'length': 4096 } }");
    g_assert_true(sl_dev_armed(qts));

    /* SKL's read-modify-write, which clears MEMPROT_EN. */
    qtest_writel(qts, memprot, qtest_readl(qts, memprot) & ~AMD_NB_MEMPROT_EN);
    g_assert_false(sl_dev_armed(qts));

    /* Only bit 0 holds a value. */
    qtest_writel(qts, memprot, 0xffffffff);
    g_assert_cmphex(qtest_readl(qts, memprot), ==, AMD_NB_MEMPROT_EN);
    qtest_writel(qts, memprot, 0);
    g_assert_cmphex(qtest_readl(qts, memprot), ==, 0);

    /* Reset clears it. PCIEXBAR resets too, so map MMCONFIG again. */
    qtest_writel(qts, memprot, AMD_NB_MEMPROT_EN);
    qtest_system_reset(qts);
    enable_mmcfg(mch);
    g_assert_cmphex(qtest_readl(qts, memprot), ==, 0);

    g_free(nb);
    g_free(mch);
    qpci_free_pc(bus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/q35/amd-nb/memprot", test_memprot);
    return g_test_run();
}
