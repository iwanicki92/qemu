/*
 * QTest testcase for the AMD northbridge stub and the MCH's function bit
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
 * SKL reaches MEMPROT_CR through MMCONFIG when the MSR maps it, and
 * through port 0xcf8 with AMD's extended register bits otherwise.
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

/* SKL's PCI_CONF1_ADDRESS(): offset bits 8 to 11 in address bits 24 to 27 */
#define CF8_EXT_ADDR(devfn, offset) \
    (0x80000000 | (((offset) & 0xf00) << 16) | ((devfn) << 8) | \
     ((offset) & 0xfc))

static uint32_t cf8_readl(QTestState *qts, uint32_t addr)
{
    qtest_outl(qts, 0xcf8, addr);
    return qtest_inl(qts, 0xcfc);
}

static void cf8_writel(QTestState *qts, uint32_t addr, uint32_t val)
{
    qtest_outl(qts, 0xcf8, addr);
    qtest_outl(qts, 0xcfc, val);
}

static void test_cf8_extended_config(void)
{
    const uint32_t memprot = CF8_EXT_ADDR(AMD_NB_DEVFN, AMD_NB_MEMPROT_CR);
    const uint32_t vendor = CF8_EXT_ADDR(AMD_NB_DEVFN, PCI_VENDOR_ID);
    QTestState *qts;

    /* Off by default, so the extended bits are ignored and 0x84 is hit. */
    qts = qtest_init("-M q35 -device amd-drtm-platform -device amd-nb");
    qtest_qmp_assert_success(qts, "{ 'execute': 'x-amd-drtm-launch',"
                             " 'arguments': { 'base': 1048576,"
                             " 'length': 4096 } }");
    g_assert_true(sl_dev_armed(qts));
    g_assert_cmphex(cf8_readl(qts, memprot), ==, 0);
    cf8_writel(qts, memprot, 0);
    g_assert_true(sl_dev_armed(qts));
    qtest_quit(qts);

    /* On, SKL's release of SL_DEV lands, and the low space still works. */
    qts = qtest_init("-M q35 -global q35-pcihost.cf8-extended-config=on"
                     " -device amd-drtm-platform -device amd-nb");
    g_assert_cmphex(cf8_readl(qts, vendor) & 0xffff, ==, PCI_VENDOR_ID_AMD);
    qtest_qmp_assert_success(qts, "{ 'execute': 'x-amd-drtm-launch',"
                             " 'arguments': { 'base': 1048576,"
                             " 'length': 4096 } }");
    g_assert_true(sl_dev_armed(qts));
    cf8_writel(qts, memprot, cf8_readl(qts, memprot) & ~AMD_NB_MEMPROT_EN);
    g_assert_false(sl_dev_armed(qts));
    cf8_writel(qts, memprot, 0xffffffff);
    g_assert_cmphex(cf8_readl(qts, memprot), ==, AMD_NB_MEMPROT_EN);
    cf8_writel(qts, memprot, 0);

    /* An empty slot answers all ones through the extended route too. */
    g_assert_cmphex(cf8_readl(qts, CF8_EXT_ADDR(PCI_DEVFN(0x19, 0),
                                                AMD_NB_MEMPROT_CR)),
                    ==, 0xffffffff);
    qtest_quit(qts);
}

static void test_mch_multifunction(void)
{
    QTestState *qts;
    QPCIBus *bus;
    QPCIDevice *mch;
    QPCIDevice *dev;

    if (!qtest_has_device("AMDVI-PCI")) {
        g_test_skip("AMDVI-PCI not available");
        return;
    }

    /* Off by default, so 00:00 stays single function. */
    qts = qtest_init("-M q35");
    bus = qpci_new_pc(qts, NULL);
    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    g_assert_nonnull(mch);
    g_assert_cmphex(qpci_config_readb(mch, PCI_HEADER_TYPE) &
                    PCI_HEADER_TYPE_MULTI_FUNCTION, ==, 0);
    g_free(mch);
    qpci_free_pc(bus);
    qtest_quit(qts);

    /* A function above 0 is refused, as before. */
    qts = qtest_init_ext(NULL, "-M q35 -device AMDVI-PCI,addr=0.2", NULL,
                         false);
    qtest_set_expected_status(qts, 1);
    qtest_wait_qemu(qts);
    qtest_quit(qts);

    /* On, the header says so and 00:00.2 answers. */
    qts = qtest_init("-M q35 -global q35-pcihost.mch-multifunction=on"
                     " -device AMDVI-PCI,addr=0.2");
    bus = qpci_new_pc(qts, NULL);
    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    g_assert_nonnull(mch);
    g_assert_cmphex(qpci_config_readb(mch, PCI_HEADER_TYPE) &
                    PCI_HEADER_TYPE_MULTI_FUNCTION, ==,
                    PCI_HEADER_TYPE_MULTI_FUNCTION);
    dev = qpci_device_find(bus, PCI_DEVFN(0, 2));
    g_assert_nonnull(dev);
    g_assert_cmphex(qpci_config_readw(dev, PCI_VENDOR_ID), ==,
                    PCI_VENDOR_ID_AMD);
    g_free(dev);
    g_free(mch);
    qpci_free_pc(bus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/q35/amd-nb/memprot", test_memprot);
    qtest_add_func("/q35/cf8-extended-config", test_cf8_extended_config);
    qtest_add_func("/q35/mch-multifunction", test_mch_multifunction);
    return g_test_run();
}
