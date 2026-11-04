/*
 * QTest testcase for the AMD northbridge stub, the MCH's function bit and
 * its SMN access pair
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
#include "hw/misc/amd_psp.h"
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

/* Where firmware put the Secure Processor's register block on one board */
#define PSP_BAR 0xcc200000
#define PSP_DEVFN PCI_DEVFN(8, 0)

/* GRUB's smn_register_read(): the address to 0xb8, the data from 0xbc */
static uint32_t smn_read(QPCIDevice *mch, uint32_t addr)
{
    qpci_config_writel(mch, MCH_HOST_BRIDGE_SMN_ADDR, addr);
    return qpci_config_readl(mch, MCH_HOST_BRIDGE_SMN_DATA);
}

static void test_mch_smn(void)
{
    QTestState *qts;
    QPCIBus *bus;
    QPCIDevice *mch;
    QPCIDevice *psp;

    /* Off by default, so the data register answers nothing */
    qts = qtest_init("-M q35 -device amd-psp,addr=8.0");
    bus = qpci_new_pc(qts, NULL);
    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    psp = qpci_device_find(bus, PSP_DEVFN);
    g_assert_nonnull(mch);
    g_assert_nonnull(psp);
    qpci_config_writel(psp, PCI_BASE_ADDRESS_0 + 4 * AMD_PSP_BAR_INDEX,
                       PSP_BAR);
    g_assert_cmphex(smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_LO), ==, 0);
    g_free(psp);
    g_free(mch);
    qpci_free_pc(bus);
    qtest_quit(qts);

    /*
     * On, PSP_BASE_ADDR_LO is the BAR as firmware assigned it, decode
     * enabled or not, and PSP_BASE_ADDR_HI and every other address zero.
     */
    qts = qtest_init("-M q35 -global mch.smn=on -device amd-psp,addr=8.0");
    bus = qpci_new_pc(qts, NULL);
    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    psp = qpci_device_find(bus, PSP_DEVFN);
    g_assert_nonnull(mch);
    g_assert_nonnull(psp);
    qpci_config_writel(psp, PCI_BASE_ADDRESS_0 + 4 * AMD_PSP_BAR_INDEX,
                       PSP_BAR);
    g_assert_cmphex(qpci_config_readw(psp, PCI_COMMAND) & PCI_COMMAND_MEMORY,
                    ==, 0);
    g_assert_cmphex(smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_LO), ==,
                    PSP_BAR);
    g_assert_cmphex(smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_HI), ==, 0);
    g_assert_cmphex(smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_LO - 4), ==,
                    0);

    /* The data register is read-only */
    smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_LO);
    qpci_config_writel(mch, MCH_HOST_BRIDGE_SMN_DATA, 0xdeadbeef);
    g_assert_cmphex(qpci_config_readl(mch, MCH_HOST_BRIDGE_SMN_DATA), ==,
                    PSP_BAR);

    /* Moving the BAR moves the answer */
    qpci_config_writel(psp, PCI_BASE_ADDRESS_0 + 4 * AMD_PSP_BAR_INDEX,
                       PSP_BAR + 0x100000);
    g_assert_cmphex(smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_LO), ==,
                    PSP_BAR + 0x100000);
    g_free(psp);
    g_free(mch);
    qpci_free_pc(bus);
    qtest_quit(qts);

    /* Without a Secure Processor the address answers zero, as no PSP */
    qts = qtest_init("-M q35 -global mch.smn=on");
    bus = qpci_new_pc(qts, NULL);
    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    g_assert_nonnull(mch);
    g_assert_cmphex(smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_LO), ==, 0);
    g_free(mch);
    qpci_free_pc(bus);
    qtest_quit(qts);

    /* amd-drtm=on turns it on */
    if (!qtest_has_device("AMDVI-PCI")) {
        return;
    }
    qts = qtest_init("-M q35,amd-drtm=on -device amd-psp,addr=8.0");
    bus = qpci_new_pc(qts, NULL);
    mch = qpci_device_find(bus, PCI_DEVFN(0, 0));
    psp = qpci_device_find(bus, PSP_DEVFN);
    g_assert_nonnull(mch);
    g_assert_nonnull(psp);
    qpci_config_writel(psp, PCI_BASE_ADDRESS_0 + 4 * AMD_PSP_BAR_INDEX,
                       PSP_BAR);
    g_assert_cmphex(smn_read(mch, MCH_HOST_BRIDGE_SMN_PSP_BASE_LO), ==,
                    PSP_BAR);
    g_free(psp);
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
    qtest_add_func("/q35/mch-smn", test_mch_smn);
    return g_test_run();
}
