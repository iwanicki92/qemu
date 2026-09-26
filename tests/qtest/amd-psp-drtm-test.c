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
#include "hw/acpi/tpm.h"
#include "qemu/bswap.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "tpm-util.h"
#include "tpm-tis-util.h"
#include <glib/gstdio.h>

uint64_t tpm_tis_base_addr = TPM_TIS_ADDR_BASE;

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

/* The service's own record on query-amd-drtm */
static void assert_psp(QTestState *s, bool kicked, const char *launch,
                       const char *signature, unsigned command,
                       unsigned status)
{
    QDict *info, *psp;

    info = qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-amd-drtm' }");
    psp = qdict_get_qdict(info, "psp");
    g_assert_nonnull(psp);
    g_assert_cmpint(qdict_get_bool(psp, "kicked"), ==, kicked);
    g_assert_cmpstr(qdict_get_str(psp, "launch"), ==, launch);
    g_assert_cmpstr(qdict_get_str(psp, "signature"), ==, signature);
    g_assert_cmphex(qdict_get_int(psp, "command"), ==, command);
    g_assert_cmphex(qdict_get_int(psp, "status"), ==, status);
    qobject_unref(info);
}

/* With the service off the device is what it was: writes are dropped */
static void test_service_off(void)
{
    QTestState *s = qtest_init(PLATFORM "-device amd-psp");
    QDict *info;

    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);
    qtest_writel(s, MBOX_CMD, AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_CAPABILITY,
                                               0));
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);
    qtest_writel(s, MBOX_ARG0, 0x1234);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==, 0);

    /* And query-amd-drtm has no record of it */
    info = qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-amd-drtm' }");
    g_assert_false(qdict_haskey(info, "psp"));
    qobject_unref(info);
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
    assert_psp(s, false, "none", "none", 0, 0);

    mbox_kick(s);
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, AMD_PSP_DRTM_READY);
    assert_psp(s, true, "none", "none", 0, 0);

    g_assert_cmphex(mbox_command(s, cap), ==, AMD_PSP_DRTM_NO_ERROR);
    assert_psp(s, true, "none", "none", AMD_PSP_DRTM_CMD_GET_CAPABILITY,
               AMD_PSP_DRTM_NO_ERROR);
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

/*
 * Every post-launch command before a launch, with the status the guide's
 * appendix A gives it, and every value that is no command
 */
static void test_unsupported(void)
{
    static const struct {
        uint8_t cmd;
        uint16_t status;
    } before_launch[] = {
        { AMD_PSP_DRTM_CMD_EXTEND_OSSL_DIGEST, AMD_PSP_DRTM_NOT_SUPPORTED },
        { AMD_PSP_DRTM_CMD_TPM_LOCALITY_ACCESS, AMD_PSP_DRTM_NOT_SUPPORTED },
        { AMD_PSP_DRTM_CMD_GET_TMR_DESCRIPTORS, AMD_PSP_DRTM_NOT_SUPPORTED },
        { AMD_PSP_DRTM_CMD_GET_TCG_LOGS, AMD_PSP_DRTM_NOT_SUPPORTED },
        { AMD_PSP_DRTM_CMD_ALLOCATE_SHARED_MEMORY,
          AMD_PSP_DRTM_OUT_OF_RESOURCES_ERROR },
        { AMD_PSP_DRTM_CMD_GET_IVRS_TABLE_INFO,
          AMD_PSP_DRTM_GET_IVRS_TABLE_FAILED },
    };
    static const uint8_t invalid[] = { 0x5, 0x6, 0xd, 0x10, 0xff };
    QTestState *s = qtest_init(PLATFORM PSP);
    int i;

    mbox_kick(s);
    for (i = 0; i < ARRAY_SIZE(before_launch); i++) {
        qtest_writel(s, MBOX_ARG0, 0x1000);
        g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(before_launch[i].cmd,
                                                         0)),
                        ==, before_launch[i].status);
        assert_psp(s, true, "none", "none", before_launch[i].cmd,
                   before_launch[i].status);
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

/* delayed-command narrows the delay to one command code */
static void test_delayed_command(void)
{
    const uint32_t cap = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_CAPABILITY, 0);
    const uint32_t release = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_TMR_RELEASE, 0);
    QTestState *s = qtest_initf(PLATFORM PSP ",command-delay=100,"
                                "delayed-command=%d",
                                AMD_PSP_DRTM_CMD_TMR_RELEASE);

    mbox_kick(s);
    g_assert_cmphex(mbox_command(s, cap), ==, AMD_PSP_DRTM_NO_ERROR);

    qtest_writel(s, MBOX_CMD, release);
    g_assert_cmphex(qtest_readl(s, MBOX_CMD), ==, release);
    qtest_clock_step(s, 100 * SCALE_MS);
    mbox_wait_ready(s);
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

/*
 * An SLB the launch accepts with verify=off: the SL header, a measured
 * body, the signature header with its tag and sizes, a signature nobody
 * checks and a key token. The offsets are the real image's shape scaled
 * down.
 */
#define SLB_BASE        0x200000
#define SLB_MEASURED    0x1000
#define SIG_HDR_OFF     SLB_MEASURED
#define SIG_OFF         (SIG_HDR_OFF + 0x100)
#define TOKEN_OFF       (SIG_OFF + 0x200)
#define TOKEN_LEN       0x440
#define SEC_PATCH_LEVEL 7
#define SHA256_LEN      32

static void build_slb(uint8_t *slb)
{
    size_t i;

    memset(slb, 0, AMD_PSP_SLB_SIZE);
    stw_le_p(slb + 0x00, 0x46);
    stw_le_p(slb + 0x02, SLB_MEASURED);
    memset(slb + 0x04, 0xda, 16);
    stl_le_p(slb + 0x14, 0xffffffff);
    stl_le_p(slb + 0x18, TOKEN_OFF + TOKEN_LEN);
    stw_le_p(slb + 0x1c, 0x1e);
    /* a SOC flag list the qtest CPU is not on, which only traces */
    stl_le_p(slb + 0x1e, 2);
    stl_le_p(slb + 0x22, 0x00a00f00);
    stl_le_p(slb + 0x26, 0x00b00f00);
    for (i = 0x46; i < SLB_MEASURED; i++) {
        slb[i] = i * 7 + 3;
    }
    memcpy(slb + SIG_HDR_OFF + 0x10, "$AS1", 4);
    stl_le_p(slb + SIG_HDR_OFF + 0x14, SIG_OFF);
    stl_le_p(slb + SIG_HDR_OFF + 0x4c, SEC_PATCH_LEVEL);
    for (i = 0; i < 0x200; i++) {
        slb[SIG_OFF + i] = i;
    }
    stl_le_p(slb + TOKEN_OFF + 56, 4096);
    stl_le_p(slb + TOKEN_OFF + 60, 4096);
    for (i = 64; i < TOKEN_LEN; i++) {
        slb[TOKEN_OFF + i] = i * 3 + 1;
    }
}

static void sha256(const void *data, size_t len, uint8_t *out)
{
    gsize digest_len = SHA256_LEN;
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);

    g_checksum_update(sum, data, len);
    g_checksum_get_digest(sum, out, &digest_len);
    g_checksum_free(sum);
    g_assert_cmpuint(digest_len, ==, SHA256_LEN);
}

/* pcr = SHA256(pcr || digest) */
static void extend_digest(uint8_t *pcr, const uint8_t *digest)
{
    uint8_t both[2 * SHA256_LEN];

    memcpy(both, pcr, SHA256_LEN);
    memcpy(both + SHA256_LEN, digest, SHA256_LEN);
    sha256(both, sizeof(both), pcr);
}

/* pcr = SHA256(pcr || SHA256(data)) */
static void extend(uint8_t *pcr, const void *data, size_t len)
{
    uint8_t digest[SHA256_LEN];

    sha256(data, len, digest);
    extend_digest(pcr, digest);
}

/* TPM2_PCR_Read of one PCR in the SHA-256 bank, at locality 0 */
static void pcr_read(QTestState *s, unsigned pcr, uint8_t *digest)
{
    unsigned char cmd[] = {
        0x80, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
        0x01, 0x7e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0b,
        0x03, 0x00, 0x00, 0x00
    };
    unsigned char rsp[1024];

    cmd[17 + pcr / 8] = 1 << (pcr % 8);
    tpm_tis_transfer(s, cmd, sizeof(cmd), rsp, sizeof(rsp));
    g_assert_cmphex(ldl_be_p(&rsp[2]), ==, 62);
    g_assert_cmphex(ldl_be_p(&rsp[6]), ==, 0);
    g_assert_cmphex(lduw_be_p(&rsp[28]), ==, SHA256_LEN);
    memcpy(digest, &rsp[30], SHA256_LEN);
}

static void assert_pcr(QTestState *s, unsigned pcr, const uint8_t *expected)
{
    uint8_t digest[SHA256_LEN];

    pcr_read(s, pcr, digest);
    if (memcmp(digest, expected, SHA256_LEN)) {
        g_autofree char *got = g_strdup("");
        g_autofree char *want = g_strdup("");
        unsigned i;

        for (i = 0; i < SHA256_LEN; i++) {
            char *t = g_strdup_printf("%s%02x", got, digest[i]);
            g_free(got);
            got = t;
            t = g_strdup_printf("%s%02x", want, expected[i]);
            g_free(want);
            want = t;
        }
        g_error("PCR %u is %s, expected %s", pcr, got, want);
    }
}

static uint32_t tis_access(QTestState *s, unsigned locty)
{
    return qtest_readl(s, TIS_REG(locty, TPM_TIS_REG_ACCESS));
}

/* swtpm and QEMU with tpm-tis on it, started past TPM2_Startup */
static QTestState *tpm_start(const char *tpm_path, const char *devices,
                             GPid *swtpm_pid, SocketAddress **addr)
{
    GError *error = NULL;
    QTestState *s;
    gboolean succ;
    char *args;

    succ = tpm_util_swtpm_start(tpm_path, swtpm_pid, addr, &error);
    g_assert_true(succ);

    args = g_strdup_printf(
        "-machine q35 "
        "-chardev socket,id=chr,path=%s "
        "-tpmdev emulator,id=tpm0,chardev=chr "
        "-device tpm-tis,tpmdev=tpm0 -device amd-drtm-platform "
        "-device amd-iommu %s",
        (*addr)->u.q_unix.path, devices);
    s = qtest_init(args);
    g_free(args);

    tpm_util_startup(s, tpm_tis_transfer);
    return s;
}

static void tpm_stop(QTestState *s, GPid swtpm_pid, SocketAddress *addr)
{
    qtest_quit(s);
    tpm_util_swtpm_kill(swtpm_pid);
    g_unlink(addr->u.q_unix.path);
    qapi_free_SocketAddress(addr);
}

static void skinit(QTestState *s, uint32_t length)
{
    qtest_qmp_assert_success(s, "{ 'execute': 'x-amd-drtm-launch', "
                             "'arguments': { 'base': %d, 'length': %d } }",
                             SLB_BASE, length);
}

/*
 * The launch that passes: the PCR 17 and PCR 18 chain the board leaves,
 * the SL_DEV release, the locality unlocks and the seize of the guest's
 * locality while the PSP held the TPM.
 */
static void test_launch(const void *data)
{
    const char *tpm_path = data;
    uint8_t slb[AMD_PSP_SLB_SIZE];
    uint8_t pcr17[SHA256_LEN] = { 0 }, pcr18[SHA256_LEN] = { 0 };
    uint32_t words[2] = { 0 };
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    QDict *info;
    unsigned l;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = tpm_start(tpm_path, PSP ",verify=off", &swtpm_pid, &addr);
    build_slb(slb);
    qtest_memwrite(s, SLB_BASE, slb, sizeof(slb));

    /* Localities 1 to 4 are locked until a launch: all-ones, writes dropped */
    for (l = 1; l <= 4; l++) {
        g_assert_cmphex(tis_access(s, l), ==, 0xffffffff);
    }
    qtest_writeb(s, TIS_REG(2, TPM_TIS_REG_ACCESS),
                 TPM_TIS_ACCESS_REQUEST_USE);
    g_assert_cmphex(tis_access(s, 0) & TPM_TIS_ACCESS_PENDING_REQUEST, ==, 0);

    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0, 0x40), ==, AMD_PSP_DRTM_NO_ERROR);

    skinit(s, SLB_MEASURED);
    extend(pcr17, slb, SLB_MEASURED);
    assert_pcr(s, 17, pcr17);

    /* The guest holds locality 0 while the PSP works */
    qtest_writeb(s, TIS_REG(0, TPM_TIS_REG_ACCESS),
                 TPM_TIS_ACCESS_REQUEST_USE);
    g_assert_cmphex(tis_access(s, 0) & TPM_TIS_ACCESS_ACTIVE_LOCALITY, ==,
                    TPM_TIS_ACCESS_ACTIVE_LOCALITY);

    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH,
                                                     0)),
                    ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==, 1);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG1), ==, 0);
    assert_psp(s, true, "ok", "skipped", AMD_PSP_DRTM_CMD_LAUNCH,
               AMD_PSP_DRTM_NO_ERROR);

    /* Seized: the guest asks again, as SKL learned to */
    g_assert_cmphex(tis_access(s, 0) & (TPM_TIS_ACCESS_ACTIVE_LOCALITY |
                                        TPM_TIS_ACCESS_BEEN_SEIZED), ==,
                    TPM_TIS_ACCESS_BEEN_SEIZED);
    qtest_writeb(s, TIS_REG(0, TPM_TIS_REG_ACCESS),
                 TPM_TIS_ACCESS_BEEN_SEIZED);
    g_assert_cmphex(tis_access(s, 0) & TPM_TIS_ACCESS_BEEN_SEIZED, ==, 0);

    /* Localities 1 and 2 open, 3 and 4 stay locked */
    g_assert_cmphex(tis_access(s, 1), !=, 0xffffffff);
    g_assert_cmphex(tis_access(s, 2), !=, 0xffffffff);
    g_assert_cmphex(tis_access(s, 3), ==, 0xffffffff);
    g_assert_cmphex(tis_access(s, 4), ==, 0xffffffff);

    /* The board's chain: SPLT version, then TSME and anti-rollback */
    extend(pcr17, words, 4);
    words[1] = 1;
    extend(pcr17, words, 8);
    assert_pcr(s, 17, pcr17);
    extend(pcr18, slb + TOKEN_OFF, TOKEN_LEN);
    words[0] = SEC_PATCH_LEVEL;
    extend(pcr18, words, 4);
    assert_pcr(s, 18, pcr18);

    /* SL_DEV is released by the service, the TMR stays */
    info = qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-amd-drtm' }");
    g_assert_false(qdict_get_bool(info, "sl-dev"));
    qobject_unref(info);
    assert_one_block(s, "tmr0", 0, 0x400000, true);

    /* No TMR changes after a launch */
    g_assert_cmphex(tmr_setup(s, 0, 0, 0x40), ==,
                    AMD_PSP_DRTM_TMR_SETUP_NOT_ALLOWED);

    /* Reset locks the localities again and forgets the launch */
    qtest_system_reset(s);
    for (l = 1; l <= 4; l++) {
        g_assert_cmphex(tis_access(s, l), ==, 0xffffffff);
    }
    assert_psp(s, false, "none", "none", 0, 0);

    tpm_stop(s, swtpm_pid, addr);
}

/*
 * Every failure is one status and a guest error: no TMR around the SLB,
 * a measured length other than the header's, a broken signature header.
 * Each caps PCRs 18 to 20 with the all-ones digest, the value the board
 * shows after a failed launch, and unlocks locality 4.
 */
static void test_launch_fails(const void *data)
{
    const char *tpm_path = data;
    const uint32_t launch = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH, 0);
    uint8_t slb[AMD_PSP_SLB_SIZE];
    uint8_t ones[SHA256_LEN];
    uint8_t pcr17[SHA256_LEN], cap[3][SHA256_LEN];
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    unsigned i;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    memset(ones, 0xff, sizeof(ones));
    s = tpm_start(tpm_path, PSP ",verify=off", &swtpm_pid, &addr);
    build_slb(slb);
    qtest_memwrite(s, SLB_BASE, slb, sizeof(slb));
    mbox_kick(s);

    /* No TMR covers the SLB */
    skinit(s, SLB_MEASURED);
    pcr_read(s, 17, pcr17);
    for (i = 0; i < 3; i++) {
        pcr_read(s, 18 + i, cap[i]);
        extend_digest(cap[i], ones);
    }
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_LAUNCH_ERROR);
    assert_psp(s, true, "failed", "none", AMD_PSP_DRTM_CMD_LAUNCH,
               AMD_PSP_DRTM_LAUNCH_ERROR);
    assert_pcr(s, 17, pcr17);
    for (i = 0; i < 3; i++) {
        assert_pcr(s, 18 + i, cap[i]);
    }
    g_assert_cmphex(tis_access(s, 4), !=, 0xffffffff);
    g_assert_cmphex(tis_access(s, 2), ==, 0xffffffff);
    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(
                                     AMD_PSP_DRTM_CMD_EXTEND_OSSL_DIGEST, 0)),
                    ==, AMD_PSP_DRTM_NOT_SUPPORTED);

    /* A TMR now, but SKINIT measured more than the header says */
    g_assert_cmphex(tmr_setup(s, 0, 0, 0x40), ==, AMD_PSP_DRTM_NO_ERROR);
    skinit(s, SLB_MEASURED + 0x10);
    pcr_read(s, 17, pcr17);
    for (i = 0; i < 3; i++) {
        pcr_read(s, 18 + i, cap[i]);
        extend_digest(cap[i], ones);
    }
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_LAUNCH_ERROR);
    assert_pcr(s, 17, pcr17);
    for (i = 0; i < 3; i++) {
        assert_pcr(s, 18 + i, cap[i]);
    }

    /* The signature header's tag is wrong */
    qtest_memwrite(s, SLB_BASE + SIG_HDR_OFF + 0x10, "$AS2", 4);
    skinit(s, SLB_MEASURED);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_LAUNCH_ERROR);
    qtest_memwrite(s, SLB_BASE + SIG_HDR_OFF + 0x10, "$AS1", 4);

    /* And the same image passes once the header is whole again */
    skinit(s, SLB_MEASURED);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_NO_ERROR);

    tpm_stop(s, swtpm_pid, addr);
}

/*
 * The signature check on a real AMDSL SKL image: the launch fails when a
 * signature byte or a signed byte is flipped, and passes with the image
 * whole. A build without gcrypt or nettle skips the check and passes
 * regardless.
 */
#define SKL_IMAGE "tests/data/amd-psp-drtm/skl.bin"

static void test_launch_signature(const void *data)
{
    const char *tpm_path = data;
    const uint32_t launch = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH, 0);
    g_autofree uint8_t *slb = g_malloc0(AMD_PSP_SLB_SIZE);
    g_autofree char *skl = NULL;
    uint8_t pcr18[SHA256_LEN];
    uint32_t words[1];
    uint32_t measured, hdr_off, signed_len, sec_patch_level;
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    gsize len;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    g_assert_true(g_file_get_contents(SKL_IMAGE, &skl, &len, NULL));
    g_assert_cmpuint(len, <=, AMD_PSP_SLB_SIZE);
    memcpy(slb, skl, len);
    measured = lduw_le_p(slb + 2);
    hdr_off = ROUND_UP(measured, 16);
    g_assert_cmpmem(slb + hdr_off + 0x10, 4, "$AS1", 4);
    signed_len = ldl_le_p(slb + hdr_off + 0x14);
    sec_patch_level = ldl_le_p(slb + hdr_off + 0x4c);
    g_assert_cmpuint(signed_len + 0x200 + TOKEN_LEN, <=, len);

    s = tpm_start(tpm_path, PSP, &swtpm_pid, &addr);
    qtest_memwrite(s, SLB_BASE, slb, AMD_PSP_SLB_SIZE);
    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0, 0x40), ==, AMD_PSP_DRTM_NO_ERROR);

#if defined(CONFIG_GCRYPT) || \
    (defined(CONFIG_NETTLE) && defined(CONFIG_HOGWEED))
    /* A signature byte flipped */
    qtest_writeb(s, SLB_BASE + signed_len, slb[signed_len] ^ 0xff);
    skinit(s, measured);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_LAUNCH_ERROR);
    assert_psp(s, true, "failed", "failed", AMD_PSP_DRTM_CMD_LAUNCH,
               AMD_PSP_DRTM_LAUNCH_ERROR);
    qtest_writeb(s, SLB_BASE + signed_len, slb[signed_len]);

    /* A signed but unmeasured byte flipped: the header's image version */
    qtest_writeb(s, SLB_BASE + hdr_off + 0x60, slb[hdr_off + 0x60] ^ 0xff);
    skinit(s, measured);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_LAUNCH_ERROR);
    qtest_writeb(s, SLB_BASE + hdr_off + 0x60, slb[hdr_off + 0x60]);
#endif

    skinit(s, measured);
    pcr_read(s, 18, pcr18);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_NO_ERROR);
#if defined(CONFIG_GCRYPT) || \
    (defined(CONFIG_NETTLE) && defined(CONFIG_HOGWEED))
    assert_psp(s, true, "ok", "verified", AMD_PSP_DRTM_CMD_LAUNCH,
               AMD_PSP_DRTM_NO_ERROR);
#else
    assert_psp(s, true, "ok", "unsupported", AMD_PSP_DRTM_CMD_LAUNCH,
               AMD_PSP_DRTM_NO_ERROR);
#endif
    extend(pcr18, slb + signed_len + 0x200, TOKEN_LEN);
    words[0] = cpu_to_le32(sec_patch_level);
    extend(pcr18, words, sizeof(words));
    assert_pcr(s, 18, pcr18);

    tpm_stop(s, swtpm_pid, addr);
}

/*
 * After a launch: EXTEND_OSSL_DIGEST hashes a range inside a TMR into
 * PCR 17 and PCR 18, then the AMDSL marker after it, and refuses an empty,
 * wrapping or uncovered range. TPM_LOCALITY_ACCESS locks locality 2 and
 * opens 4. Both are unsupported before the launch.
 */
#define DLME_BASE   0x4000000
#define DLME_LEN    0x1234
/* A TMR over the first 256 MiB, which holds the SLB and the MLE */
#define TMR_UNITS   0x1000

static uint32_t extend_ossl_digest(QTestState *s, uint64_t base,
                                   uint32_t size)
{
    qtest_writel(s, MBOX_ARG0, size);
    qtest_writel(s, MBOX_ARG1, base);
    qtest_writel(s, MBOX_ARG2, base >> 32);
    return mbox_command(s, AMD_PSP_DRTM_CMD(
                               AMD_PSP_DRTM_CMD_EXTEND_OSSL_DIGEST, 0));
}

static void test_after_launch(const void *data)
{
    const char *tpm_path = data;
    const uint32_t launch = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH, 0);
    const uint32_t access = AMD_PSP_DRTM_CMD(
                                AMD_PSP_DRTM_CMD_TPM_LOCALITY_ACCESS, 0);
    uint8_t slb[AMD_PSP_SLB_SIZE], dlme[DLME_LEN];
    uint8_t pcr17[SHA256_LEN], pcr18[SHA256_LEN];
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    unsigned i;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = tpm_start(tpm_path, PSP ",verify=off", &swtpm_pid, &addr);
    build_slb(slb);
    qtest_memwrite(s, SLB_BASE, slb, sizeof(slb));
    for (i = 0; i < DLME_LEN; i++) {
        dlme[i] = i * 5 + 1;
    }
    qtest_memwrite(s, DLME_BASE, dlme, sizeof(dlme));
    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0, TMR_UNITS), ==, AMD_PSP_DRTM_NO_ERROR);

    /* Not before the launch */
    g_assert_cmphex(extend_ossl_digest(s, DLME_BASE, DLME_LEN), ==,
                    AMD_PSP_DRTM_NOT_SUPPORTED);
    g_assert_cmphex(mbox_command(s, access), ==, AMD_PSP_DRTM_NOT_SUPPORTED);

    skinit(s, SLB_MEASURED);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_NO_ERROR);
    pcr_read(s, 17, pcr17);
    pcr_read(s, 18, pcr18);

    /*
     * Empty, wrapping, past the TMR's 256 MiB, off a 64 MiB boundary and
     * longer than 64 MiB: nothing extended
     */
    g_assert_cmphex(extend_ossl_digest(s, DLME_BASE, 0), ==,
                    AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED);
    g_assert_cmphex(extend_ossl_digest(s, 0xfffffffffffff000ull, 0x2000), ==,
                    AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED);
    g_assert_cmphex(extend_ossl_digest(s, 0xc000000, 0x4000001), ==,
                    AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED);
    g_assert_cmphex(extend_ossl_digest(s, 0x10000000, 0x1000), ==,
                    AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED);
    g_assert_cmphex(extend_ossl_digest(s, DLME_BASE + 0x10000, DLME_LEN), ==,
                    AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED);
    g_assert_cmphex(extend_ossl_digest(s, 0, 0x4000001), ==,
                    AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED);
    assert_pcr(s, 17, pcr17);
    assert_pcr(s, 18, pcr18);

    /* The range's digest, then the marker, into both PCRs */
    g_assert_cmphex(extend_ossl_digest(s, DLME_BASE, DLME_LEN), ==,
                    AMD_PSP_DRTM_NO_ERROR);
    extend(pcr17, dlme, DLME_LEN);
    extend(pcr17, "AMDSL", 5);
    extend(pcr18, dlme, DLME_LEN);
    extend(pcr18, "AMDSL", 5);
    assert_pcr(s, 17, pcr17);
    assert_pcr(s, 18, pcr18);

    /* Locality 2 handed back to the PSP, 4 opened, 1 still open */
    g_assert_cmphex(tis_access(s, 2), !=, 0xffffffff);
    g_assert_cmphex(tis_access(s, 4), ==, 0xffffffff);
    g_assert_cmphex(mbox_command(s, access), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(tis_access(s, 1), !=, 0xffffffff);
    g_assert_cmphex(tis_access(s, 2), ==, 0xffffffff);
    g_assert_cmphex(tis_access(s, 4), !=, 0xffffffff);

    /* A request for locality 2 afterwards is dropped, 0 stays usable */
    qtest_writeb(s, TIS_REG(2, TPM_TIS_REG_ACCESS),
                 TPM_TIS_ACCESS_REQUEST_USE);
    g_assert_cmphex(tis_access(s, 2), ==, 0xffffffff);
    qtest_writeb(s, TIS_REG(0, TPM_TIS_REG_ACCESS),
                 TPM_TIS_ACCESS_REQUEST_USE);
    g_assert_cmphex(tis_access(s, 0) & TPM_TIS_ACCESS_ACTIVE_LOCALITY, ==,
                    TPM_TIS_ACCESS_ACTIVE_LOCALITY);

    tpm_stop(s, swtpm_pid, addr);
}

/*
 * GET_TCG_LOGS after a launch and an extend: the region holds the TCG2
 * header the board showed and one event per extend the service made, in
 * its order, with the digests and event data the test computes itself.
 * Replaying them gives the PCR values. Guest writes to the region are
 * dropped and a reset empties it.
 */
static const uint8_t tcg_log_header[] = {
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x00, 0x00, 0x00,
    'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0',
    '3', 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x20, 0x00, 0x00,
};

typedef struct {
    uint32_t pcr;
    uint32_t type;
    uint8_t digest[SHA256_LEN];
    uint32_t data_len;
    const void *data;
} TcgEvent;

/* One TCG_PCR_EVENT2 at log + off, checked field by field */
static size_t assert_event(const uint8_t *log, size_t off, size_t len,
                           const TcgEvent *ev)
{
    size_t need = 12 + 2 + SHA256_LEN + 4 + ev->data_len;

    g_assert_cmpuint(off + need, <=, len);
    g_assert_cmphex(ldl_le_p(log + off), ==, ev->pcr);
    g_assert_cmphex(ldl_le_p(log + off + 4), ==, ev->type);
    g_assert_cmphex(ldl_le_p(log + off + 8), ==, 1);
    g_assert_cmphex(lduw_le_p(log + off + 12), ==, 0x000b);
    g_assert_cmpmem(log + off + 14, SHA256_LEN, ev->digest, SHA256_LEN);
    g_assert_cmphex(ldl_le_p(log + off + 14 + SHA256_LEN), ==, ev->data_len);
    if (ev->data_len) {
        g_assert_cmpmem(log + off + 18 + SHA256_LEN, ev->data_len, ev->data,
                        ev->data_len);
    }
    return off + need;
}

static void test_tcg_logs(const void *data)
{
    const char *tpm_path = data;
    const uint32_t launch = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH, 0);
    const uint32_t get_logs = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_GET_TCG_LOGS,
                                               0);
    static const uint32_t splt = 0, fuse[2] = { 0, 1 }, patch = SEC_PATCH_LEVEL;
    uint8_t slb[AMD_PSP_SLB_SIZE], dlme[DLME_LEN], log[AMD_PSP_TCG_LOG_SIZE];
    uint8_t pcr17[SHA256_LEN] = { 0 }, pcr18[SHA256_LEN] = { 0 };
    TcgEvent ev[9] = {
        { 17, AMD_PSP_EV_SL_IMAGE, { 0 }, 0, NULL },
        { 17, AMD_PSP_EV_SPLT_VERSION, { 0 }, 4, &splt },
        { 17, AMD_PSP_EV_FUSE_STATE, { 0 }, 8, fuse },
        { 18, AMD_PSP_EV_KEY_TOKEN, { 0 }, 0, NULL },
        { 18, AMD_PSP_EV_SEC_PATCH_LEVEL, { 0 }, 4, &patch },
        { 17, AMD_PSP_EV_OS_SL_LOAD, { 0 }, 0, NULL },
        { 18, AMD_PSP_EV_OS_SL_LOAD, { 0 }, 0, NULL },
        { 17, AMD_PSP_EV_AMD_SL_SEPARATOR, { 0 }, 5, "AMDSL" },
        { 18, AMD_PSP_EV_AMD_SL_SEPARATOR, { 0 }, 5, "AMDSL" },
    };
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    size_t len, off;
    unsigned i;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = tpm_start(tpm_path, PSP ",verify=off", &swtpm_pid, &addr);
    build_slb(slb);
    qtest_memwrite(s, SLB_BASE, slb, sizeof(slb));
    for (i = 0; i < DLME_LEN; i++) {
        dlme[i] = i * 11 + 2;
    }
    qtest_memwrite(s, DLME_BASE, dlme, sizeof(dlme));
    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0, TMR_UNITS), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(mbox_command(s, get_logs), ==,
                    AMD_PSP_DRTM_NOT_SUPPORTED);

    skinit(s, SLB_MEASURED);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(extend_ossl_digest(s, DLME_BASE, DLME_LEN), ==,
                    AMD_PSP_DRTM_NO_ERROR);

    sha256(slb, SLB_MEASURED, ev[0].digest);
    sha256(&splt, 4, ev[1].digest);
    sha256(fuse, 8, ev[2].digest);
    sha256(slb + TOKEN_OFF, TOKEN_LEN, ev[3].digest);
    sha256(&patch, 4, ev[4].digest);
    sha256(dlme, DLME_LEN, ev[5].digest);
    sha256(dlme, DLME_LEN, ev[6].digest);
    sha256("AMDSL", 5, ev[7].digest);
    sha256("AMDSL", 5, ev[8].digest);

    g_assert_cmphex(mbox_command(s, get_logs), ==, AMD_PSP_DRTM_NO_ERROR);
    len = qtest_readl(s, MBOX_ARG0);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG1), ==, AMD_PSP_TCG_LOG_BASE);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG2), ==, 0);
    g_assert_cmpuint(len, <=, sizeof(log));
    qtest_memread(s, AMD_PSP_TCG_LOG_BASE, log, sizeof(log));

    g_assert_cmpuint(len, >=, sizeof(tcg_log_header));
    g_assert_cmpmem(log, sizeof(tcg_log_header), tcg_log_header,
                    sizeof(tcg_log_header));
    off = sizeof(tcg_log_header);
    for (i = 0; i < ARRAY_SIZE(ev); i++) {
        off = assert_event(log, off, len, &ev[i]);
        extend_digest(ev[i].pcr == 17 ? pcr17 : pcr18, ev[i].digest);
    }
    g_assert_cmpuint(off, ==, len);
    assert_pcr(s, 17, pcr17);
    assert_pcr(s, 18, pcr18);

    /* Guest writes are dropped */
    qtest_writel(s, AMD_PSP_TCG_LOG_BASE, 0xdeadbeef);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_TCG_LOG_BASE), ==, 0);

    /* A reset empties the log */
    qtest_system_reset(s);
    mbox_kick(s);
    g_assert_cmphex(mbox_command(s, get_logs), ==,
                    AMD_PSP_DRTM_NOT_SUPPORTED);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_TCG_LOG_BASE + 4), ==, 0);

    tpm_stop(s, swtpm_pid, addr);
}

/* A kicked service, a TMR over the SLB and the MLE, and a launch */
static void launch_ok(QTestState *s, uint8_t *slb)
{
    build_slb(slb);
    qtest_memwrite(s, SLB_BASE, slb, AMD_PSP_SLB_SIZE);
    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0, TMR_UNITS), ==, AMD_PSP_DRTM_NO_ERROR);
    skinit(s, SLB_MEASURED);
    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH,
                                                     0)),
                    ==, AMD_PSP_DRTM_NO_ERROR);
}

static uint64_t region_base(QTestState *s)
{
    return qtest_readl(s, MBOX_ARG1) |
           (uint64_t)qtest_readl(s, MBOX_ARG2) << 32;
}

/*
 * The three commands no loader issues, after a launch: the TMR
 * descriptors in 64 KiB units, a shared buffer the guest can write, and a
 * copy of the IVRS the machine's ACPI carries. A reset empties all three.
 */
static void test_post_launch_regions(const void *data)
{
    const char *tpm_path = data;
    const uint32_t get_tmrs = AMD_PSP_DRTM_CMD(
                                  AMD_PSP_DRTM_CMD_GET_TMR_DESCRIPTORS, 0);
    const uint32_t allocate = AMD_PSP_DRTM_CMD(
                                  AMD_PSP_DRTM_CMD_ALLOCATE_SHARED_MEMORY, 0);
    const uint32_t get_ivrs = AMD_PSP_DRTM_CMD(
                                  AMD_PSP_DRTM_CMD_GET_IVRS_TABLE_INFO, 0);
    uint8_t slb[AMD_PSP_SLB_SIZE], ivrs[AMD_PSP_IVRS_SIZE], sum = 0;
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    uint32_t len, i;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = tpm_start(tpm_path, PSP ",verify=off,tmr-count=2", &swtpm_pid, &addr);
    launch_ok(s, slb);

    /* Index 0 as TMR_SETUP took it, index 1 never set */
    g_assert_cmphex(mbox_command(s, get_tmrs), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==, 2 * AMD_PSP_TMR_DESC_LEN);
    g_assert_cmphex(region_base(s), ==, AMD_PSP_TMR_DESC_BASE);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_TMR_DESC_BASE), ==, 0);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_TMR_DESC_BASE + 4), ==, 0);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_TMR_DESC_BASE + 8), ==, TMR_UNITS);
    for (i = 12; i < 24; i += 4) {
        g_assert_cmphex(qtest_readl(s, AMD_PSP_TMR_DESC_BASE + i), ==, 0);
    }
    qtest_writel(s, AMD_PSP_TMR_DESC_BASE + 8, 0xdeadbeef);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_TMR_DESC_BASE + 8), ==, TMR_UNITS);

    /* Nothing, or more than the buffer holds, is refused */
    qtest_writel(s, MBOX_ARG0, 0);
    g_assert_cmphex(mbox_command(s, allocate), ==,
                    AMD_PSP_DRTM_OUT_OF_RESOURCES_ERROR);
    qtest_writel(s, MBOX_ARG0, AMD_PSP_SHARED_SIZE + 1);
    g_assert_cmphex(mbox_command(s, allocate), ==,
                    AMD_PSP_DRTM_OUT_OF_RESOURCES_ERROR);
    qtest_writel(s, MBOX_ARG0, AMD_PSP_SHARED_SIZE);
    g_assert_cmphex(mbox_command(s, allocate), ==, AMD_PSP_DRTM_NO_ERROR);
    g_assert_cmphex(qtest_readl(s, MBOX_ARG0), ==, AMD_PSP_SHARED_SIZE);
    g_assert_cmphex(region_base(s), ==, AMD_PSP_SHARED_BASE);
    qtest_writel(s, AMD_PSP_SHARED_BASE, 0x5a5aa5a5);
    qtest_writel(s, AMD_PSP_SHARED_BASE + AMD_PSP_SHARED_SIZE - 4, 0x12345678);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_SHARED_BASE), ==, 0x5a5aa5a5);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_SHARED_BASE +
                                AMD_PSP_SHARED_SIZE - 4), ==, 0x12345678);

    /* The IVRS whole: its signature, length and checksum */
    g_assert_cmphex(mbox_command(s, get_ivrs), ==, AMD_PSP_DRTM_NO_ERROR);
    len = qtest_readl(s, MBOX_ARG0);
    g_assert_cmphex(region_base(s), ==, AMD_PSP_IVRS_BASE);
    g_assert_cmpuint(len, >=, 48);
    g_assert_cmpuint(len, <=, sizeof(ivrs));
    qtest_memread(s, AMD_PSP_IVRS_BASE, ivrs, len);
    g_assert_cmpmem(ivrs, 4, "IVRS", 4);
    g_assert_cmpuint(ldl_le_p(ivrs + 4), ==, len);
    for (i = 0; i < len; i++) {
        sum += ivrs[i];
    }
    g_assert_cmpuint(sum, ==, 0);
    qtest_writel(s, AMD_PSP_IVRS_BASE, 0);
    g_assert_cmpmem(ivrs, 4, "IVRS", 4);

    /* A reset empties the three regions and forgets the launch */
    qtest_system_reset(s);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_TMR_DESC_BASE + 8), ==, 0);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_SHARED_BASE), ==, 0);
    g_assert_cmphex(qtest_readl(s, AMD_PSP_IVRS_BASE), ==, 0);
    mbox_kick(s);
    g_assert_cmphex(mbox_command(s, get_tmrs), ==, AMD_PSP_DRTM_NOT_SUPPORTED);

    tpm_stop(s, swtpm_pid, addr);
}

/* A machine whose ACPI has no IVRS gives the service none to hand out */
static void test_no_ivrs(const void *data)
{
    const char *tpm_path = data;
    uint8_t slb[AMD_PSP_SLB_SIZE];
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = tpm_start(tpm_path, "-global amd-iommu.ivrs=off " PSP ",verify=off",
                  &swtpm_pid, &addr);
    launch_ok(s, slb);
    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(
                                     AMD_PSP_DRTM_CMD_GET_IVRS_TABLE_INFO, 0)),
                    ==, AMD_PSP_DRTM_GET_IVRS_TABLE_FAILED);
    tpm_stop(s, swtpm_pid, addr);
}

/* min-spl fails a launch whose SecPatchLevel is below it, and only then */
static void test_min_spl(const void *data)
{
    const char *tpm_path = data;
    const uint32_t launch = AMD_PSP_DRTM_CMD(AMD_PSP_DRTM_CMD_LAUNCH, 0);
    uint8_t slb[AMD_PSP_SLB_SIZE];
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    char props[64];

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    snprintf(props, sizeof(props), PSP ",verify=off,min-spl=%u",
             SEC_PATCH_LEVEL + 1);
    s = tpm_start(tpm_path, props, &swtpm_pid, &addr);
    build_slb(slb);
    qtest_memwrite(s, SLB_BASE, slb, sizeof(slb));
    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0, TMR_UNITS), ==, AMD_PSP_DRTM_NO_ERROR);
    skinit(s, SLB_MEASURED);
    g_assert_cmphex(mbox_command(s, launch), ==, AMD_PSP_DRTM_LAUNCH_ERROR);
    tpm_stop(s, swtpm_pid, addr);

    snprintf(props, sizeof(props), PSP ",verify=off,min-spl=%u",
             SEC_PATCH_LEVEL);
    s = tpm_start(tpm_path, props, &swtpm_pid, &addr);
    launch_ok(s, slb);
    tpm_stop(s, swtpm_pid, addr);
}

/*
 * A TMR over [0, 4 GiB), the one drtm sets up, covers the interrupt
 * window: the PIT's message from the IO-APIC goes through the IOMMU's
 * view and is dropped, and arrives once TMR_RELEASE lifts the block.
 */
#define IOAPIC_BASE     0xfec00000
#define PIT_PIN         2
#define PROBE_VECTOR    0x40

static bool probe_pending(QTestState *s)
{
    g_autofree char *out = qtest_hmp(s, "info lapic 0");
    g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
    g_autofree char *want = g_strdup_printf(" %u ", PROBE_VECTOR);
    char **l;

    for (l = lines; *l; l++) {
        if (g_str_has_prefix(*l, "IRR")) {
            return strstr(*l, want) != NULL;
        }
    }
    g_assert_not_reached();
}

static void test_tmr_probe(void)
{
    QTestState *s;

    if (!qtest_has_device("amd-iommu")) {
        g_test_skip("amd-iommu not available");
        return;
    }

    s = qtest_init(PLATFORM "-device amd-iommu " PSP);
    mbox_kick(s);
    g_assert_cmphex(tmr_setup(s, 0, 0, 0x10000), ==, AMD_PSP_DRTM_NO_ERROR);
    assert_one_block(s, "tmr0", 0, 0x100000000ULL, true);

    /* Pin 2, fixed, physical, edge, active high, unmasked, to APIC 0 */
    qtest_writel(s, IOAPIC_BASE, 0x10 + 2 * PIT_PIN + 1);
    qtest_writel(s, IOAPIC_BASE + 0x10, 0);
    qtest_writel(s, IOAPIC_BASE, 0x10 + 2 * PIT_PIN);
    qtest_writel(s, IOAPIC_BASE + 0x10, PROBE_VECTOR);
    /* PIT channel 0, rate generator, about 1 kHz */
    qtest_outb(s, 0x43, 0x34);
    qtest_outb(s, 0x40, 1193 & 0xff);
    qtest_outb(s, 0x40, 1193 >> 8);

    qtest_clock_step(s, 20 * SCALE_MS);
    g_assert_false(probe_pending(s));

    g_assert_cmphex(mbox_command(s, AMD_PSP_DRTM_CMD(
                                     AMD_PSP_DRTM_CMD_TMR_RELEASE, 0)),
                    ==, AMD_PSP_DRTM_NO_ERROR);
    assert_no_blocks(s);
    qtest_clock_step(s, 20 * SCALE_MS);
    g_assert_true(probe_pending(s));
    qtest_quit(s);
}

/* locality-locks=off leaves the TIS as it is without a PSP */
static void test_locks_off(const void *data)
{
    const char *tpm_path = data;
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    unsigned l;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = tpm_start(tpm_path, PSP ",locality-locks=off", &swtpm_pid, &addr);
    for (l = 0; l <= 4; l++) {
        g_assert_cmphex(tis_access(s, l), !=, 0xffffffff);
    }
    tpm_stop(s, swtpm_pid, addr);
}

int main(int argc, char **argv)
{
    g_autofree char *tpm_path = g_dir_make_tmp("qemu-amd-psp-drtm.XXXXXX",
                                               NULL);
    int ret;

    g_test_init(&argc, &argv, NULL);

    if (!qtest_has_machine("q35") || !qtest_has_device("amd-psp")) {
        g_test_skip("q35 or amd-psp not available");
        ret = g_test_run();
        tpm_util_rmdir(tpm_path);
        return ret;
    }

    qtest_add_func("/amd-psp/drtm/service-off", test_service_off);
    qtest_add_func("/amd-psp/drtm/needs-platform", test_needs_platform);
    qtest_add_func("/amd-psp/drtm/kick-and-capability",
                   test_kick_and_capability);
    qtest_add_func("/amd-psp/drtm/bar", test_bar);
    qtest_add_func("/amd-psp/drtm/unsupported", test_unsupported);
    qtest_add_func("/amd-psp/drtm/tmr", test_tmr);
    qtest_add_func("/amd-psp/drtm/busy-and-delay", test_busy_and_delay);
    qtest_add_func("/amd-psp/drtm/delayed-command", test_delayed_command);
    qtest_add_func("/amd-psp/drtm/reset", test_reset);
    qtest_add_func("/amd-psp/drtm/tmr-probe", test_tmr_probe);
    qtest_add_data_func("/amd-psp/drtm/launch", tpm_path, test_launch);
    qtest_add_data_func("/amd-psp/drtm/launch-fails", tpm_path,
                        test_launch_fails);
    qtest_add_data_func("/amd-psp/drtm/launch-signature", tpm_path,
                        test_launch_signature);
    qtest_add_data_func("/amd-psp/drtm/after-launch", tpm_path,
                        test_after_launch);
    qtest_add_data_func("/amd-psp/drtm/tcg-logs", tpm_path, test_tcg_logs);
    qtest_add_data_func("/amd-psp/drtm/post-launch-regions", tpm_path,
                        test_post_launch_regions);
    qtest_add_data_func("/amd-psp/drtm/no-ivrs", tpm_path, test_no_ivrs);
    qtest_add_data_func("/amd-psp/drtm/min-spl", tpm_path, test_min_spl);
    qtest_add_data_func("/amd-psp/drtm/locks-off", tpm_path, test_locks_off);

    ret = g_test_run();
    tpm_util_rmdir(tpm_path);
    return ret;
}
