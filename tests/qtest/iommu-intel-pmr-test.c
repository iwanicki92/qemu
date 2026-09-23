/*
 * QTest for the VT-d Protected Memory Regions (PMR)
 *
 * Runs on a q35 machine with txt=on so the IOMMU reports the PLMR
 * and PHMR capability bits, and leaves DMA remapping disabled so
 * every translation is passthrough and only the PMR check can reject
 * a transfer.  That is exactly the path the PMR has to cover: a
 * device with no root table would otherwise bypass the IOMMU
 * entirely.
 *
 * The test drives the guest-visible register interface directly
 * (the same register sequence the Linux iommu driver uses to release
 * a PMR): program the window, set PMEN.EPM, verify DMA denial, clear
 * PMEN.EPM, verify DMA succeeds again.  No guest and no SENTER run
 * in this test.
 *
 * The machine requires a TPM backend for txt=on even though this test
 * never measures; the in-process TPM emulator from tpm-emu.c satisfies
 * the check, the same way txt-test.c does.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>

#include "hw/i386/intel_iommu_internal.h"
#include "hw/i386/intel_txt.h"
#include "hw/misc/iommu-testdev.h"
#include "io/channel-socket.h"
#include "libqtest-single.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "libqos/qos-iommu-testdev.h"
#include "libqos/qos-intel-iommu.h"
#include "qapi-visit.h"
#include "qemu/module.h"
#include "tpm-emu.h"

#define PMR_IOMMU_BASE      Q35_HOST_BRIDGE_IOMMU_ADDR
#define PMR_DMA_IN_WINDOW   0x40000      /* inside [0, 2 MiB) */
#define PMR_DMA_OUT_WINDOW  0x400000     /* outside the window */
#define PMR_LO_LIMIT        0x1fffff     /* last address of [0, 2 MiB) */
#define PMR_DMA_LEN         4

static TPMTestState pmr_tpm;
static GThread *pmr_tpm_thread;

static void pmr_save_testdev(QPCIDevice *dev, int devfn, void *data)
{
    *(QPCIDevice **)data = dev;
}

static uint32_t pmr_pmen(QTestState *qts)
{
    return qtest_readl(qts, PMR_IOMMU_BASE + DMAR_PMEN_REG);
}

static uint32_t pmr_dma(QTestState *qts, QPCIDevice *dev, QPCIBar bar,
                        uint64_t addr)
{
    return qos_iommu_testdev_trigger_dma(dev, bar, addr, addr,
                                         PMR_DMA_LEN, 0);
}

/* Trigger a floppy sector read through Q35's i8257 ISA DMA channel 2. */
static void dpr_isa_read(QTestState *qts, uint32_t target)
{
    static const uint8_t command[] = {
        0xe6, 0, 0, 0, 1, 2, 1, 0x1b, 0xff,
    };
    unsigned int i;

    qtest_outb(qts, 0x0a, 0x06); /* mask channel 2 */
    qtest_outb(qts, 0x0c, 0);    /* clear flip-flop */
    qtest_outb(qts, 0x04, target & 0xff);
    qtest_outb(qts, 0x04, (target >> 8) & 0xff);
    qtest_outb(qts, 0x81, (target >> 16) & 0xff);
    qtest_outb(qts, 0x05, 0xff); /* 512 bytes minus one */
    qtest_outb(qts, 0x05, 0x01);
    qtest_outb(qts, 0x0b, 0x46); /* single, device-to-memory, ch2 */
    qtest_outb(qts, 0x0a, 0x02); /* unmask channel 2 */
    qtest_outb(qts, 0x3f2, 0x1c); /* motor on, controller + DMA enabled */
    for (i = 0; i < G_N_ELEMENTS(command); i++) {
        qtest_outb(qts, 0x3f5, command[i]);
    }
    for (i = 0; i < 1000; i++) {
        qtest_clock_step(qts, 1000000); /* bounded 1 ms virtual steps */
        if ((qtest_inb(qts, 0x3f4) & 0xd0) == 0xd0) {
            break;
        }
    }
    g_assert_cmpuint(i, <, 1000);
    for (i = 0; i < 7; i++) {
        qtest_inb(qts, 0x3f5);
    }
}

static void test_dpr(QTestState *qts, QPCIDevice *dev, QPCIBar bar)
{
    const uint64_t dpr = (0x10ull << 20) | (2ull << 4) | TXT_DPR_LOCK;
    const uint64_t base = 0xe00000;
    const uint64_t top = 0x1000000;

    g_assert_cmpuint(pmr_dma(qts, dev, bar, base), ==, 0);
    qtest_writel(qts, base, 0x5a5a5a5a);
    /* An invalid, wrapping DPR must not latch its lock bit. */
    qtest_writeq(qts, INTEL_TXT_PUBLIC_BASE + TXT_DPR,
                 (1ull << 4) | TXT_DPR_LOCK);
    g_assert_cmphex(qtest_readq(qts, INTEL_TXT_PUBLIC_BASE + TXT_DPR), ==,
                    0);
    qtest_writeq(qts, INTEL_TXT_PUBLIC_BASE + TXT_DPR, dpr);
    g_assert_cmphex(qtest_readq(qts, INTEL_TXT_PUBLIC_BASE + TXT_DPR), ==,
                    dpr);
    /* CPU access remains possible, but PCI DMA into DPR is denied. */
    qtest_writel(qts, base, 0x12345678);
    g_assert_cmphex(qtest_readl(qts, base), ==, 0x12345678);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, base), ==, ITD_DMA_ERR_TX_FAIL);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, top - 4), ==,
                     ITD_DMA_ERR_TX_FAIL);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, base - 4), ==, 0);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, top), ==, 0);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, base - 2), ==,
                     ITD_DMA_ERR_TX_FAIL);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, top - 2), ==,
                     ITD_DMA_ERR_TX_FAIL);

    /* ISA DMA does not traverse VT-d; it must still be denied. */
    qtest_writel(qts, base, 0x12345678);
    dpr_isa_read(qts, base);
    g_assert_cmphex(qtest_readl(qts, base), ==, 0x12345678);
    qtest_writel(qts, base - 0x1000, 0x12345678);
    dpr_isa_read(qts, base - 0x1000);
    g_assert_cmphex(qtest_readl(qts, base - 0x1000), ==, 0);

    /* PMEN controls PMR only: toggling it cannot disable the DPR. */
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PLMBASE_REG, 0);
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PLMLIMIT_REG, PMR_LO_LIMIT);
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PMEN_REG, VTD_PMEN_EPM);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, PMR_DMA_IN_WINDOW), ==,
                     ITD_DMA_ERR_TX_FAIL);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, base), ==, ITD_DMA_ERR_TX_FAIL);
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PMEN_REG, 0);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, PMR_DMA_IN_WINDOW), ==, 0);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, base), ==, ITD_DMA_ERR_TX_FAIL);
}

static void test_pmr(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev = NULL;
    QPCIBar bar;
    uint32_t cap, pmen;

    if (!qtest_has_machine("q35")) {
        g_test_skip("q35 machine not available");
        return;
    }

    qts = qtest_initf(
        "-machine q35,txt=on -smp 1 -m 512 -net none "
        "-device intel-iommu -device iommu-testdev "
        "-drive if=floppy,file=null-co://,file.read-zeroes=on,"
        "format=raw,size=1440k "
        "-chardev socket,id=chr,path=%s "
        "-tpmdev emulator,id=dev,chardev=chr "
        "-device tpm-tis,tpmdev=dev",
        pmr_tpm.addr->u.q_unix.path);

    pcibus = qpci_new_pc(qts, NULL);
    g_assert(pcibus);
    qpci_device_foreach(pcibus, IOMMU_TESTDEV_VENDOR_ID,
                        IOMMU_TESTDEV_DEVICE_ID, pmr_save_testdev, &dev);
    g_assert(dev);
    qpci_device_enable(dev);
    bar = qpci_iomap(dev, 0, NULL);
    g_assert_false(bar.is_io);

    cap = qtest_readl(qts, PMR_IOMMU_BASE + DMAR_CAP_REG);
    g_assert_true(cap & (VTD_CAP_PLMR | VTD_CAP_PHMR));

    /* The PMR starts released. */
    pmen = pmr_pmen(qts);
    g_assert_cmpuint(pmen & (VTD_PMEN_EPM | VTD_PMEN_PRS), ==, 0);

    /* Before enable, DMA into the would-be window succeeds. */
    g_assert_cmpuint(pmr_dma(qts, dev, bar, PMR_DMA_IN_WINDOW), ==, 0);

    /* Program the low PMR [0, 2 MiB) and enable it. */
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PLMBASE_REG, 0);
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PLMLIMIT_REG, PMR_LO_LIMIT);
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PMEN_REG, VTD_PMEN_EPM);

    /* The device drives PRS once the programming is accepted. */
    pmen = pmr_pmen(qts);
    g_assert_true(pmen & (VTD_PMEN_EPM | VTD_PMEN_PRS));

    /* Base/limit are locked while the region is protected. */
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PLMBASE_REG, 0x400000);
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PLMLIMIT_REG, 0x5fffff);
    g_assert_cmpuint(qtest_readl(qts,
                                 PMR_IOMMU_BASE + DMAR_PLMBASE_REG), ==, 0);
    g_assert_cmpuint(qtest_readl(qts,
                                 PMR_IOMMU_BASE + DMAR_PLMLIMIT_REG),
                     ==, PMR_LO_LIMIT);

    /* DMA into the window is denied, outside still succeeds. */
    g_assert_cmpuint(pmr_dma(qts, dev, bar, PMR_DMA_IN_WINDOW),
                     ==, ITD_DMA_ERR_TX_FAIL);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, PMR_DMA_OUT_WINDOW), ==, 0);

    /* Release the PMR (the Linux iommu driver handshake). */
    qtest_writel(qts, PMR_IOMMU_BASE + DMAR_PMEN_REG, 0);
    pmen = pmr_pmen(qts);
    g_assert_cmpuint(pmen & (VTD_PMEN_EPM | VTD_PMEN_PRS), ==, 0);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, PMR_DMA_IN_WINDOW), ==, 0);

    test_dpr(qts, dev, bar);
    qtest_system_reset(qts);
    g_assert_cmphex(qtest_readq(qts, INTEL_TXT_PUBLIC_BASE + TXT_DPR), ==,
                    0);
    qpci_device_enable(dev);
    bar = qpci_iomap(dev, 0, NULL);
    g_assert_cmpuint(pmr_dma(qts, dev, bar, 0xe00000), ==, 0);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    char *tmp_path = g_dir_make_tmp("qemu-iommu-pmr-test.XXXXXX", NULL);
    int ret;

    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);

    pmr_tpm.addr = g_new0(SocketAddress, 1);
    pmr_tpm.addr->type = SOCKET_ADDRESS_TYPE_UNIX;
    pmr_tpm.addr->u.q_unix.path = g_build_filename(tmp_path, "sock", NULL);
    g_mutex_init(&pmr_tpm.data_mutex);
    g_cond_init(&pmr_tpm.data_cond);
    pmr_tpm.data_cond_signal = false;
    pmr_tpm.tpm_version = TPM_VERSION_2_0;

    pmr_tpm_thread = g_thread_new(NULL, tpm_emu_ctrl_thread, &pmr_tpm);
    tpm_emu_test_wait_cond(&pmr_tpm);

    qtest_add_func("/intel-iommu/pmr-and-dpr", test_pmr);
    ret = g_test_run();

    g_thread_join(pmr_tpm_thread);
    g_unlink(pmr_tpm.addr->u.q_unix.path);
    qapi_free_SocketAddress(pmr_tpm.addr);
    g_rmdir(tmp_path);
    g_free(tmp_path);
    return ret;
}
