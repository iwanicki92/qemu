/*
 * QTest testcase for txt-firmware=on: the platform as TXT firmware
 * leaves it, after power-on and after a reset
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>

#include "hw/i386/intel_txt.h"
#include "libqos/fw_cfg.h"
#include "libqtest.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "tpm-emu.h"

#define RAM_SIZE    (512 * MiB)
#define ACM_SIZE    0x8000
#define SMP         2

/* Read off the DPR, as the TSEG size below it depends on the machine */
static uint64_t dpr_base;
#define DPR_TOP     (dpr_base + INTEL_TXT_FW_DPR_SIZE)
#define SINIT_BASE  (dpr_base + INTEL_TXT_FW_SINIT_OFFSET)
#define HEAP_BASE   (dpr_base + INTEL_TXT_FW_HEAP_OFFSET)

/* ACM_UUID_V3, in wire order */
static const uint8_t acm_uuid[16] = {
    0xaa, 0x3a, 0xc0, 0x7f, 0xa7, 0x46, 0xdb, 0x18,
    0x2e, 0xac, 0x69, 0x8f, 0x8d, 0x41, 0x7f, 0x5a,
};

typedef struct {
    char *dir;
    GThread *thread;
    TPMTestState tpm;
} Swtpm;

/* An emulated TPM for one QEMU instance, which txt=on requires */
static const char *swtpm_start(Swtpm *t)
{
    t->dir = g_dir_make_tmp("qemu-txt-firmware-test.XXXXXX", NULL);
    t->tpm.addr = g_new0(SocketAddress, 1);
    t->tpm.addr->type = SOCKET_ADDRESS_TYPE_UNIX;
    t->tpm.addr->u.q_unix.path = g_build_filename(t->dir, "sock", NULL);
    g_mutex_init(&t->tpm.data_mutex);
    g_cond_init(&t->tpm.data_cond);
    t->tpm.data_cond_signal = false;
    t->tpm.tpm_version = TPM_VERSION_2_0;
    t->thread = g_thread_new(NULL, tpm_emu_ctrl_thread, &t->tpm);
    tpm_emu_test_wait_cond(&t->tpm);
    return t->tpm.addr->u.q_unix.path;
}

static void swtpm_stop(Swtpm *t)
{
    g_thread_join(t->thread);
    g_unlink(t->tpm.addr->u.q_unix.path);
    qapi_free_SocketAddress(t->tpm.addr);
    g_rmdir(t->dir);
    g_free(t->dir);
}

#define TPM_ARGS    "-chardev socket,id=chr,path=%s " \
                    "-tpmdev emulator,id=dev,chardev=chr " \
                    "-device tpm-tis,tpmdev=dev "

static uint64_t txt_read(QTestState *qts, uint64_t reg)
{
    return qtest_readq(qts, INTEL_TXT_PUBLIC_BASE + reg);
}

static void check_registers(QTestState *qts)
{
    uint64_t dpr = txt_read(qts, TXT_DPR);

    g_assert_cmphex(dpr & TXT_DPR_LOCK, ==, TXT_DPR_LOCK);
    g_assert_cmpuint((dpr >> 4) & 0xff, ==, INTEL_TXT_FW_DPR_SIZE / MiB);
    /* Below TSEG, at least 8 MiB, and the gap left for firmware */
    dpr_base = (dpr & 0xfff00000) - INTEL_TXT_FW_DPR_SIZE;
    g_assert_cmphex(DPR_TOP, <=, RAM_SIZE - 8 * MiB - INTEL_TXT_FW_GAP);
    g_assert_cmphex(txt_read(qts, TXT_SINIT_BASE), ==, SINIT_BASE);
    g_assert_cmphex(txt_read(qts, TXT_SINIT_SIZE), ==,
                    INTEL_TXT_FW_SINIT_SIZE);
    g_assert_cmphex(txt_read(qts, TXT_HEAP_BASE), ==, HEAP_BASE);
    g_assert_cmphex(txt_read(qts, TXT_HEAP_SIZE), ==,
                    INTEL_TXT_FW_HEAP_SIZE);
}

/* The heap's BIOS data, which GRUB checks before it takes the ACM */
static void check_heap(QTestState *qts)
{
    /* The section's size, then version 6, bios_sinit_size, CPU count */
    g_assert_cmphex(qtest_readq(qts, HEAP_BASE), ==, 8 + 0x24 + 8);
    g_assert_cmpuint(qtest_readl(qts, HEAP_BASE + 8), ==, 6);
    g_assert_cmphex(qtest_readl(qts, HEAP_BASE + 8 + 0x04), ==, ACM_SIZE);
    g_assert_cmpuint(qtest_readl(qts, HEAP_BASE + 8 + 0x18), ==, SMP);
    /* An END element closes it */
    g_assert_cmphex(qtest_readq(qts, HEAP_BASE + 8 + 0x24), ==, 8ULL << 32);
}

/* The ACM as SENTER and the loaders find it, following its offsets */
static void check_acm(QTestState *qts)
{
    uint64_t info, ids, gdt, didvid = txt_read(qts, TXT_DIDVID);
    uint8_t uuid[sizeof(acm_uuid)];

    g_assert_cmphex(qtest_readw(qts, SINIT_BASE), ==, 2);         /* chipset */
    g_assert_cmphex(qtest_readw(qts, SINIT_BASE + 2), ==, 0);     /* SINIT */
    g_assert_cmphex(qtest_readl(qts, SINIT_BASE + 0x10), ==, 0x8086);
    g_assert_cmphex(qtest_readl(qts, SINIT_BASE + 0x18), ==, ACM_SIZE / 4);

    /* The info table follows the header and the scratch area */
    info = SINIT_BASE + 4 * (qtest_readl(qts, SINIT_BASE + 0x04) +
                             qtest_readl(qts, SINIT_BASE + 0x7c));
    qtest_memread(qts, info, uuid, sizeof(uuid));
    g_assert_true(memcmp(uuid, acm_uuid, sizeof(uuid)) == 0);
    g_assert_cmpuint(qtest_readb(qts, info + 0x10), ==, 1);    /* SINIT */
    g_assert_cmpuint(qtest_readb(qts, info + 0x11), ==, 3);    /* version */
    g_assert_cmpuint(qtest_readl(qts, info + 0x18), >=, 6);    /* OS-SINIT */
    /* Both wake methods, TPM 2.0 PCR usage and event log format */
    g_assert_cmphex(qtest_readl(qts, info + 0x20) & 0x333, ==, 0x333);

    /* One chipset id, this chipset's */
    ids = SINIT_BASE + qtest_readl(qts, info + 0x14);
    g_assert_cmpuint(qtest_readl(qts, ids), ==, 1);
    g_assert_cmphex(qtest_readw(qts, ids + 4 + 0x04), ==, didvid & 0xffff);
    g_assert_cmphex(qtest_readw(qts, ids + 4 + 0x06), ==,
                    (didvid >> 16) & 0xffff);

    /* Flat code at the entry selector, flat data after it */
    gdt = SINIT_BASE + qtest_readl(qts, SINIT_BASE + 0x2c);
    g_assert_cmpuint(qtest_readl(qts, SINIT_BASE + 0x28), ==, 3 * 8 - 1);
    g_assert_cmpuint(qtest_readl(qts, SINIT_BASE + 0x30), ==, 8);
    g_assert_cmphex(qtest_readq(qts, gdt + 8), ==, 0x00cf9b000000ffffULL);
    g_assert_cmphex(qtest_readq(qts, gdt + 16), ==, 0x00cf93000000ffffULL);
}

/* RAM, the DPR reserved, RAM: split, so coreboot keeps the DPR out */
static void check_e820(QTestState *qts)
{
    QFWCFG *fw_cfg = pc_fw_cfg_init(qts);
    struct {
        uint64_t address, length;
        uint32_t type;
    } QEMU_PACKED table[16];
    size_t size = qfw_cfg_get_file(fw_cfg, "etc/e820", table, sizeof(table));
    bool low = false, high = false, reserved = false;

    for (size_t i = 0; i < size / sizeof(table[0]); i++) {
        uint64_t start = le64_to_cpu(table[i].address);
        uint64_t end = start + le64_to_cpu(table[i].length);

        if (le32_to_cpu(table[i].type) == 1) {
            g_assert_true(end <= dpr_base || start >= DPR_TOP);
            low |= start == 0 && end == dpr_base;
            high |= start == DPR_TOP && end == RAM_SIZE;
        } else if (start == dpr_base && end == DPR_TOP) {
            reserved = true;
        }
    }
    g_assert_true(low);
    g_assert_true(high);
    g_assert_true(reserved);
    pc_fw_cfg_uninit(fw_cfg);
}

static void check_platform(QTestState *qts)
{
    check_registers(qts);
    check_heap(qts);
    check_acm(qts);
    check_e820(qts);
}

/* At power-on, then after a reset that has the DPR's contents to redo */
static void test_firmware_setup(void)
{
    Swtpm tpm;
    QTestState *qts = qtest_initf("-machine q35,txt=on,txt-firmware=on "
                                  "-m %" PRIu64 "M -smp %d "
                                  "-device intel-iommu " TPM_ARGS,
                                  RAM_SIZE / MiB, SMP, swtpm_start(&tpm));

    check_platform(qts);
    qtest_memset(qts, dpr_base, 0, INTEL_TXT_FW_DPR_SIZE);
    qtest_system_reset(qts);
    check_platform(qts);
    qtest_quit(qts);
    swtpm_stop(&tpm);
}

/*
 * IA32_FEATURE_CONTROL is locked before the firmware runs, so the
 * value QEMU hands the firmware to write there must not be offered
 */
static void test_no_feature_control_file(void)
{
    Swtpm tpm;
    QTestState *qts = qtest_initf("-machine q35,txt=on,txt-firmware=on,"
                                  "txt-vmx-compat=on -cpu qemu64,smx=on "
                                  "-m %" PRIu64 "M -device intel-iommu "
                                  TPM_ARGS, RAM_SIZE / MiB,
                                  swtpm_start(&tpm));
    QFWCFG *fw_cfg = pc_fw_cfg_init(qts);
    uint64_t val;

    g_assert_cmpuint(qfw_cfg_get_file(fw_cfg, "etc/msr_feature_control",
                                      &val, sizeof(val)), ==, 0);
    pc_fw_cfg_uninit(fw_cfg);
    qtest_quit(qts);
    swtpm_stop(&tpm);
}

/* Without intel-iommu nothing can lock the DPR */
static void test_requires_iommu(void)
{
    Swtpm tpm;
    g_autofree char *args =
        g_strdup_printf("-machine q35,txt=on,txt-firmware=on "
                        "-m %" PRIu64 "M " TPM_ARGS,
                        RAM_SIZE / MiB, swtpm_start(&tpm));
    QTestState *qts = qtest_init_ext(NULL, args, NULL, false);

    qtest_set_expected_status(qts, 1);
    qtest_wait_qemu(qts);
    qtest_quit(qts);
    swtpm_stop(&tpm);
}

int main(int argc, char **argv)
{
    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/txt-firmware/setup", test_firmware_setup);
    qtest_add_func("/txt-firmware/no_feature_control_file",
                   test_no_feature_control_file);
    qtest_add_func("/txt-firmware/requires_iommu", test_requires_iommu);

    return g_test_run();
}
