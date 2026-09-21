/*
 * QTest testcase for the Intel TXT chipset device
 *
 * Copyright (c) 2026 Michał Kopeć <michal@nozomi.space>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>

#include "hw/i386/intel_txt.h"
#include "io/channel-socket.h"
#include "libqtest-single.h"
#include "qemu/module.h"
#include "tpm-emu.h"

static uint64_t txt_read(uint64_t reg)
{
    return readq(INTEL_TXT_PUBLIC_BASE + reg);
}

static void txt_write(uint64_t reg, uint64_t val)
{
    writeq(INTEL_TXT_PUBLIC_BASE + reg, val);
}

static uint64_t txt_private_read(uint64_t reg)
{
    return readq(INTEL_TXT_PRIVATE_BASE + reg);
}

static void txt_private_write(uint64_t reg, uint64_t val)
{
    writeq(INTEL_TXT_PRIVATE_BASE + reg, val);
}

static void txt_test_didvid(void)
{
    uint64_t didvid = txt_read(TXT_DIDVID);

    g_assert_cmpuint(didvid, ==, INTEL_TXT_DIDVID_DEFAULT);
    /* vendor and device ids in the low 32 bits */
    g_assert_cmpuint(didvid & 0xffff, ==, 0x8086);
    g_assert_cmpuint((didvid >> 16) & 0xffff, ==, 0x29c0);
}

static void txt_test_ver_fsbif(void)
{
    g_assert_cmphex(txt_read(TXT_VER_FSBIF) & TXT_VER_FSBIF_PROD_FUSED,
                    ==, TXT_VER_FSBIF_PROD_FUSED);
}

static void txt_test_sinit(void)
{
    txt_write(TXT_SINIT_BASE, 0x12345000);
    g_assert_cmpuint(txt_read(TXT_SINIT_BASE), ==, 0x12345000);

    txt_write(TXT_SINIT_SIZE, 0x20000);
    g_assert_cmpuint(txt_read(TXT_SINIT_SIZE), ==, 0x20000);

    txt_write(TXT_HEAP_BASE, 0x3ab000);
    g_assert_cmpuint(txt_read(TXT_HEAP_BASE), ==, 0x3ab000);

    txt_write(TXT_HEAP_SIZE, 0xf0000);
    g_assert_cmpuint(txt_read(TXT_HEAP_SIZE), ==, 0xf0000);
}

static void txt_test_dpr_lock(void)
{
    /*
     * DPR: lock bit 0, size [11:4], top [31:20].  Writing a value
     * with the lock bit set makes the register write-once.
     */
    uint64_t dpr = (0x3f0 << 20) | (0x20 << 4) | TXT_DPR_LOCK;

    txt_write(TXT_DPR, dpr);
    g_assert_cmpuint(txt_read(TXT_DPR), ==, dpr & TXT_DPR_MASK);

    /* ignored after lock, even an attempt to unlock */
    txt_write(TXT_DPR, 0);
    g_assert_cmpuint(txt_read(TXT_DPR), ==, dpr & TXT_DPR_MASK);
}

static void txt_test_private_space(void)
{
    /* reads mirror the public space ... */
    g_assert_cmpuint(txt_private_read(TXT_DIDVID),
                     ==, INTEL_TXT_DIDVID_DEFAULT);

    /* ... but writes are ignored (private space is SINIT-only) */
    txt_write(TXT_HEAP_BASE, 0);
    txt_private_write(TXT_HEAP_BASE, 0xdead0000);
    g_assert_cmpuint(txt_read(TXT_HEAP_BASE), ==, 0);
}

static void txt_test_locality(void)
{
    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_LOCALITY1_OPEN, ==, 0);
    txt_write(TXT_CMD_OPEN_LOCALITY1, 1);
    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_LOCALITY1_OPEN,
                    ==, TXT_STS_LOCALITY1_OPEN);

    txt_write(TXT_CMD_CLOSE_LOCALITY1, 1);
    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_LOCALITY1_OPEN, ==, 0);

    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_LOCALITY2_OPEN, ==, 0);
    txt_write(TXT_CMD_OPEN_LOCALITY2, 1);
    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_LOCALITY2_OPEN,
                    ==, TXT_STS_LOCALITY2_OPEN);

    txt_write(TXT_CMD_CLOSE_LOCALITY2, 1);
    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_LOCALITY2_OPEN, ==, 0);
}

static void txt_test_close_private(void)
{
    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_PRIVATE_OPEN, ==, 0);
    txt_write(TXT_CMD_CLOSE_PRIVATE, 1);
    g_assert_cmphex(txt_read(TXT_STS) & TXT_STS_PRIVATE_OPEN, ==, 0);
}

static void txt_test_capabilities(void)
{
    g_assert_cmphex(txt_read(TXT_CAPABILITIES), ==, TXT_CAPABILITIES_DPR);
}

static void txt_test_spad_errorcode(void)
{
    txt_write(TXT_SPAD, 0x12345000);
    g_assert_cmphex(txt_read(TXT_SPAD), ==, 0x12345000);

    txt_write(TXT_ERRORCODE, 0xc0000001);
    g_assert_cmphex(txt_read(TXT_ERRORCODE), ==, 0xc0000001);
}

static void txt_test_public_key(void)
{
    for (unsigned i = 0; i < 4; i++) {
        uint64_t val = txt_read(TXT_PUBLIC_KEY + i * 8);

        g_assert_cmpuint(val, !=, 0);
        g_assert_cmphex(val, ==, TXT_PUBLIC_KEY_PLACEHOLDER);
    }
}

static void txt_test_ests_w1c(void)
{
    /*
     * The only software-settable ESTS bit is TXT_RESET_STS, set as
     * a side effect of TXT.CMD_RESET.  It survives the machine reset
     * that the command also requests (reset_hold preserves it), so
     * the W1C clear works regardless of reset timing.
     */
    txt_write(TXT_CMD_RESET, 1);
    g_assert_cmphex(txt_read(TXT_ESTS) & TXT_ESTS_TXT_RESET_STS,
                    ==, TXT_ESTS_TXT_RESET_STS);

    txt_write(TXT_ESTS, TXT_ESTS_TXT_RESET_STS);
    g_assert_cmphex(txt_read(TXT_ESTS) & TXT_ESTS_TXT_RESET_STS, ==, 0);
}

static void txt_test_secrets(void)
{
    g_assert_cmphex(txt_read(TXT_E2STS) & TXT_E2STS_SECRET_STS, ==, 0);

    txt_write(TXT_CMD_SECRETS, 1);
    g_assert_cmphex(txt_read(TXT_E2STS) & TXT_E2STS_SECRET_STS,
                    ==, TXT_E2STS_SECRET_STS);

    txt_write(TXT_CMD_NO_SECRETS, 1);
    g_assert_cmphex(txt_read(TXT_E2STS) & TXT_E2STS_SECRET_STS, ==, 0);
}

int main(int argc, char **argv)
{
    int ret;
    char *args, *tmp_path = g_dir_make_tmp("qemu-txt-test.XXXXXX", NULL);
    GThread *thread;
    TPMTestState test;

    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);

    test.addr = g_new0(SocketAddress, 1);
    test.addr->type = SOCKET_ADDRESS_TYPE_UNIX;
    test.addr->u.q_unix.path = g_build_filename(tmp_path, "sock", NULL);
    g_mutex_init(&test.data_mutex);
    g_cond_init(&test.data_cond);
    test.data_cond_signal = false;
    test.tpm_version = TPM_VERSION_2_0;

    thread = g_thread_new(NULL, tpm_emu_ctrl_thread, &test);
    tpm_emu_test_wait_cond(&test);

    /*
     * The TXT machine requires a TPM backend for the DRTM
     * measurements; the TPM decode area itself is the regular
     * tpm-tis device at 0xFED40000.
     */
    args = g_strdup_printf(
        "-machine q35,txt=on "
        "-chardev socket,id=chr,path=%s "
        "-tpmdev emulator,id=dev,chardev=chr "
        "-device tpm-tis,tpmdev=dev",
        test.addr->u.q_unix.path);
    qtest_start(args);

    qtest_add_func("/txt/test_didvid", txt_test_didvid);
    qtest_add_func("/txt/test_ver_fsbif", txt_test_ver_fsbif);
    qtest_add_func("/txt/test_sinit", txt_test_sinit);
    qtest_add_func("/txt/test_dpr_lock", txt_test_dpr_lock);
    qtest_add_func("/txt/test_private_space", txt_test_private_space);
    qtest_add_func("/txt/test_locality", txt_test_locality);
    qtest_add_func("/txt/test_close_private", txt_test_close_private);
    qtest_add_func("/txt/test_secrets", txt_test_secrets);
    qtest_add_func("/txt/test_capabilities", txt_test_capabilities);
    qtest_add_func("/txt/test_spad_errorcode", txt_test_spad_errorcode);
    qtest_add_func("/txt/test_public_key", txt_test_public_key);
    /*
     * Registered last: requests a machine reset as a side effect of
     * testing the ESTS write-one-to-clear path.
     */
    qtest_add_func("/txt/test_ests_w1c", txt_test_ests_w1c);

    ret = g_test_run();

    qtest_end();

    g_thread_join(thread);
    g_unlink(test.addr->u.q_unix.path);
    qapi_free_SocketAddress(test.addr);
    g_rmdir(tmp_path);
    g_free(tmp_path);
    g_free(args);
    return ret;
}
