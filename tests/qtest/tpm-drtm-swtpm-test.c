/*
 * QTest testcase for the locality 4 hash an AMD dynamic launch sends to
 * swtpm through the TPM TIS frontend
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include "qemu/bswap.h"

#include "libqtest.h"
#include "qemu/module.h"
#include "tpm-tests.h"
#include "tpm-tis-util.h"
#include "hw/acpi/tpm.h"

uint64_t tpm_tis_base_addr = TPM_TIS_ADDR_BASE;

/* Three hash_data chunks: two full ones and a short tail. */
#define IMAGE_BASE   0x100000
#define IMAGE_LENGTH 9000

#define SHA256_LEN   32

/* TPM2_PCR_Read of PCR 17 in the SHA-256 bank */
static const unsigned char tpm2_pcrread_17[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
    0x01, 0x7e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0b,
    0x03, 0x00, 0x00, 0x02
};

/*
 * The response carries the header, pcrUpdateCounter, the selection echoed
 * back, the digest count and one TPM2B_DIGEST of 32 bytes.
 */
#define PCRREAD_RESP_LEN     62
#define PCRREAD_DIGEST_OFF   30

static void pcr17_read(QTestState *s, unsigned char *digest)
{
    unsigned char rsp[1024];

    tpm_tis_transfer(s, tpm2_pcrread_17, sizeof(tpm2_pcrread_17),
                     rsp, sizeof(rsp));

    /* header, then response code */
    g_assert_cmphex(rsp[0], ==, 0x80);
    g_assert_cmphex(rsp[1], ==, 0x01);
    g_assert_cmphex(ldl_be_p(&rsp[2]), ==, PCRREAD_RESP_LEN);
    g_assert_cmphex(ldl_be_p(&rsp[6]), ==, 0);
    g_assert_cmphex(lduw_be_p(&rsp[PCRREAD_DIGEST_OFF - 2]), ==, SHA256_LEN);

    memcpy(digest, &rsp[PCRREAD_DIGEST_OFF], SHA256_LEN);
}

/*
 * What the locality 4 sequence leaves in PCR 17: the PCR reset to zeros,
 * then extended with the digest of the image.
 */
static void expected_pcr17(const unsigned char *image, size_t len,
                           unsigned char *expected)
{
    unsigned char zeros_and_digest[2 * SHA256_LEN] = { 0 };
    gsize digest_len = SHA256_LEN;
    GChecksum *sum;

    sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, image, len);
    g_checksum_get_digest(sum, &zeros_and_digest[SHA256_LEN], &digest_len);
    g_checksum_free(sum);
    g_assert_cmpuint(digest_len, ==, SHA256_LEN);

    digest_len = SHA256_LEN;
    sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, zeros_and_digest, sizeof(zeros_and_digest));
    g_checksum_get_digest(sum, expected, &digest_len);
    g_checksum_free(sum);
    g_assert_cmpuint(digest_len, ==, SHA256_LEN);
}

/* swtpm and QEMU with tpm-tis on it, started past TPM2_Startup */
static QTestState *drtm_qtest_start(const char *tpm_path, const char *devices,
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
        "-tpmdev emulator,id=tpm0,chardev=chr %s",
        (*addr)->u.q_unix.path, devices);
    s = qtest_init(args);
    g_free(args);

    /* Before TPM2_Startup the sequence would land in PCR 0 as an H-CRTM. */
    tpm_util_startup(s, tpm_tis_transfer);
    return s;
}

static void drtm_qtest_stop(QTestState *s, GPid swtpm_pid, SocketAddress *addr)
{
    qtest_quit(s);
    tpm_util_swtpm_kill(swtpm_pid);

    g_unlink(addr->u.q_unix.path);
    qapi_free_SocketAddress(addr);
}

static void fill_image(unsigned char *image, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        image[i] = (unsigned char)(i * 7 + 3);
    }
}

/*
 * The sequence through the locality 4 registers: any value starts and
 * ends it, the image goes through HASH_DATA in whatever widths the
 * writer picks.
 */
static void hash_through_registers(QTestState *s, const unsigned char *image,
                                   size_t len)
{
    size_t off = 0;

    qtest_writeb(s, TIS_REG(4, TPM_TIS_REG_HASH_START), 0);
    while (len - off >= 4) {
        qtest_writel(s, TIS_REG(4, TPM_TIS_REG_HASH_DATA),
                     ldl_le_p(image + off));
        off += 4;
    }
    while (off < len) {
        qtest_writeb(s, TIS_REG(4, TPM_TIS_REG_HASH_DATA), image[off++]);
    }
    qtest_writeb(s, TIS_REG(4, TPM_TIS_REG_HASH_END), 0);
}

static void tpm_drtm_swtpm_test(const void *data)
{
    const char *tpm_path = data;
    unsigned char image[IMAGE_LENGTH];
    unsigned char expected[SHA256_LEN];
    unsigned char digest[SHA256_LEN];
    unsigned char before[SHA256_LEN];
    uint32_t access_before, access_after, sts_before, sts_after;
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;
    QDict *rsp;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = drtm_qtest_start(tpm_path, "-device tpm-tis,tpmdev=tpm0 "
                         "-device amd-drtm-platform", &swtpm_pid, &addr);

    fill_image(image, sizeof(image));
    qtest_memwrite(s, IMAGE_BASE, image, sizeof(image));
    expected_pcr17(image, sizeof(image), expected);

    /* Without locality4=on the registers are the hardware-only ones */
    pcr17_read(s, before);
    hash_through_registers(s, image, sizeof(image));
    pcr17_read(s, digest);
    g_assert_cmpmem(digest, sizeof(digest), before, sizeof(before));

    access_before = qtest_readb(s, TIS_REG(0, TPM_TIS_REG_ACCESS));
    sts_before = qtest_readl(s, TIS_REG(0, TPM_TIS_REG_STS));

    qtest_qmp_assert_success(s,
        "{ 'execute': 'x-amd-drtm-launch', "
        "'arguments': { 'base': %" PRIu64 ", 'length': %d } }",
        (uint64_t)IMAGE_BASE, IMAGE_LENGTH);

    rsp = qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-amd-drtm' }");
    g_assert_true(qdict_get_bool(rsp, "launched"));
    qobject_unref(rsp);

    /*
     * The interface only observes the transfer. The one bit that changes
     * is tpmEstablishment, cleared once the TPM has seen a launch.
     */
    access_after = qtest_readb(s, TIS_REG(0, TPM_TIS_REG_ACCESS));
    sts_after = qtest_readl(s, TIS_REG(0, TPM_TIS_REG_STS));
    g_assert_cmphex(access_after & ~TPM_TIS_ACCESS_TPM_ESTABLISHMENT, ==,
                    access_before & ~TPM_TIS_ACCESS_TPM_ESTABLISHMENT);
    g_assert_cmphex(access_after & TPM_TIS_ACCESS_TPM_ESTABLISHMENT, ==, 0);
    g_assert_cmphex(sts_after, ==, sts_before);

    pcr17_read(s, digest);
    g_assert_cmpmem(digest, sizeof(digest), expected, sizeof(expected));

    drtm_qtest_stop(s, swtpm_pid, addr);
}

/* The same measurement driven by software through the locality 4 registers */
static void tpm_drtm_locality4_test(const void *data)
{
    const char *tpm_path = data;
    unsigned char image[IMAGE_LENGTH];
    unsigned char expected[SHA256_LEN];
    unsigned char digest[SHA256_LEN];
    SocketAddress *addr = NULL;
    GPid swtpm_pid;
    QTestState *s;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    s = drtm_qtest_start(tpm_path, "-device tpm-tis,tpmdev=tpm0,locality4=on",
                         &swtpm_pid, &addr);

    fill_image(image, sizeof(image));
    expected_pcr17(image, sizeof(image), expected);

    g_assert_cmphex(qtest_readb(s, TIS_REG(0, TPM_TIS_REG_ACCESS)) &
                    TPM_TIS_ACCESS_TPM_ESTABLISHMENT, ==,
                    TPM_TIS_ACCESS_TPM_ESTABLISHMENT);

    /* Data before HASH_START is dropped, so the digest covers the image */
    qtest_writel(s, TIS_REG(4, TPM_TIS_REG_HASH_DATA), 0xdeadbeef);
    hash_through_registers(s, image, sizeof(image));

    g_assert_cmphex(qtest_readb(s, TIS_REG(0, TPM_TIS_REG_ACCESS)) &
                    TPM_TIS_ACCESS_TPM_ESTABLISHMENT, ==, 0);
    pcr17_read(s, digest);
    g_assert_cmpmem(digest, sizeof(digest), expected, sizeof(expected));

    drtm_qtest_stop(s, swtpm_pid, addr);
}

int main(int argc, char **argv)
{
    char *tpm_path;
    int ret;

    tpm_path = g_dir_make_tmp("qemu-tpm-drtm-swtpm-test.XXXXXX", NULL);

    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);

    qtest_add_data_func("/tpm/drtm-swtpm/test", tpm_path,
                        tpm_drtm_swtpm_test);
    qtest_add_data_func("/tpm/drtm-swtpm/locality4", tpm_path,
                        tpm_drtm_locality4_test);
    ret = g_test_run();

    tpm_util_rmdir(tpm_path);
    g_free(tpm_path);

    return ret;
}
