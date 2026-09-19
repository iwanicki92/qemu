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

static void tpm_drtm_swtpm_test(const void *data)
{
    const char *tpm_path = data;
    unsigned char image[IMAGE_LENGTH];
    unsigned char expected[SHA256_LEN];
    unsigned char digest[SHA256_LEN];
    uint32_t access_before, access_after, sts_before, sts_after;
    SocketAddress *addr = NULL;
    GError *error = NULL;
    GPid swtpm_pid;
    gboolean succ;
    QTestState *s;
    QDict *rsp;
    char *args;
    size_t i;

    if (!tpm_util_swtpm_has_tpm2()) {
        g_test_skip("swtpm not in PATH or missing --tpm2 support");
        return;
    }

    succ = tpm_util_swtpm_start(tpm_path, &swtpm_pid, &addr, &error);
    g_assert_true(succ);

    args = g_strdup_printf(
        "-machine q35 "
        "-chardev socket,id=chr,path=%s "
        "-tpmdev emulator,id=tpm0,chardev=chr "
        "-device tpm-tis,tpmdev=tpm0 "
        "-device amd-drtm-platform",
        addr->u.q_unix.path);
    s = qtest_init(args);
    g_free(args);

    /* Before TPM2_Startup the sequence would land in PCR 0 as an H-CRTM. */
    tpm_util_startup(s, tpm_tis_transfer);

    for (i = 0; i < sizeof(image); i++) {
        image[i] = (unsigned char)(i * 7 + 3);
    }
    qtest_memwrite(s, IMAGE_BASE, image, sizeof(image));
    expected_pcr17(image, sizeof(image), expected);

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

    qtest_quit(s);
    tpm_util_swtpm_kill(swtpm_pid);

    g_unlink(addr->u.q_unix.path);
    qapi_free_SocketAddress(addr);
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
    ret = g_test_run();

    tpm_util_rmdir(tpm_path);
    g_free(tpm_path);

    return ret;
}
