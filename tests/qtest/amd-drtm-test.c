/*
 * QTest for the AMD dynamic launch platform object
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"

#define SLB_BASE    0x200000
#define SLB_LENGTH  0x1234

static QDict *query_amd_drtm(QTestState *s)
{
    return qtest_qmp_assert_success_ref(s, "{ 'execute': 'query-amd-drtm' }");
}

static void check_cleared(QDict *info)
{
    g_assert_false(qdict_get_bool(info, "launched"));
    g_assert_cmpuint(qdict_get_int(info, "slb-base"), ==, 0);
    g_assert_cmpuint(qdict_get_int(info, "slb-length"), ==, 0);
    g_assert_false(qdict_get_bool(info, "sl-dev"));
    g_assert_cmpstr(qdict_get_str(info, "hash"), ==, "none");
    g_assert_cmpuint(qlist_size(qdict_get_qlist(info, "dma-blocks")), ==, 0);
}

static void test_launch(void)
{
    QTestState *s = qtest_init("-M q35 -device amd-drtm-platform");
    uint8_t image[SLB_LENGTH];
    QDict *info, *block;
    QList *blocks;
    int i;

    info = query_amd_drtm(s);
    check_cleared(info);
    qobject_unref(info);

    for (i = 0; i < SLB_LENGTH; i++) {
        image[i] = i;
    }
    qtest_memwrite(s, SLB_BASE, image, sizeof(image));

    qtest_qmp_assert_success(s, "{ 'execute': 'x-amd-drtm-launch', "
                             "'arguments': { 'base': %d, 'length': %d } }",
                             SLB_BASE, SLB_LENGTH);

    info = query_amd_drtm(s);
    g_assert_true(qdict_get_bool(info, "launched"));
    g_assert_cmpuint(qdict_get_int(info, "slb-base"), ==, SLB_BASE);
    g_assert_cmpuint(qdict_get_int(info, "slb-length"), ==, SLB_LENGTH);
    g_assert_true(qdict_get_bool(info, "sl-dev"));
    /* no TPM on this command line */
    g_assert_cmpstr(qdict_get_str(info, "hash"), ==, "unsupported");
    blocks = qdict_get_qlist(info, "dma-blocks");
    g_assert_cmpuint(qlist_size(blocks), ==, 1);
    block = qobject_to(QDict, qlist_peek(blocks));
    g_assert_cmpstr(qdict_get_str(block, "name"), ==, "sl_dev");
    g_assert_cmpuint(qdict_get_int(block, "base"), ==, SLB_BASE);
    g_assert_cmpuint(qdict_get_int(block, "len"), ==, 0x10000);
    qobject_unref(info);

    qtest_system_reset(s);

    info = query_amd_drtm(s);
    check_cleared(info);
    qobject_unref(info);

    qtest_quit(s);
}

static void test_second_instance_rejected(void)
{
    QTestState *s = qtest_init_ext(NULL, "-M q35 -device amd-drtm-platform "
                                   "-device amd-drtm-platform", NULL, false);

    qtest_set_expected_status(s, 1);
    qtest_wait_qemu(s);
    qtest_quit(s);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    if (!qtest_has_machine("q35")) {
        g_test_skip("q35 machine not available");
        return g_test_run();
    }

    qtest_add_func("/q35/amd-drtm/launch", test_launch);
    qtest_add_func("/q35/amd-drtm/second-instance-rejected",
                   test_second_instance_rejected);
    return g_test_run();
}
