/*
 * QTest testcase for the AMD FCH PMIO window's AcpiPmTmrBlk
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#define FCH_PMIO            0xfed80300
#define ACPI_PM_TMR_BLK     (FCH_PMIO + 0x64)

/* The ICH9 LPC bridge at 0:1f.0 and its PMBASE register */
#define LPC_PMBASE          (0x80000000 | (0x1f << 11) | 0x40)

static void set_pmbase(QTestState *qts, uint32_t pmbase)
{
    qtest_outl(qts, 0xcf8, LPC_PMBASE);
    qtest_outl(qts, 0xcfc, pmbase | 1);
}

/* The PM timer's port follows PMBASE, 0 while firmware has not set one */
static void test_pm_timer(void)
{
    QTestState *qts = qtest_init("-machine q35 -device amd-fch-pmio");

    set_pmbase(qts, 0);
    g_assert_cmphex(qtest_readw(qts, ACPI_PM_TMR_BLK), ==, 0);
    set_pmbase(qts, 0x600);
    g_assert_cmphex(qtest_readw(qts, ACPI_PM_TMR_BLK), ==, 0x608);
    g_assert_cmphex(qtest_readb(qts, ACPI_PM_TMR_BLK + 1), ==, 0x06);
    g_assert_cmphex(qtest_readl(qts, ACPI_PM_TMR_BLK), ==, 0x608);

    /* Writes do not move it */
    qtest_writew(qts, ACPI_PM_TMR_BLK, 0x1234);
    g_assert_cmphex(qtest_readw(qts, ACPI_PM_TMR_BLK), ==, 0x608);
    qtest_quit(qts);
}

/* Every other byte is storage, cleared by a reset */
static void test_storage(void)
{
    QTestState *qts = qtest_init("-machine q35 -device amd-fch-pmio");

    qtest_writel(qts, FCH_PMIO + 4, 0x5a5aa5a5);
    g_assert_cmphex(qtest_readl(qts, FCH_PMIO + 4), ==, 0x5a5aa5a5);
    g_assert_cmphex(qtest_readb(qts, FCH_PMIO + 7), ==, 0x5a);
    qtest_system_reset(qts);
    g_assert_cmphex(qtest_readl(qts, FCH_PMIO + 4), ==, 0);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/amd-fch-pmio/pm-timer", test_pm_timer);
    qtest_add_func("/amd-fch-pmio/storage", test_storage);
    return g_test_run();
}
