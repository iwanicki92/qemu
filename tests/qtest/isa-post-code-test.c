/*
 * QTest testcase for the POST code capture on ports 0x80 to 0x83
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

static char *start_and_write(void (*write)(QTestState *qts))
{
    g_autofree char *path = NULL;
    char *contents = NULL;
    QTestState *qts;
    int fd;

    fd = g_file_open_tmp("post-code-XXXXXX", &path, NULL);
    g_assert(fd >= 0);
    close(fd);
    qts = qtest_initf("-machine q35 -chardev file,id=post,path=%s "
                      "-device isa-post-code,chardev=post", path);
    write(qts);
    qtest_quit(qts);
    g_assert(g_file_get_contents(path, &contents, NULL, NULL));
    unlink(path);
    return contents;
}

/* A dword at 0x80 arrives whole, not as its low byte. */
static void write_dword(QTestState *qts)
{
    qtest_outl(qts, 0x80, 0xdead0002);
}

static void test_dword(void)
{
    g_autofree char *log = start_and_write(write_dword);

    g_assert_cmpstr(log, ==, "0x80 4 0xdead0002\n");
}

static void write_mixed(QTestState *qts)
{
    qtest_outb(qts, 0x80, 0x42);
    qtest_outw(qts, 0x80, 0x1001);
    qtest_outb(qts, 0x83, 0x7);
}

static void test_mixed(void)
{
    g_autofree char *log = start_and_write(write_mixed);

    g_assert_cmpstr(log, ==, "0x80 1 0x42\n0x80 2 0x1001\n0x83 1 0x07\n");
}

static void read_back(QTestState *qts)
{
    g_assert_cmphex(qtest_inb(qts, 0x80), ==, 0xff);
}

/* Reads are not logged and answer all ones. */
static void test_read(void)
{
    g_autofree char *log = start_and_write(read_back);

    g_assert_cmpstr(log, ==, "");
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/isa-post-code/dword", test_dword);
    qtest_add_func("/isa-post-code/mixed", test_mixed);
    qtest_add_func("/isa-post-code/read", test_read);
    return g_test_run();
}
