/*
 * Ownership seam of the TPM backend's single command slot
 *
 * Regression test for the device-originated request path
 * (TPMBackendCmd::no_frontend_notify, see
 * tpm_backend_request_completed() in backends/tpm/tpm_backend.c):
 *
 *  - an internal (device-originated) request must complete without
 *    notifying the TPM frontend at all, and the response must land
 *    in the caller's own buffer;
 *  - a second submission while a request is in flight must be
 *    dropped, and the in-flight request's response slot must stay
 *    untouched;
 *  - a normal frontend-originated request issued after internal
 *    traffic must still notify the frontend exactly once, with the
 *    backend's completion status;
 *  - a failing request releases the slot either way, and only the
 *    frontend-originated one reports the failure to the frontend.
 *
 * The seam is tested in-process against the real tpm_backend.c with
 * a mock backend (canned response, no TPM transport) and a mock
 * TPMIf that counts request_completed() calls, so no TPM
 * implementation or chardev is needed.
 *
 * Copyright (C) 2026 Michał Kopeć <michal@local>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "system/tpm_backend.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qapi/error.h"

/*
 * Canned response: the 10-byte TPM2 error header the fake swtpm
 * emulator (tests/qtest/tpm-emu.c) sends for every command:
 * tag TPM2_ST_NO_SESSIONS (0x8001), size 10, TPM_RC_FAILURE (0x101),
 * all big-endian.
 */
static const uint8_t mock_tpm_response[10] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01
};

/* ---------------- mock TPM backend ---------------- */

/* Set by the error-path tests to make handle_request fail. */
static bool mock_tpm_fail_request;

static void mock_tpm_handle_request(TPMBackend *s, TPMBackendCmd *cmd,
                                    Error **errp)
{
    /*
     * Runs on a thread-pool worker, so report failures through @errp
     * (the worker turns that into a -1 completion status) rather than
     * aborting the process from a non-main thread.
     */
    if (mock_tpm_fail_request) {
        error_setg(errp, "mock TPM backend failure");
        return;
    }
    if (cmd->out_len < sizeof(mock_tpm_response)) {
        error_setg(errp, "mock TPM response buffer too small");
        return;
    }
    memcpy(cmd->out, mock_tpm_response, sizeof(mock_tpm_response));
}

static TPMVersion mock_tpm_get_version(TPMBackend *s)
{
    return TPM_VERSION_2_0;
}

static size_t mock_tpm_get_buffer_size(TPMBackend *s)
{
    return sizeof(mock_tpm_response);
}

static void mock_tpm_backend_class_init(ObjectClass *oc, const void *data)
{
    TPMBackendClass *k = TPM_BACKEND_CLASS(oc);

    k->type = TPM_TYPE_EMULATOR;
    k->handle_request = mock_tpm_handle_request;
    k->get_tpm_version = mock_tpm_get_version;
    k->get_buffer_size = mock_tpm_get_buffer_size;
}

static const TypeInfo mock_tpm_backend_info = {
    .name = "mock-tpm-backend",
    .parent = TYPE_TPM_BACKEND,
    .class_init = mock_tpm_backend_class_init,
};

/* ---------------- mock TPM frontend (TPMIf) ---------------- */

static int mock_tpm_notify_count;
static int mock_tpm_last_ret;

static void mock_tpm_request_completed(TPMIf *ti, int ret)
{
    mock_tpm_notify_count++;
    mock_tpm_last_ret = ret;
}

static void mock_tpm_if_class_init(ObjectClass *oc, const void *data)
{
    TPMIfClass *tc = TPM_IF_CLASS(oc);

    tc->model = TPM_MODEL_TPM_TIS;
    tc->request_completed = mock_tpm_request_completed;
}

/*
 * A plain object implementing TPMIf is enough: the backend only ever
 * casts it to TPMIf and calls request_completed(), so no device
 * infrastructure is needed.
 */
typedef struct MockTPMIf {
    Object parent;
} MockTPMIf;

static const TypeInfo mock_tpm_if_info = {
    .name = "mock-tpm-if",
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(MockTPMIf),
    .class_init = mock_tpm_if_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    },
};

/* ---------------- helpers ---------------- */

static TPMBackend *mock_tpm_backend_create(TPMIf **out_tif)
{
    TPMBackend *be = TPM_BACKEND(object_new("mock-tpm-backend"));
    TPMIf *ti = TPM_IF(object_new("mock-tpm-if"));

    *out_tif = ti;
    tpm_backend_init(be, ti, &error_abort);
    return be;
}

/*
 * The backend stores the caller's TPMBackendCmd pointer and reads it
 * from the worker thread, so the struct must outlive the
 * deliver/finish_sync pair (same contract as
 * intel_txt_tpm_send()).  Build it in the test body.
 */
static void mock_tpm_reset_state(void)
{
    mock_tpm_notify_count = 0;
    mock_tpm_last_ret = INT_MIN;
    mock_tpm_fail_request = false;
}

static void mock_tpm_cmd_init(TPMBackendCmd *cmd, uint8_t *out,
                              uint32_t out_len, bool no_frontend_notify)
{
    *cmd = (TPMBackendCmd) {
        .locty = 0,
        .in = NULL,
        .in_len = 0,
        .out = out,
        .out_len = out_len,
        .no_frontend_notify = no_frontend_notify,
    };
}

/* ---------------- tests ---------------- */

static void test_internal_request_notifies_nothing(void)
{
    TPMIf *ti;
    TPMBackend *be = mock_tpm_backend_create(&ti);
    uint8_t rsp[32] = { 0 };

    TPMBackendCmd cmd;

    BQL_LOCK_GUARD();
    mock_tpm_reset_state();

    g_assert(!tpm_backend_request_pending(be));

    mock_tpm_cmd_init(&cmd, rsp, sizeof(rsp), true);
    tpm_backend_deliver_request(be, &cmd);
    g_assert(tpm_backend_request_pending(be));
    tpm_backend_finish_sync(be);
    g_assert(!tpm_backend_request_pending(be));

    /* The response landed in the device's own buffer ... */
    g_assert_cmpmem(rsp, 10, mock_tpm_response, sizeof(mock_tpm_response));
    /* ... and the frontend was never told about the command. */
    g_assert_cmpint(mock_tpm_notify_count, ==, 0);

    object_unref(OBJECT(ti));
    object_unref(OBJECT(be));
}

static void test_second_submission_is_dropped(void)
{
    TPMIf *ti;
    TPMBackend *be = mock_tpm_backend_create(&ti);
    uint8_t rsp1[32] = { 0 }, rsp2[32] = { 0 };
    TPMBackendCmd cmd1, cmd2;
    size_t i;

    BQL_LOCK_GUARD();
    mock_tpm_reset_state();

    mock_tpm_cmd_init(&cmd1, rsp1, sizeof(rsp1), true);
    tpm_backend_deliver_request(be, &cmd1);
    /*
     * The backend owns the slot now; this second submission must be
     * dropped (it logs "There is a TPM request pending").
     */
    mock_tpm_cmd_init(&cmd2, rsp2, sizeof(rsp2), true);
    tpm_backend_deliver_request(be, &cmd2);
    g_assert(tpm_backend_request_pending(be));
    tpm_backend_finish_sync(be);
    g_assert(!tpm_backend_request_pending(be));

    g_assert_cmpmem(rsp1, 10, mock_tpm_response, sizeof(mock_tpm_response));
    for (i = 0; i < sizeof(rsp2); i++) {
        g_assert_cmpuint(rsp2[i], ==, 0);
    }
    g_assert_cmpint(mock_tpm_notify_count, ==, 0);

    object_unref(OBJECT(ti));
    object_unref(OBJECT(be));
}

static void test_frontend_request_after_internal(void)
{
    TPMIf *ti;
    TPMBackend *be = mock_tpm_backend_create(&ti);
    uint8_t rsp_int[32] = { 0 }, rsp_fe[32] = { 0 };
    TPMBackendCmd cmd_int, cmd_fe;

    BQL_LOCK_GUARD();
    mock_tpm_reset_state();

    /* Internal request first: no frontend notification. */
    mock_tpm_cmd_init(&cmd_int, rsp_int, sizeof(rsp_int), true);
    tpm_backend_deliver_request(be, &cmd_int);
    tpm_backend_finish_sync(be);
    g_assert_cmpint(mock_tpm_notify_count, ==, 0);

    /*
     * A normal frontend-originated request issued afterwards must
     * still complete through the frontend exactly once.
     */
    mock_tpm_cmd_init(&cmd_fe, rsp_fe, sizeof(rsp_fe), false);
    tpm_backend_deliver_request(be, &cmd_fe);
    tpm_backend_finish_sync(be);
    g_assert_cmpmem(rsp_fe, 10, mock_tpm_response, sizeof(mock_tpm_response));
    g_assert_cmpint(mock_tpm_notify_count, ==, 1);
    /* ... and the backend's success status reached it. */
    g_assert_cmpint(mock_tpm_last_ret, ==, 0);

    object_unref(OBJECT(ti));
    object_unref(OBJECT(be));
}

/*
 * A backend-side failure must reach the frontend as a -1 completion:
 * dropping or masking that status would leave the frontend waiting on
 * a response that never comes.
 */
static void test_frontend_error_is_propagated(void)
{
    TPMIf *ti;
    TPMBackend *be = mock_tpm_backend_create(&ti);
    uint8_t rsp[32] = { 0 };
    TPMBackendCmd cmd;

    BQL_LOCK_GUARD();
    mock_tpm_reset_state();
    mock_tpm_fail_request = true;

    mock_tpm_cmd_init(&cmd, rsp, sizeof(rsp), false);
    tpm_backend_deliver_request(be, &cmd);
    tpm_backend_finish_sync(be);

    g_assert_cmpint(mock_tpm_notify_count, ==, 1);
    g_assert_cmpint(mock_tpm_last_ret, ==, -1);
    /* The slot is released on the error path too. */
    g_assert(!tpm_backend_request_pending(be));

    object_unref(OBJECT(ti));
    object_unref(OBJECT(be));
}

/*
 * The same failure on a device-originated command stays invisible to
 * the frontend: it must not learn about a command it never issued,
 * not even as an error.
 */
static void test_internal_error_notifies_nothing(void)
{
    TPMIf *ti;
    TPMBackend *be = mock_tpm_backend_create(&ti);
    uint8_t rsp[32] = { 0 };
    TPMBackendCmd cmd;

    BQL_LOCK_GUARD();
    mock_tpm_reset_state();
    mock_tpm_fail_request = true;

    mock_tpm_cmd_init(&cmd, rsp, sizeof(rsp), true);
    tpm_backend_deliver_request(be, &cmd);
    tpm_backend_finish_sync(be);

    g_assert_cmpint(mock_tpm_notify_count, ==, 0);
    g_assert(!tpm_backend_request_pending(be));

    object_unref(OBJECT(ti));
    object_unref(OBJECT(be));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    module_call_init(MODULE_INIT_QOM);
    type_register_static(&mock_tpm_backend_info);
    type_register_static(&mock_tpm_if_info);
    qemu_init_main_loop(&error_abort);

    g_test_add_func("/tpm-ownership/internal-request-notifies-nothing",
                    test_internal_request_notifies_nothing);
    g_test_add_func("/tpm-ownership/second-submission-is-dropped",
                    test_second_submission_is_dropped);
    g_test_add_func("/tpm-ownership/frontend-request-after-internal",
                    test_frontend_request_after_internal);
    g_test_add_func("/tpm-ownership/frontend-error-is-propagated",
                    test_frontend_error_is_propagated);
    g_test_add_func("/tpm-ownership/internal-error-notifies-nothing",
                    test_internal_error_notifies_nothing);

    return g_test_run();
}
