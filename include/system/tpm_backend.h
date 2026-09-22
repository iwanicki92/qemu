/*
 * QEMU TPM Backend
 *
 * Copyright IBM, Corp. 2013
 *
 * Authors:
 *  Stefan Berger  <stefanb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef TPM_BACKEND_H
#define TPM_BACKEND_H

#include "qom/object.h"
#include "qemu/option.h"
#include "system/tpm.h"
#include "qapi/error.h"

#ifdef CONFIG_TPM

#define TYPE_TPM_BACKEND "tpm-backend"
OBJECT_DECLARE_TYPE(TPMBackend, TPMBackendClass,
                    TPM_BACKEND)


typedef struct TPMBackendCmd {
    uint8_t locty;
    const uint8_t *in;
    uint32_t in_len;
    uint8_t *out;
    uint32_t out_len;
    bool selftest_done;
    /*
     * Device-originated command: do not notify the TPM frontend on
     * completion.  The response bytes went to the device's own
     * buffer, so running the frontend's request_completed would
     * corrupt its state machine and raise an interrupt for a
     * command the guest never sent (hw/i386/intel_txt.c).
     */
    bool no_frontend_notify;
} TPMBackendCmd;

struct TPMBackend {
    Object parent;

    /*< protected >*/
    TPMIf *tpmif;
    bool opened;
    bool had_startup_error;
    TPMBackendCmd *cmd;

    /* <public> */
    char *id;

    QLIST_ENTRY(TPMBackend) list;
};

struct TPMBackendClass {
    ObjectClass parent_class;

    enum TpmType type;
    const QemuOptDesc *opts;
    /* get a descriptive text of the backend to display to the user */
    const char *desc;

    TPMBackend *(*create)(QemuOpts *opts);

    /* start up the TPM on the backend - optional */
    int (*startup_tpm)(TPMBackend *t, size_t buffersize);

    /* optional */
    void (*reset)(TPMBackend *t);

    void (*cancel_cmd)(TPMBackend *t);

    /* optional */
    bool (*get_tpm_established_flag)(TPMBackend *t);

    /* optional */
    int (*reset_tpm_established_flag)(TPMBackend *t, uint8_t locty);

    TPMVersion (*get_tpm_version)(TPMBackend *t);

    size_t (*get_buffer_size)(TPMBackend *t);

    TpmTypeOptions *(*get_tpm_options)(TPMBackend *t);

    void (*handle_request)(TPMBackend *s, TPMBackendCmd *cmd, Error **errp);

    /*
     * Optional: the TIS _TPM_Hash_Start / _TPM_Hash_Data /
     * _TPM_Hash_End signal sequence, used to establish a DRTM.
     *
     * These are *signals*, not TPM commands, so they travel on the
     * backend's control channel rather than through a TPMBackendCmd.
     * hash_start resets the DRTM PCRs (17-22) and hash_end extends
     * PCR 17 with the hash of everything passed to hash_data --
     * something TPM2_PCR_Reset cannot do at any locality.
     *
     * @locty must be the DRTM locality (4).  Passing anything else
     * makes the whole sequence a silent no-op on at least swtpm: the
     * commands still succeed but no PCR changes, so callers must not
     * treat a zero return as proof that a measurement landed.
     */
    int (*hash_start)(TPMBackend *t, uint8_t locty, Error **errp);
    int (*hash_data)(TPMBackend *t, const uint8_t *data, size_t len,
                     Error **errp);
    int (*hash_end)(TPMBackend *t, Error **errp);
};

/**
 * tpm_backend_get_type:
 * @s: the backend
 *
 * Returns the TpmType of the backend.
 */
enum TpmType tpm_backend_get_type(TPMBackend *s);

/**
 * tpm_backend_init:
 * @s: the backend to initialized
 * @tpmif: TPM interface
 * @datacb: callback for sending data to frontend
 * @errp: a pointer to return the #Error object if an error occurs.
 *
 * Initialize the backend with the given variables.
 *
 * Returns 0 on success.
 */
int tpm_backend_init(TPMBackend *s, TPMIf *tpmif, Error **errp);

/**
 * tpm_backend_startup_tpm:
 * @s: the backend whose TPM support is to be started
 * @buffersize: the buffer size the TPM is supposed to use,
 *              0 to leave it as-is
 *
 * Returns 0 on success.
 */
int tpm_backend_startup_tpm(TPMBackend *s, size_t buffersize);

/**
 * tpm_backend_had_startup_error:
 * @s: the backend to query for a startup error
 *
 * Check whether the backend had an error during startup. Returns
 * false if no error occurred and the backend can be used, true
 * otherwise.
 */
bool tpm_backend_had_startup_error(TPMBackend *s);

/**
 * tpm_backend_deliver_request:
 * @s: the backend to send the request to
 * @cmd: the command to deliver
 *
 * Send a request to the backend. The backend will then send the request
 * to the TPM implementation.
 */
void tpm_backend_deliver_request(TPMBackend *s, TPMBackendCmd *cmd);

/**
 * tpm_backend_reset:
 * @s: the backend to reset
 *
 * Reset the backend into a well defined state with all previous errors
 * reset.
 */
void tpm_backend_reset(TPMBackend *s);

/**
 * tpm_backend_cancel_cmd:
 * @s: the backend
 *
 * Cancel any ongoing command being processed by the TPM implementation
 * on behalf of the QEMU guest.
 */
void tpm_backend_cancel_cmd(TPMBackend *s);

/**
 * tpm_backend_get_tpm_established_flag:
 * @s: the backend
 *
 * Get the TPM establishment flag. This function may be called very
 * frequently by the frontend since for example in the TIS implementation
 * this flag is part of a register.
 */
bool tpm_backend_get_tpm_established_flag(TPMBackend *s);

/**
 * tpm_backend_reset_tpm_established_flag:
 * @s: the backend
 * @locty: the locality number
 *
 * Reset the TPM establishment flag.
 */
int tpm_backend_reset_tpm_established_flag(TPMBackend *s, uint8_t locty);

/**
 * tpm_backend_get_tpm_version:
 * @s: the backend to call into
 *
 * Get the TPM Version that is emulated at the backend.
 *
 * Returns TPMVersion.
 */
TPMVersion tpm_backend_get_tpm_version(TPMBackend *s);

/**
 * tpm_backend_get_buffer_size:
 * @s: the backend to call into
 *
 * Get the TPM's buffer size.
 *
 * Returns buffer size.
 */
size_t tpm_backend_get_buffer_size(TPMBackend *s);

/**
 * tpm_backend_finish_sync:
 * @s: the backend to call into
 *
 * Finish the pending command synchronously (this will call aio_poll()
 * on qemu main AIOContext until it ends)
 */
void tpm_backend_finish_sync(TPMBackend *s);

/**
 * tpm_backend_query_tpm:
 * @s: the backend
 *
 * Query backend tpm info
 *
 * Returns newly allocated TPMInfo
 */
TPMInfo *tpm_backend_query_tpm(TPMBackend *s);

/**
 * tpm_backend_hash_sequence:
 * @s: the backend
 * @data: the bytes to measure
 * @len: length of @data; the backend chunks it as needed
 * @errp: a pointer to return the #Error object if an error occurs.
 *
 * Run a complete TIS _TPM_Hash_Start / _TPM_Hash_Data / _TPM_Hash_End
 * sequence over @data, establishing a DRTM.
 *
 * The sequence is transactional and is exposed as a single call on
 * purpose: there is no abort signal, so a caller that could stop
 * between phases would be able to leave the TPM in a
 * hash-in-progress state with no way out.  The DRTM locality is
 * likewise fixed internally rather than being a parameter, because
 * only locality 4 is meaningful and the wrong value turns the whole
 * sequence into a silent no-op on at least swtpm.
 *
 * Returns 0 on success, -1 on error (including a backend that does
 * not implement the sequence).
 */
int tpm_backend_hash_sequence(TPMBackend *s, const uint8_t *data, size_t len,
                              Error **errp);

/**
 * tpm_backend_has_hash_sequence:
 * @s: the backend
 *
 * Whether this backend implements the _TPM_Hash_* sequence at all.
 * Only the emulator backend does; the passthrough backend cannot,
 * because the signals are not expressible over the host TPM's
 * command interface.
 */
bool tpm_backend_has_hash_sequence(TPMBackend *s);

TPMBackend *qemu_find_tpm_be(const char *id);
TPMBackend *qemu_find_tpm_be_any(void);

#endif /* CONFIG_TPM */

#endif /* TPM_BACKEND_H */
