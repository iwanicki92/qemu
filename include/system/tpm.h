/*
 * Public TPM functions
 *
 * Copyright (C) 2011-2013 IBM Corporation
 *
 * Authors:
 *  Stefan Berger    <stefanb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_TPM_H
#define QEMU_TPM_H

#include "qapi/qapi-types-tpm.h"
#include "qom/object.h"

#ifdef CONFIG_TPM

int tpm_config_parse(QemuOptsList *opts_list, const char *optstr);
int tpm_init(void);
void tpm_cleanup(void);

typedef enum TPMVersion {
    TPM_VERSION_UNSPEC = 0,
    TPM_VERSION_1_2 = 1,
    TPM_VERSION_2_0 = 2,
} TPMVersion;

#define TYPE_TPM_IF "tpm-if"
typedef struct TPMIfClass TPMIfClass;
DECLARE_CLASS_CHECKERS(TPMIfClass, TPM_IF,
                       TYPE_TPM_IF)
#define TPM_IF(obj)                             \
    INTERFACE_CHECK(TPMIf, (obj), TYPE_TPM_IF)

typedef struct TPMIf TPMIf;

struct TPMIfClass {
    InterfaceClass parent_class;

    enum TpmModel model;
    void (*request_completed)(TPMIf *obj, int ret);
    enum TPMVersion (*get_version)(TPMIf *obj);
    bool ppi_enabled;
    /* optional: the locality 4 hash the processor sends at SKINIT */
    int (*hash_image)(TPMIf *obj, const uint8_t *data, size_t len);
    /*
     * optional: a command run for an agent beside the processor at its
     * own locality, and the localities such an agent keeps locked
     */
    int (*run_command)(TPMIf *obj, uint8_t locty, const uint8_t *in,
                       size_t in_len, uint8_t *out, size_t out_len);
    void (*set_locality_locks)(TPMIf *obj, uint8_t locked);
};

#define TYPE_TPM_TIS_ISA            "tpm-tis"
#define TYPE_TPM_TIS_SYSBUS         "tpm-tis-device"
#define TYPE_TPM_CRB                "tpm-crb"
#define TYPE_TPM_SPAPR              "tpm-spapr"
#define TYPE_TPM_TIS_I2C            "tpm-tis-i2c"

#define TPM_IS_TIS_ISA(chr)                         \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_TIS_ISA)
#define TPM_IS_TIS_SYSBUS(chr)                      \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_TIS_SYSBUS)
#define TPM_IS_CRB(chr)                             \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_CRB)
#define TPM_IS_SPAPR(chr)                           \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_SPAPR)
#define TPM_IS_TIS_I2C(chr)                      \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_TIS_I2C)

/* returns NULL unless there is exactly one TPM device */
static inline TPMIf *tpm_find(void)
{
    Object *obj = object_resolve_path_type("", TYPE_TPM_IF, NULL);

    return TPM_IF(obj);
}

static inline TPMVersion tpm_get_version(TPMIf *ti)
{
    if (!ti) {
        return TPM_VERSION_UNSPEC;
    }

    return TPM_IF_GET_CLASS(ti)->get_version(ti);
}

static inline bool tpm_ppi_enabled(TPMIf *ti)
{
    if (!ti) {
        return false;
    }
    return TPM_IF_GET_CLASS(ti)->ppi_enabled;
}

/*
 * Measure an image as the processor does at SKINIT: PCRs 17 to 22 reset,
 * PCR 17 extended with its digest. Returns 0, -ENOTSUP when the frontend or
 * its backend has no locality 4 path, or another negative errno.
 */
static inline int tpm_hash_image(TPMIf *ti, const uint8_t *data, size_t len)
{
    TPMIfClass *tic;

    if (!ti) {
        return -ENOTSUP;
    }
    tic = TPM_IF_GET_CLASS(ti);
    if (!tic->hash_image) {
        return -ENOTSUP;
    }
    return tic->hash_image(ti, data, len);
}

/*
 * Run a command for an agent beside the processor at its own locality, as
 * the PSP does at locality 3. Any guest command in flight finishes first,
 * the guest's active locality is seized, and the exchange runs in the
 * caller's thread, so only the main loop may call this. Returns 0 with the
 * response in @out, -ENOTSUP without such a path, or a negative errno.
 */
static inline int tpm_run_command(TPMIf *ti, uint8_t locty, const uint8_t *in,
                                  size_t in_len, uint8_t *out, size_t out_len)
{
    TPMIfClass *tic;

    if (!ti) {
        return -ENOTSUP;
    }
    tic = TPM_IF_GET_CLASS(ti);
    if (!tic->run_command) {
        return -ENOTSUP;
    }
    return tic->run_command(ti, locty, in, in_len, out, out_len);
}

/*
 * The localities a firmware agent keeps the processor out of, one bit per
 * locality: reads there answer all-ones and writes are dropped. Returns
 * false when the frontend has no such mask.
 */
static inline bool tpm_set_locality_locks(TPMIf *ti, uint8_t locked)
{
    TPMIfClass *tic;

    if (!ti) {
        return false;
    }
    tic = TPM_IF_GET_CLASS(ti);
    if (!tic->set_locality_locks) {
        return false;
    }
    tic->set_locality_locks(ti, locked);
    return true;
}

#else /* CONFIG_TPM */

#define tpm_init()  (0)
#define tpm_cleanup()

/* needed for an alignment check in non-tpm code */
static inline Object *TPM_IS_CRB(Object *obj)
{
     return NULL;
}

#endif /* CONFIG_TPM */

#endif /* QEMU_TPM_H */
