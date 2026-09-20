/*
 * AMD Secure Processor
 *
 * A PCI function answering with an AMD Secure Processor's vendor and device
 * ID, its C2PMSG mailbox registers, and the second window an ASPT declares
 * for them. With drtm-service=on the DRTM service AMD's publication 58453
 * specifies answers behind the mailbox, as far as the TrenchBoot fork
 * drives it. Without it reads answer and writes are dropped.
 *
 * Copyright (c) 2026 iwanicki92 <iwanicki92@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/misc/amd_psp.h"
#include "crypto/akcipher.h"
#include "crypto/hash.h"
#include "hw/core/qdev-properties.h"
#include "hw/i386/amd_drtm.h"
#include "qapi/error.h"
#include "qemu/bswap.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "system/address-spaces.h"
#include "system/tpm.h"
#include "trace.h"

/*
 * The SL header (SKL's head.S) and the signature block behind the
 * measured part (58453, appendix B): the FW_SIG_HEADER, whose header
 * version field holds the tag, the signature and the key token.
 */
#define SL_HDR_MEASURED_LENGTH      0x02
#define SL_HDR_SOC_FLAG             0x1c
#define SIG_HDR_LEN                 0x100
#define SIG_HDR_TAG                 0x10
#define SIG_HDR_SIZE_FW_SIGNED      0x14
#define SIG_HDR_SEC_PATCH_LEVEL     0x4c
#define SIG_LEN                     0x200
#define TOKEN_LEN                   0x440
#define SIG_TAG                     "$AS1"

/*
 * The key token: the sizes in bits, then the exponent and the modulus,
 * each little-endian in a 512-byte field. The signature is RSA-PSS over
 * the first SizeFWSigned bytes with SHA-384, MGF1 and a salt as long as
 * the hash (RFC 8017), little-endian too.
 */
#define KEY_HDR_EXP_BITS            56
#define KEY_HDR_MOD_BITS            60
#define KEY_EXP_OFF                 64
#define KEY_MOD_OFF                 576
#define KEY_PART_LEN                512
#define SHA384_LEN                  48
#define PSS_SALT_LEN                SHA384_LEN
#define PSS_TRAILER                 0xbc

/*
 * The marker EXTEND_OSSL_DIGEST records after the range's digest, as the
 * board's event log shows it: the EV_TYPE_AMD_SL_SEPARATOR event carries
 * the five bytes "AMDSL", where 58453 prints 'SKL.'.
 */
#define OSSL_MARKER                 "AMDSL"
#define OSSL_MARKER_LEN             5
#define OSSL_CHUNK                  0x10000

/*
 * The event log's header, as the board's log has it: an EV_NO_ACTION
 * event in PCR 0 with a zero SHA-1 digest carrying the Spec ID Event03
 * structure, TCG2 version 2.0, one algorithm, SHA-256.
 */
static const uint8_t tcg_log_header[] = {
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x00, 0x00, 0x00,
    'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0',
    '3', 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x20, 0x00, 0x00,
};

/* A TCG_PCR_EVENT2 with one SHA-256 digest, before its event data */
#define TCG_EVENT2_OVERHEAD         (12 + 2 + SHA256_LEN + 4)

/* The stepping is masked when the SOC flag list is compared */
#define CPUID_STEPPING_MASK         0xf

#define SHA256_LEN                  32

/* What the service says to the TPM, at locality 3 */
#define PSP_TPM_LOCALITY            3
#define TPM2_ST_NO_SESSIONS         0x8001
#define TPM2_ST_SESSIONS            0x8002
#define TPM2_CC_PCR_EXTEND          0x182
#define TPM2_CC_PCR_READ            0x17e
#define TPM2_RS_PW                  0x40000009
#define TPM2_ALG_SHA256             0x000b
#define TPM2_RSP_CODE_OFF           6
#define TPM2_PCR_READ_RSP_LEN       62
#define TPM2_PCR_READ_DIGEST_OFF    30

/* SHA-256 and SHA-384 are always there, through glib when no library is */
static void amd_psp_hash(QCryptoHashAlgo alg, const void *data, size_t len,
                         uint8_t *digest, size_t digest_len)
{
    if (qcrypto_hash_bytes(alg, data, len, &digest, &digest_len,
                           &error_abort) < 0) {
        g_assert_not_reached();
    }
}

static void amd_psp_sha256(const void *data, size_t len, uint8_t *digest)
{
    amd_psp_hash(QCRYPTO_HASH_ALGO_SHA256, data, len, digest, SHA256_LEN);
}

static void amd_psp_sha384(const void *data, size_t len, uint8_t *digest)
{
    amd_psp_hash(QCRYPTO_HASH_ALGO_SHA384, data, len, digest, SHA384_LEN);
}

static const char *amd_psp_hex(const uint8_t *digest, char *out)
{
    static const char hex[] = "0123456789abcdef";
    unsigned i;

    for (i = 0; i < SHA256_LEN; i++) {
        out[2 * i] = hex[digest[i] >> 4];
        out[2 * i + 1] = hex[digest[i] & 0xf];
    }
    out[2 * SHA256_LEN] = 0;
    return out;
}

/* A command to the TPM and its response code, -1 when nothing came back */
static int amd_psp_tpm_run(AmdPspState *s, uint8_t *cmd, size_t len,
                           uint8_t *rsp, size_t rsp_len)
{
    int ret;

    stw_be_p(cmd + 2, 0);
    stl_be_p(cmd + 2, len);
    ret = tpm_run_command(s->tpm, PSP_TPM_LOCALITY, cmd, len, rsp, rsp_len);
    if (ret < 0) {
        return ret;
    }
    if (ldl_be_p(rsp + 2) < TPM2_RSP_CODE_OFF + 4 ||
        ldl_be_p(rsp + TPM2_RSP_CODE_OFF) != 0) {
        return -EIO;
    }
    return 0;
}

static int amd_psp_pcr_read(AmdPspState *s, unsigned pcr, uint8_t *digest)
{
    uint8_t cmd[20] = { 0 };
    uint8_t rsp[TPM2_PCR_READ_RSP_LEN + 64];
    char hex[2 * SHA256_LEN + 1];
    int ret;

    stw_be_p(cmd, TPM2_ST_NO_SESSIONS);
    stl_be_p(cmd + 6, TPM2_CC_PCR_READ);
    stl_be_p(cmd + 10, 1);
    stw_be_p(cmd + 14, TPM2_ALG_SHA256);
    cmd[16] = 3;
    cmd[17 + pcr / 8] = 1 << (pcr % 8);
    ret = amd_psp_tpm_run(s, cmd, sizeof(cmd), rsp, sizeof(rsp));
    if (ret < 0) {
        return ret;
    }
    if (ldl_be_p(rsp + 2) != TPM2_PCR_READ_RSP_LEN) {
        return -EIO;
    }
    memcpy(digest, rsp + TPM2_PCR_READ_DIGEST_OFF, SHA256_LEN);
    trace_amd_psp_drtm_pcr_read(pcr, amd_psp_hex(digest, hex));
    return 0;
}

static int amd_psp_pcr_extend(AmdPspState *s, unsigned pcr,
                              const uint8_t *digest)
{
    uint8_t cmd[65] = { 0 };
    uint8_t rsp[64];
    char hex[2 * SHA256_LEN + 1];

    stw_be_p(cmd, TPM2_ST_SESSIONS);
    stl_be_p(cmd + 6, TPM2_CC_PCR_EXTEND);
    stl_be_p(cmd + 10, pcr);
    stl_be_p(cmd + 14, 9);
    stl_be_p(cmd + 18, TPM2_RS_PW);
    stl_be_p(cmd + 27, 1);
    stw_be_p(cmd + 31, TPM2_ALG_SHA256);
    memcpy(cmd + 33, digest, SHA256_LEN);
    trace_amd_psp_drtm_pcr_extend(pcr, amd_psp_hex(digest, hex));
    return amd_psp_tpm_run(s, cmd, sizeof(cmd), rsp, sizeof(rsp));
}

static void amd_psp_log_write(AmdPspState *s, uint32_t off, const void *buf,
                              size_t len)
{
    memcpy((uint8_t *)memory_region_get_ram_ptr(&s->tcg_log) + off, buf, len);
    memory_region_set_dirty(&s->tcg_log, off, len);
}

static void amd_psp_log_clear(AmdPspState *s)
{
    if (s->tcg_log_len) {
        memset(memory_region_get_ram_ptr(&s->tcg_log), 0, s->tcg_log_len);
        memory_region_set_dirty(&s->tcg_log, 0, s->tcg_log_len);
    }
    s->tcg_log_len = 0;
    s->tcg_log_full = false;
}

/* One event appended to the log, the header first when the log is empty */
static void amd_psp_log_event(AmdPspState *s, unsigned pcr, uint16_t type,
                              const uint8_t *digest, const void *data,
                              uint32_t len)
{
    uint8_t ev[TCG_EVENT2_OVERHEAD];
    uint32_t need = TCG_EVENT2_OVERHEAD + len;

    if (s->tcg_log_full) {
        return;
    }
    if (!s->tcg_log_len) {
        amd_psp_log_write(s, 0, tcg_log_header, sizeof(tcg_log_header));
        s->tcg_log_len = sizeof(tcg_log_header);
    }
    if (s->tcg_log_len + need > AMD_PSP_TCG_LOG_SIZE) {
        s->tcg_log_full = true;
        amd_drtm_guest_error(s->platform, "amd-psp: the event log is full, "
                             "GET_TCG_LOGS will fail from now on");
        return;
    }
    stl_le_p(ev, pcr);
    stl_le_p(ev + 4, type);
    stl_le_p(ev + 8, 1);
    stw_le_p(ev + 12, TPM2_ALG_SHA256);
    memcpy(ev + 14, digest, SHA256_LEN);
    stl_le_p(ev + 14 + SHA256_LEN, len);
    amd_psp_log_write(s, s->tcg_log_len, ev, sizeof(ev));
    if (len) {
        amd_psp_log_write(s, s->tcg_log_len + sizeof(ev), data, len);
    }
    s->tcg_log_len += need;
    trace_amd_psp_drtm_log_event(pcr, type, len);
}

/* Extend @pcr with @digest and log it as @type, with @data as event data */
static int amd_psp_extend_digest(AmdPspState *s, unsigned pcr, uint16_t type,
                                 const uint8_t *digest, const void *data,
                                 uint32_t len)
{
    int ret = amd_psp_pcr_extend(s, pcr, digest);

    if (ret < 0) {
        return ret;
    }
    amd_psp_log_event(s, pcr, type, digest, data, len);
    return 0;
}

/*
 * Extend @pcr with the SHA-256 of @data and log it as @type. The board's
 * log carries the data itself for the short values and nothing for the
 * hashed blobs.
 */
static int amd_psp_extend(AmdPspState *s, unsigned pcr, uint16_t type,
                          const void *data, size_t len, bool log_data)
{
    uint8_t digest[SHA256_LEN];

    amd_psp_sha256(data, len, digest);
    return amd_psp_extend_digest(s, pcr, type, digest, log_data ? data : NULL,
                                 log_data ? len : 0);
}

static void amd_psp_apply_locks(AmdPspState *s)
{
    trace_amd_psp_drtm_locks(s->locks);
    if (s->tpm && !tpm_set_locality_locks(s->tpm, s->locks) && s->locks) {
        warn_report_once("amd-psp: the TPM frontend has no locality locks "
                         "(tpm-tis is needed), the guest sees every "
                         "locality");
    }
}

static void amd_psp_unlock(AmdPspState *s, uint8_t mask)
{
    s->locks &= ~mask;
    amd_psp_apply_locks(s);
}

static bool amd_psp_in_tmr(AmdPspState *s, uint64_t base, uint64_t len)
{
    unsigned i;

    for (i = 0; i < AMD_PSP_DRTM_TMR_MAX; i++) {
        AmdPspTmr *tmr = &s->tmr[i];

        if (tmr->set && tmr->len && base >= tmr->base &&
            base + len <= tmr->base + tmr->len) {
            return true;
        }
    }
    return false;
}

/*
 * Hardware collapses every reason into one status, so each is named here
 * as a guest error. PCRs 18 to 20 are capped with all-ones, locality 4 is
 * unlocked, and the post-launch commands stay refused.
 */
static uint16_t G_GNUC_PRINTF(2, 3)
amd_psp_launch_failed(AmdPspState *s, const char *fmt, ...)
{
    uint8_t ones[SHA256_LEN];
    g_autofree char *why = NULL;
    va_list ap;
    unsigned pcr;

    va_start(ap, fmt);
    why = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    trace_amd_psp_drtm_launch_failed(why);
    amd_drtm_guest_error(s->platform, "amd-psp: LAUNCH failed: %s", why);

    memset(ones, 0xff, sizeof(ones));
    for (pcr = 18; pcr <= 20; pcr++) {
        amd_psp_pcr_extend(s, pcr, ones);
    }
    s->launch = AMD_PSP_LAUNCH_STATE_FAILED;
    amd_psp_log_clear(s);
    amd_psp_unlock(s, BIT(4));
    return AMD_PSP_DRTM_LAUNCH_ERROR;
}

/*
 * The SL header points at a count and CPUID leaf 1 EAX values with the
 * stepping masked. A miss only traces: on hardware, adding the running
 * family to the list changed nothing.
 */
static void amd_psp_check_soc_flags(AmdPspState *s, const uint8_t *slb)
{
    uint32_t cpu = amd_drtm_cpu_signature() & ~CPUID_STEPPING_MASK;
    unsigned off = lduw_le_p(slb + SL_HDR_SOC_FLAG);
    uint32_t count, i;
    bool match = false;

    if (off + 4 > AMD_PSP_SLB_SIZE) {
        return;
    }
    count = ldl_le_p(slb + off);
    if (count > (AMD_PSP_SLB_SIZE - off - 4) / 4) {
        return;
    }
    for (i = 0; i < count; i++) {
        if ((ldl_le_p(slb + off + 4 + 4 * i) & ~CPUID_STEPPING_MASK) == cpu) {
            match = true;
        }
    }
    trace_amd_psp_drtm_soc_flags(cpu, count, match);
}

static size_t der_put_len(uint8_t *out, size_t len)
{
    if (len < 0x80) {
        out[0] = len;
        return 1;
    }
    if (len < 0x100) {
        out[0] = 0x81;
        out[1] = len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = len >> 8;
    out[2] = len;
    return 3;
}

/* A DER INTEGER from a big-endian magnitude */
static size_t der_put_uint(uint8_t *out, const uint8_t *be, size_t len)
{
    size_t n = 0;
    bool pad;

    while (len > 1 && be[0] == 0) {
        be++;
        len--;
    }
    pad = be[0] & 0x80;
    out[n++] = 0x02;
    n += der_put_len(out + n, len + pad);
    if (pad) {
        out[n++] = 0;
    }
    memcpy(out + n, be, len);
    return n + len;
}

/* The token's key as the PKCS#1 RSAPublicKey the crypto layer parses */
static size_t amd_psp_token_to_der(const uint8_t *token, uint8_t *der,
                                   Error **errp)
{
    uint32_t exp_bits = ldl_le_p(token + KEY_HDR_EXP_BITS);
    uint32_t mod_bits = ldl_le_p(token + KEY_HDR_MOD_BITS);
    uint8_t exp[KEY_PART_LEN], mod[KEY_PART_LEN];
    uint8_t body[2 * (KEY_PART_LEN + 5)];
    size_t n, i;

    if (mod_bits != 8 * SIG_LEN || !exp_bits || exp_bits % 8 ||
        exp_bits > 8 * KEY_PART_LEN) {
        error_setg(errp, "key token with a %u-bit modulus and a %u-bit "
                   "exponent", mod_bits, exp_bits);
        return 0;
    }
    for (i = 0; i < mod_bits / 8; i++) {
        mod[i] = token[KEY_MOD_OFF + mod_bits / 8 - 1 - i];
    }
    for (i = 0; i < exp_bits / 8; i++) {
        exp[i] = token[KEY_EXP_OFF + exp_bits / 8 - 1 - i];
    }
    n = der_put_uint(body, mod, mod_bits / 8);
    n += der_put_uint(body + n, exp, exp_bits / 8);
    der[0] = 0x30;
    i = 1 + der_put_len(der + 1, n);
    memcpy(der + i, body, n);
    return i + n;
}

static void amd_psp_mgf1(const uint8_t *seed, uint8_t *mask, size_t mask_len)
{
    uint8_t buf[SHA384_LEN + 4], digest[SHA384_LEN];
    uint32_t counter = 0;
    size_t n;

    memcpy(buf, seed, SHA384_LEN);
    while (mask_len) {
        stl_be_p(buf + SHA384_LEN, counter++);
        amd_psp_sha384(buf, sizeof(buf), digest);
        n = MIN(mask_len, SHA384_LEN);
        memcpy(mask, digest, n);
        mask += n;
        mask_len -= n;
    }
}

/*
 * RFC 8017 9.1.2 on the encoded message the public key operation gave:
 * with a 4096-bit modulus emBits is 4095, so the top bit of the masked
 * data block must be clear.
 */
static bool amd_psp_pss_verify(const uint8_t *em, const uint8_t *msg,
                               size_t msg_len, Error **errp)
{
    uint8_t db[SIG_LEN - SHA384_LEN - 1];
    uint8_t mprime[8 + 2 * SHA384_LEN], h[SHA384_LEN];
    const size_t ps_len = sizeof(db) - PSS_SALT_LEN - 1;
    const uint8_t *hash = em + sizeof(db);
    size_t i;

    if (em[SIG_LEN - 1] != PSS_TRAILER) {
        error_setg(errp, "no PSS trailer");
        return false;
    }
    if (em[0] & 0x80) {
        error_setg(errp, "PSS encoding wider than the modulus");
        return false;
    }
    amd_psp_mgf1(hash, db, sizeof(db));
    for (i = 0; i < sizeof(db); i++) {
        db[i] ^= em[i];
    }
    db[0] &= 0x7f;
    for (i = 0; i < ps_len; i++) {
        if (db[i]) {
            error_setg(errp, "PSS padding not zero");
            return false;
        }
    }
    if (db[ps_len] != 0x01) {
        error_setg(errp, "no PSS salt separator");
        return false;
    }
    memset(mprime, 0, 8);
    amd_psp_sha384(msg, msg_len, mprime + 8);
    memcpy(mprime + 8 + SHA384_LEN, db + ps_len + 1, PSS_SALT_LEN);
    amd_psp_sha384(mprime, sizeof(mprime), h);
    if (memcmp(h, hash, SHA384_LEN)) {
        error_setg(errp, "PSS hash mismatch");
        return false;
    }
    return true;
}

/*
 * The signature check over the first SizeFWSigned bytes with the token's
 * key. The crypto layer offers the raw RSA operation with gcrypt or
 * nettle and no PSS, so the decode is done here. Without either library
 * the check is skipped.
 */
static AmdPspSignatureResult amd_psp_verify_signature(AmdPspState *s,
                                                      const uint8_t *slb,
                                                      uint32_t signed_len,
                                                      const uint8_t *sig,
                                                      const uint8_t *token,
                                                      Error **errp)
{
    QCryptoAkCipherOptions opts = {
        .alg = QCRYPTO_AK_CIPHER_ALGO_RSA,
        .u.rsa = {
            .padding_alg = QCRYPTO_RSA_PADDING_ALGO_RAW,
            .hash_alg = QCRYPTO_HASH_ALGO_SHA384,
        },
    };
    g_autoptr(QCryptoAkCipher) key = NULL;
    uint8_t der[4 + 2 * (KEY_PART_LEN + 5)];
    uint8_t sig_be[SIG_LEN], em[SIG_LEN];
    size_t der_len, i;

    if (!qcrypto_akcipher_supports(&opts)) {
        warn_report_once("amd-psp: no gcrypt or nettle in this build, the "
                         "SKL signature is not checked");
        return AMD_PSP_SIGNATURE_RESULT_UNSUPPORTED;
    }
    der_len = amd_psp_token_to_der(token, der, errp);
    if (!der_len) {
        return AMD_PSP_SIGNATURE_RESULT_FAILED;
    }
    key = qcrypto_akcipher_new(&opts, QCRYPTO_AK_CIPHER_KEY_TYPE_PUBLIC, der,
                               der_len, errp);
    if (!key) {
        return AMD_PSP_SIGNATURE_RESULT_FAILED;
    }
    for (i = 0; i < SIG_LEN; i++) {
        sig_be[i] = sig[SIG_LEN - 1 - i];
    }
    if (qcrypto_akcipher_encrypt(key, sig_be, SIG_LEN, em, SIG_LEN,
                                 errp) != SIG_LEN) {
        return AMD_PSP_SIGNATURE_RESULT_FAILED;
    }
    if (!amd_psp_pss_verify(em, slb, signed_len, errp)) {
        return AMD_PSP_SIGNATURE_RESULT_FAILED;
    }
    return AMD_PSP_SIGNATURE_RESULT_VERIFIED;
}

/*
 * The guide's section 2: the SLB SKINIT recorded, inside a TMR, with the
 * signature block behind the measured part, the signature over it, and
 * PCR 17 holding what SKINIT measured. Then the chain the board leaves in
 * PCR 17 and PCR 18, the unlocks and the SL_DEV release.
 */
static uint16_t amd_psp_cmd_launch(AmdPspState *s)
{
    AmdDrtmPlatform *p = s->platform;
    g_autofree uint8_t *slb = NULL;
    uint8_t pcr17[SHA256_LEN], expected[2 * SHA256_LEN];
    uint32_t words[2];
    uint32_t length, hdr_off, signed_len, sec_patch_level;
    const uint8_t *sig, *token;
    hwaddr base;

    s->tpm = tpm_find();
    s->signature = AMD_PSP_SIGNATURE_RESULT_NONE;

    if (!amd_drtm_launched(p)) {
        return amd_psp_launch_failed(s, "no SKINIT recorded, no SKL address "
                                     "to read");
    }
    base = p->slb_base;
    length = p->slb_length;
    if (!amd_psp_in_tmr(s, base, AMD_PSP_SLB_SIZE)) {
        return amd_psp_launch_failed(s, "the SLB at 0x%" HWADDR_PRIx
                                     " lies in no TMR", base);
    }

    slb = g_malloc(AMD_PSP_SLB_SIZE);
    if (address_space_read(&address_space_memory, base, MEMTXATTRS_UNSPECIFIED,
                           slb, AMD_PSP_SLB_SIZE) != MEMTX_OK) {
        return amd_psp_launch_failed(s, "the SLB at 0x%" HWADDR_PRIx
                                     " is not readable memory", base);
    }

    hdr_off = ROUND_UP(length, 16);
    if (hdr_off + SIG_HDR_LEN + SIG_LEN + TOKEN_LEN > AMD_PSP_SLB_SIZE) {
        return amd_psp_launch_failed(s, "measured length 0x%x leaves no room "
                                     "for the signature block", length);
    }
    if (memcmp(slb + hdr_off + SIG_HDR_TAG, SIG_TAG, strlen(SIG_TAG))) {
        return amd_psp_launch_failed(s, "no " SIG_TAG " signature header at "
                                     "0x%x", hdr_off + SIG_HDR_TAG);
    }
    signed_len = ldl_le_p(slb + hdr_off + SIG_HDR_SIZE_FW_SIGNED);
    if (signed_len < hdr_off + SIG_HDR_LEN ||
        signed_len > AMD_PSP_SLB_SIZE - SIG_LEN - TOKEN_LEN) {
        return amd_psp_launch_failed(s, "SizeFWSigned 0x%x does not fit the "
                                     "SLB", signed_len);
    }
    sig = slb + signed_len;
    token = sig + SIG_LEN;
    sec_patch_level = ldl_le_p(slb + hdr_off + SIG_HDR_SEC_PATCH_LEVEL);

    if (s->verify) {
        Error *err = NULL;

        s->signature = amd_psp_verify_signature(s, slb, signed_len, sig, token,
                                                &err);
        if (s->signature == AMD_PSP_SIGNATURE_RESULT_FAILED) {
            uint16_t status = amd_psp_launch_failed(s, "the signature does not "
                                                    "verify: %s",
                                                    error_get_pretty(err));
            error_free(err);
            return status;
        }
    } else {
        s->signature = AMD_PSP_SIGNATURE_RESULT_SKIPPED;
    }
    trace_amd_psp_drtm_signature(s->signature);

    amd_psp_check_soc_flags(s, slb);

    if (!s->tpm) {
        return amd_psp_launch_failed(s, "no TPM to read PCR 17 from");
    }
    if (amd_psp_pcr_read(s, 17, pcr17) < 0) {
        return amd_psp_launch_failed(s, "PCR 17 could not be read");
    }
    /* The SKINIT measurement: the reset value extended with the digest */
    memset(expected, 0, SHA256_LEN);
    amd_psp_sha256(slb, length, expected + SHA256_LEN);
    amd_psp_sha256(expected, sizeof(expected), expected);
    if (memcmp(pcr17, expected, SHA256_LEN)) {
        return amd_psp_launch_failed(s, "PCR 17 does not hold the measurement "
                                     "of the SLB's first 0x%x bytes", length);
    }
    /* SKINIT's own extend heads the log, though the service did not make it */
    amd_psp_log_event(s, 17, AMD_PSP_EV_SL_IMAGE, expected + SHA256_LEN, NULL,
                      0);

    words[0] = cpu_to_le32(s->splt_version);
    if (amd_psp_extend(s, 17, AMD_PSP_EV_SPLT_VERSION, words, 4, true) < 0) {
        return amd_psp_launch_failed(s, "PCR 17 extend with the SPLT version "
                                     "failed");
    }
    /* TSME off, anti-rollback set: the board's fuse words, in this order */
    words[0] = 0;
    words[1] = cpu_to_le32(1);
    if (amd_psp_extend(s, 17, AMD_PSP_EV_FUSE_STATE, words, 8, true) < 0) {
        return amd_psp_launch_failed(s, "PCR 17 extend with the fuse state "
                                     "failed");
    }
    if (amd_psp_extend(s, 18, AMD_PSP_EV_KEY_TOKEN, token, TOKEN_LEN,
                       false) < 0) {
        return amd_psp_launch_failed(s, "PCR 18 extend with the key token "
                                     "failed");
    }
    words[0] = cpu_to_le32(sec_patch_level);
    if (amd_psp_extend(s, 18, AMD_PSP_EV_SEC_PATCH_LEVEL, words, 4,
                       true) < 0) {
        return amd_psp_launch_failed(s, "PCR 18 extend with the patch level "
                                     "failed");
    }

    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0] = 1;
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1] = 0;
    s->launch = AMD_PSP_LAUNCH_STATE_OK;
    amd_psp_unlock(s, BIT(1) | BIT(2));
    amd_drtm_sl_dev_release(p);
    trace_amd_psp_drtm_launch_ok(base, length, sec_patch_level);
    return AMD_PSP_DRTM_NO_ERROR;
}

static const char *amd_psp_tmr_name(unsigned index)
{
    static const char *const names[AMD_PSP_DRTM_TMR_MAX] = {
        "tmr0", "tmr1", "tmr2", "tmr3", "tmr4", "tmr5", "tmr6", "tmr7",
    };

    return names[index];
}

static void amd_psp_tmr_release(AmdPspState *s, unsigned index)
{
    AmdPspTmr *tmr = &s->tmr[index];

    if (!tmr->set) {
        return;
    }
    trace_amd_psp_drtm_tmr_release(index, tmr->base, tmr->len);
    amd_drtm_unblock_dma(s->platform, amd_psp_tmr_name(index));
    tmr->set = false;
}

/* The SHA-256 of a range of guest memory, read a chunk at a time */
static bool amd_psp_hash_range(uint64_t base, uint64_t len, uint8_t *digest)
{
    g_autoptr(QCryptoHash) hash = qcrypto_hash_new(QCRYPTO_HASH_ALGO_SHA256,
                                                   &error_abort);
    g_autofree uint8_t *buf = g_malloc(OSSL_CHUNK);
    size_t digest_len = SHA256_LEN;
    uint64_t n;

    while (len) {
        n = MIN(len, OSSL_CHUNK);
        if (address_space_read(&address_space_memory, base,
                               MEMTXATTRS_UNSPECIFIED, buf, n) != MEMTX_OK) {
            return false;
        }
        if (qcrypto_hash_update(hash, buf, n, &error_abort) < 0) {
            g_assert_not_reached();
        }
        base += n;
        len -= n;
    }
    if (qcrypto_hash_finalize_bytes(hash, &digest, &digest_len,
                                    &error_abort) < 0) {
        g_assert_not_reached();
    }
    return true;
}

/*
 * The guide's section 3: C2PMSG_93 the size, _94 and _95 the base of the
 * DLME copy inside a TMR. Its digest goes into PCR 17 and PCR 18, then
 * the marker into both.
 */
static uint16_t amd_psp_cmd_extend_ossl_digest(AmdPspState *s)
{
    uint64_t size = s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0];
    uint64_t base = s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1] |
                    (uint64_t)s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2] << 32;
    uint8_t digest[SHA256_LEN];
    char hex[2 * SHA256_LEN + 1];

    if (s->launch != AMD_PSP_LAUNCH_STATE_OK) {
        return AMD_PSP_DRTM_NOT_SUPPORTED;
    }
    if (!size || base + size < base) {
        amd_drtm_guest_error(s->platform, "amd-psp: EXTEND_OSSL_DIGEST of "
                             "0x%" PRIx64 " bytes at 0x%" PRIx64 " is empty "
                             "or wraps", size, base);
        return AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED;
    }
    if (!amd_psp_in_tmr(s, base, size)) {
        amd_drtm_guest_error(s->platform, "amd-psp: EXTEND_OSSL_DIGEST of "
                             "0x%" PRIx64 " bytes at 0x%" PRIx64 " lies in "
                             "no TMR", size, base);
        return AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED;
    }
    if (!amd_psp_hash_range(base, size, digest)) {
        amd_drtm_guest_error(s->platform, "amd-psp: EXTEND_OSSL_DIGEST of "
                             "0x%" PRIx64 " bytes at 0x%" PRIx64 " is not "
                             "readable memory", size, base);
        return AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED;
    }
    trace_amd_psp_drtm_extend_ossl_digest(base, size,
                                          amd_psp_hex(digest, hex));
    if (amd_psp_extend_digest(s, 17, AMD_PSP_EV_OS_SL_LOAD, digest, NULL,
                              0) < 0 ||
        amd_psp_extend_digest(s, 18, AMD_PSP_EV_OS_SL_LOAD, digest, NULL,
                              0) < 0 ||
        amd_psp_extend(s, 17, AMD_PSP_EV_AMD_SL_SEPARATOR, OSSL_MARKER,
                       OSSL_MARKER_LEN, true) < 0 ||
        amd_psp_extend(s, 18, AMD_PSP_EV_AMD_SL_SEPARATOR, OSSL_MARKER,
                       OSSL_MARKER_LEN, true) < 0) {
        amd_drtm_guest_error(s->platform, "amd-psp: EXTEND_OSSL_DIGEST could "
                             "not extend PCR 17 and PCR 18");
        return AMD_PSP_DRTM_EXTEND_OSSL_DIGEST_FAILED;
    }
    return AMD_PSP_DRTM_NO_ERROR;
}

/* Locality 2 back to the PSP, locality 4 to the OS, as Xen asks on exit */
static uint16_t amd_psp_cmd_tpm_locality_access(AmdPspState *s)
{
    if (s->launch != AMD_PSP_LAUNCH_STATE_OK) {
        return AMD_PSP_DRTM_NOT_SUPPORTED;
    }
    trace_amd_psp_drtm_tpm_locality_access();
    s->locks |= BIT(2);
    amd_psp_unlock(s, BIT(4));
    return AMD_PSP_DRTM_NO_ERROR;
}

/*
 * The log's size in C2PMSG_93 and its address in _94 and _95, as the
 * board answered. What the board answers before any launch is untested:
 * an empty log is taken as the failed status.
 */
static uint16_t amd_psp_cmd_get_tcg_logs(AmdPspState *s)
{
    if (!s->tcg_log_len || s->tcg_log_full) {
        return AMD_PSP_DRTM_GET_TCG_LOGS_FAILED_ERROR;
    }
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0] = s->tcg_log_len;
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1] = s->tcg_log_base;
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2] = s->tcg_log_base >> 32;
    trace_amd_psp_drtm_get_tcg_logs(s->tcg_log_base, s->tcg_log_len);
    return AMD_PSP_DRTM_NO_ERROR;
}

static uint16_t amd_psp_cmd_get_capability(AmdPspState *s)
{
    /* The board's values: DRTM enabled, TSME off, anti-rollback set */
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0] = AMD_PSP_DRTM_CAP_ENABLED |
                                          AMD_PSP_DRTM_CAP_ANTI_ROLLBACK;
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1] = AMD_PSP_DRTM_VERSION;
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2] =
        (s->tmr_alignment & AMD_PSP_DRTM_CAP_TMR_ALIGNMENT_MASK) |
        ((uint32_t)s->tmr_count << AMD_PSP_DRTM_CAP_TMR_COUNT_SHIFT);
    return AMD_PSP_DRTM_NO_ERROR;
}

/*
 * C2PMSG_93 the size in 64 KiB units, _94 and _95 the base. A size of zero
 * is accepted, as the board accepted GRUB's, and only recorded: a launch
 * inside such a TMR cannot pass, hence the guest error.
 */
static uint16_t amd_psp_cmd_tmr_setup(AmdPspState *s, unsigned index)
{
    uint64_t units = s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0];
    uint64_t base = s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1] |
                    (uint64_t)s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2] << 32;
    uint64_t len = units * AMD_PSP_DRTM_TMR_UNIT;
    AmdPspTmr *tmr;

    if (s->launch == AMD_PSP_LAUNCH_STATE_OK) {
        return AMD_PSP_DRTM_TMR_SETUP_NOT_ALLOWED;
    }
    if (index >= s->tmr_count) {
        return AMD_PSP_DRTM_TMR_SETUP_FAILED_ERROR;
    }
    if (base & (s->tmr_alignment - 1)) {
        return AMD_PSP_DRTM_MEMORY_UNALIGNED_ERROR;
    }
    if (base + len < base) {
        return AMD_PSP_DRTM_TMR_SETUP_FAILED_ERROR;
    }
    if (!len) {
        amd_drtm_guest_error(s->platform, "amd-psp: TMR %u at 0x%" PRIx64
                             " has zero size, a launch inside it will fail",
                             index, base);
    }

    amd_psp_tmr_release(s, index);
    tmr = &s->tmr[index];
    tmr->set = true;
    tmr->base = base;
    tmr->len = len;
    trace_amd_psp_drtm_tmr_setup(index, base, len);
    if (len) {
        amd_drtm_block_dma(s->platform, base, len, amd_psp_tmr_name(index),
                           false);
    }
    return AMD_PSP_DRTM_NO_ERROR;
}

static uint16_t amd_psp_cmd_tmr_release(AmdPspState *s)
{
    unsigned i;

    for (i = 0; i < AMD_PSP_DRTM_TMR_MAX; i++) {
        amd_psp_tmr_release(s, i);
    }
    return AMD_PSP_DRTM_NO_ERROR;
}

static uint16_t amd_psp_dispatch(AmdPspState *s, uint8_t cmd, unsigned index)
{
    switch (cmd) {
    case AMD_PSP_DRTM_CMD_GET_CAPABILITY:
        return amd_psp_cmd_get_capability(s);
    case AMD_PSP_DRTM_CMD_TMR_SETUP:
        return amd_psp_cmd_tmr_setup(s, index);
    case AMD_PSP_DRTM_CMD_TMR_RELEASE:
        return amd_psp_cmd_tmr_release(s);
    case AMD_PSP_DRTM_CMD_LAUNCH:
        return amd_psp_cmd_launch(s);
    case AMD_PSP_DRTM_CMD_EXTEND_OSSL_DIGEST:
        return amd_psp_cmd_extend_ossl_digest(s);
    case AMD_PSP_DRTM_CMD_TPM_LOCALITY_ACCESS:
        return amd_psp_cmd_tpm_locality_access(s);
    case AMD_PSP_DRTM_CMD_GET_TCG_LOGS:
        return amd_psp_cmd_get_tcg_logs(s);
    case AMD_PSP_DRTM_CMD_GET_TMR_DESCRIPTORS:
    case AMD_PSP_DRTM_CMD_ALLOCATE_SHARED_MEMORY:
    case AMD_PSP_DRTM_CMD_GET_IVRS_TABLE_INFO:
        /* The three the fork never issues, not modelled */
        return AMD_PSP_DRTM_NOT_SUPPORTED;
    default:
        return AMD_PSP_DRTM_INVALID_SERVICE_ID_ERROR;
    }
}

static void amd_psp_publish(AmdPspState *s)
{
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = AMD_PSP_DRTM_READY | s->status;
    s->busy = false;
    trace_amd_psp_drtm_status(s->command, s->status);
}

static void amd_psp_delay_expired(void *opaque)
{
    amd_psp_publish(opaque);
}

/* The command the last write issued, run once the write has returned */
static void amd_psp_run_command(void *opaque)
{
    AmdPspState *s = opaque;
    uint32_t word = s->c2pmsg[AMD_PSP_C2PMSG_DRTM];
    unsigned index = (word >> AMD_PSP_DRTM_TMR_INDEX_SHIFT) &
                     AMD_PSP_DRTM_TMR_INDEX_MASK;

    s->command = (word >> AMD_PSP_DRTM_CMD_SHIFT) & AMD_PSP_DRTM_CMD_MASK;
    s->status = amd_psp_dispatch(s, s->command, index);

    if (s->command_delay) {
        trace_amd_psp_drtm_ready_held(s->command_delay);
        timer_mod(s->delay_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + s->command_delay);
    } else {
        amd_psp_publish(s);
    }
}

/*
 * A write to C2PMSG_72. Zero is the kick the service needs before it
 * answers anything, as GRUB's comment records. Until it arrives a command
 * leaves the ready bit clear, which is what the guest's timeout is for.
 * One command runs at a time, and one arriving meanwhile is dropped.
 */
static void amd_psp_command_write(AmdPspState *s, uint32_t value)
{
    uint32_t word = value & ~AMD_PSP_DRTM_READY;

    if (s->busy) {
        amd_drtm_guest_error(s->platform, "amd-psp: write 0x%x to C2PMSG_72 "
                             "while command 0x%x is in flight, dropped",
                             value, s->command);
        return;
    }
    if (!word) {
        trace_amd_psp_drtm_kick();
        s->kicked = true;
        s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = AMD_PSP_DRTM_READY;
        return;
    }
    s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = word;
    if (!s->kicked) {
        amd_drtm_guest_error(s->platform, "amd-psp: command 0x%x before the "
                             "service was kicked, no answer until a zero "
                             "write", word);
        return;
    }
    s->busy = true;
    s->command = (word >> AMD_PSP_DRTM_CMD_SHIFT) & AMD_PSP_DRTM_CMD_MASK;
    trace_amd_psp_drtm_command(s->command,
                               (word >> AMD_PSP_DRTM_TMR_INDEX_SHIFT) &
                               AMD_PSP_DRTM_TMR_INDEX_MASK,
                               s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG0],
                               s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG1],
                               s->c2pmsg[AMD_PSP_C2PMSG_DRTM_ARG2]);
    qemu_bh_schedule(s->bh);
}

static uint64_t amd_psp_read(void *opaque, hwaddr addr, unsigned size)
{
    AmdPspState *s = opaque;
    hwaddr offset = addr - AMD_PSP_C2PMSG_BASE;

    if (addr < AMD_PSP_C2PMSG_BASE || offset >= sizeof(s->c2pmsg)) {
        return 0;
    }
    return s->c2pmsg[offset / sizeof(s->c2pmsg[0])];
}

/*
 * Without the service a write is dropped rather than stored: a write is
 * how x86 issues a command, and answering one means running the service.
 */
static void amd_psp_write(void *opaque, hwaddr addr, uint64_t value,
                          unsigned size)
{
    AmdPspState *s = opaque;
    hwaddr offset = addr - AMD_PSP_C2PMSG_BASE;
    unsigned reg;

    if (!s->drtm_service || addr < AMD_PSP_C2PMSG_BASE ||
        offset >= sizeof(s->c2pmsg)) {
        return;
    }
    reg = offset / sizeof(s->c2pmsg[0]);
    switch (reg) {
    case AMD_PSP_C2PMSG_DRTM:
        amd_psp_command_write(s, value);
        break;
    case AMD_PSP_C2PMSG_DRTM_ARG0:
    case AMD_PSP_C2PMSG_DRTM_ARG1:
    case AMD_PSP_C2PMSG_DRTM_ARG2:
        s->c2pmsg[reg] = value;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps amd_psp_mmio_ops = {
    .read = amd_psp_read,
    .write = amd_psp_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/*
 * Everything the service did goes, its TMR blocks included. swtpm resets
 * at the same point, so there is nothing for a surviving state to
 * protect. The registers return to what drtm-ready says.
 */
static void amd_psp_reset(DeviceState *dev)
{
    AmdPspState *s = AMD_PSP(dev);
    unsigned i;

    if (s->drtm_service) {
        trace_amd_psp_drtm_reset();
        timer_del(s->delay_timer);
        qemu_bh_cancel(s->bh);
        for (i = 0; i < AMD_PSP_DRTM_TMR_MAX; i++) {
            amd_psp_tmr_release(s, i);
        }
        amd_psp_log_clear(s);
    }
    s->kicked = false;
    s->busy = false;
    s->command = 0;
    s->status = 0;
    s->launch = AMD_PSP_LAUNCH_STATE_NONE;
    s->signature = AMD_PSP_SIGNATURE_RESULT_NONE;
    memset(s->c2pmsg, 0, sizeof(s->c2pmsg));
    /*
     * The board's TPM_ACCESS before any launch: localities 1 to 4 locked,
     * a successful launch opens 1 and 2, a failed one 4. The TPM is looked
     * up at each use, since it may be created after this device.
     */
    if (s->drtm_service) {
        s->tpm = tpm_find();
        s->locks = s->locality_locks ? BIT(1) | BIT(2) | BIT(3) | BIT(4) : 0;
        amd_psp_apply_locks(s);
    }
    /*
     * Whether real firmware leaves the register ready before SKINIT is
     * not known, which is what the property is for.
     */
    if (s->drtm_ready) {
        s->c2pmsg[AMD_PSP_C2PMSG_DRTM] = AMD_PSP_DRTM_READY;
    }
}

/* The service's record on query-amd-drtm */
static AmdPspDrtmInfo *amd_psp_drtm_info(void *opaque)
{
    AmdPspState *s = opaque;
    AmdPspDrtmInfo *info = g_new0(AmdPspDrtmInfo, 1);

    info->kicked = s->kicked;
    info->launch = s->launch;
    info->signature = s->signature;
    info->command = s->command;
    info->status = s->status;
    return info;
}

static void amd_psp_realize(PCIDevice *pci_dev, Error **errp)
{
    AmdPspState *s = AMD_PSP(pci_dev);

    pci_set_word(pci_dev->config + PCI_DEVICE_ID, s->device_id);

    if (s->drtm_service) {
        s->platform = amd_drtm_platform_find();
        if (!s->platform) {
            error_setg(errp, "drtm-service=on needs one %s, which holds "
                       "the launch the service checks and the DMA blocks "
                       "its TMRs are", TYPE_AMD_DRTM_PLATFORM);
            return;
        }
        if (!s->tmr_count || s->tmr_count > AMD_PSP_DRTM_TMR_MAX) {
            error_setg(errp, "tmr-count must be 1 to %d", AMD_PSP_DRTM_TMR_MAX);
            return;
        }
        if (!is_power_of_2(s->tmr_alignment) ||
            s->tmr_alignment > AMD_PSP_DRTM_CAP_TMR_ALIGNMENT_MASK) {
            error_setg(errp, "tmr-alignment must be a power of two below "
                       "2^24");
            return;
        }
        if (s->tcg_log_base & (AMD_PSP_TCG_LOG_SIZE - 1)) {
            error_setg(errp, "tcg-log-base must be aligned to 0x%x",
                       AMD_PSP_TCG_LOG_SIZE);
            return;
        }
        s->bh = qemu_bh_new_guarded(amd_psp_run_command, s,
                                    &DEVICE(s)->mem_reentrancy_guard);
        s->delay_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                      amd_psp_delay_expired, s);
        /* The event log, read like memory, written by the service alone */
        if (!memory_region_init_rom(&s->tcg_log, OBJECT(s), "amd-psp-tcg-log",
                                    AMD_PSP_TCG_LOG_SIZE, errp)) {
            return;
        }
        memory_region_add_subregion(get_system_memory(), s->tcg_log_base,
                                    &s->tcg_log);
        amd_drtm_set_psp(s->platform, amd_psp_drtm_info, s);
    }

    memory_region_init_io(&s->mmio, OBJECT(s), &amd_psp_mmio_ops, s,
                          "amd-psp-mmio", AMD_PSP_BAR_SIZE);
    pci_register_bar(pci_dev, AMD_PSP_BAR_INDEX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

    /*
     * The same registers again, where the ASPT says they are. Firmware
     * leaves this function's memory decode off on at least one board, so
     * this window is the only route software can take without changing the
     * platform first.
     */
    memory_region_init_alias(&s->window, OBJECT(s), "amd-psp-aspt", &s->mmio,
                             AMD_PSP_ASPT_WINDOW, AMD_PSP_ASPT_SIZE);
    memory_region_add_subregion(get_system_memory(), AMD_PSP_ASPT_BASE,
                                &s->window);
}

static void amd_psp_exit(PCIDevice *pci_dev)
{
    AmdPspState *s = AMD_PSP(pci_dev);

    memory_region_del_subregion(get_system_memory(), &s->window);
    if (s->drtm_service) {
        amd_drtm_set_psp(s->platform, NULL, NULL);
        memory_region_del_subregion(get_system_memory(), &s->tcg_log);
        timer_free(s->delay_timer);
        qemu_bh_delete(s->bh);
    }
}

static const Property amd_psp_properties[] = {
    DEFINE_PROP_UINT16("device-id", AmdPspState, device_id,
                       AMD_PSP_DEFAULT_ID),
    DEFINE_PROP_BOOL("drtm-ready", AmdPspState, drtm_ready, true),
    DEFINE_PROP_BOOL("aspt", AmdPspState, aspt, true),
    /*
     * The DRTM ACPI device is firmware's on hardware, behind a setup option
     * of its own, and rides on this device here because it is the AMD one a
     * guest asking for any of this already has.
     */
    DEFINE_PROP_BOOL("drtm-device", AmdPspState, drtm_device, false),
    /* The service behind the mailbox, and what it reports and checks */
    DEFINE_PROP_BOOL("drtm-service", AmdPspState, drtm_service, false),
    DEFINE_PROP_UINT8("tmr-count", AmdPspState, tmr_count, 1),
    DEFINE_PROP_UINT32("tmr-alignment", AmdPspState, tmr_alignment,
                       AMD_PSP_DRTM_TMR_UNIT),
    DEFINE_PROP_UINT32("splt-version", AmdPspState, splt_version, 0),
    DEFINE_PROP_BOOL("verify", AmdPspState, verify, true),
    /* Milliseconds the ready bit stays clear after each command */
    DEFINE_PROP_UINT32("command-delay", AmdPspState, command_delay, 0),
    DEFINE_PROP_BOOL("locality-locks", AmdPspState, locality_locks, true),
    DEFINE_PROP_UINT64("tcg-log-base", AmdPspState, tcg_log_base,
                       AMD_PSP_TCG_LOG_BASE),
};

static void amd_psp_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = amd_psp_realize;
    k->exit = amd_psp_exit;
    k->vendor_id = PCI_VENDOR_ID_AMD;
    k->device_id = AMD_PSP_DEFAULT_ID;
    k->class_id = PCI_CLASS_CRYPT_OTHER;
    dc->desc = "AMD Secure Processor (mailbox registers, DRTM service)";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_legacy_reset(dc, amd_psp_reset);
    device_class_set_props(dc, amd_psp_properties);
}

static const TypeInfo amd_psp_info = {
    .name          = TYPE_AMD_PSP,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(AmdPspState),
    .class_init    = amd_psp_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void amd_psp_register_types(void)
{
    type_register_static(&amd_psp_info);
}

type_init(amd_psp_register_types)
