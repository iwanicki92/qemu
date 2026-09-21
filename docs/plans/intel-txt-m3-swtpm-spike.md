# swtpm Locality Spike — Intel TXT de-risking for QEMU (M3 SENTER)

**Status:** PARTIAL — protocol findings complete and verified; locality matrix
results in §6 are filled in as each step runs (run `spike3.py` again to
refresh; latest raw output in `run_output3c.txt` / `run_output3d.txt`).

**Question answered:** does swtpm 0.10.2 (libtpms-based, TPM 2.0 mode) accept
locality-4 `TPM2_PCR_Extend` / `TPM2_PCR_Reset` into DRTM PCRs 17/18, and how
does it treat the same operations at locality 3 and locality 0?

**TL;DR:** The QEMU-compatible swtpm wire protocol (two-socket ctrl/data,
`CMD_SET_DATAFD` with SCM_RIGHTS fd passing) works end-to-end with hand-built
TPM 2.0 commands; all 24 PCRs are allocated in all four hash banks by default;
locality matrix below. **Verdict: locality-4 extends of PCR 17/18 WORK; locality 0 is correctly refused; TPM2_PCR_Reset does not work on the DRTM PCRs at any locality.**

---

## 1. Environment

| item | value |
|---|---|
| swtpm | `/usr/bin/swtpm` 0.10.2 (TPM 2.0 capable), invoked as `swtpm socket` |
| guest-side emulator | libtpms (bundled with swtpm; self-tests RSA-1024/2048 pkcs1/pss, camellia-128/256, tdes at CMD_INIT) |
| driver | Python 3.14, `spike.py`/`spike2.py`/`spike3.py` in this directory (no tpm2-tools, all TPM 2.0 byte streams hand-built) |
| wire-protocol reference | QEMU tree (read-only): `/home/michal/Development/qemu/backends/tpm/{tpm_emulator.c,tpm_ioctl.h,tpm_int.h,tpm_util.c}` |
| per-instance log | `--log file=<state_dir>/swtpm.log,level=20` for every swtpm; dumps + process liveness after every failure |

## 2. Exact reproduction steps

### 2.1 swtpm invocation

QEMU-faithful mode (no `--server`; data channel handed over via
`CMD_SET_DATAFD`, exactly what QEMU's `tpm_emulator_prepare_data_fd()` does):

```
/usr/bin/swtpm socket \
  --tpm2 \
  --tpmstate dir=<state_dir> \
  --log file=<state_dir>/swtpm.log,level=20 \
  --ctrl type=unixio,path=<state_dir>/swtpm.ctrl \
  --locality allow-set-locality
```

An alternate `--server type=unixio,path=<state_dir>/swtpm.sock` variant was
also tested (behaves identically for the data channel once established).

Kill strays before starting: `pkill -f 'swtpm [s]ocket'` (bracket avoids
self-match), verify with `pgrep -af`.

### 2.2 Control-channel protocol (from QEMU `tpm_ioctl.h`)

Unix stream socket to `swtpm.ctrl`. Request = 4-byte big-endian command
number + command-specific struct; response = 4-byte BE result code (+
struct). Commands used:

| cmd | number | request struct | response |
|---|---|---|---|
| `CMD_GET_CAPABILITY` | `0x01` | none | 4 rc + 4 caps |
| `CMD_INIT` | `0x02` | u32 flags (0) | 4 rc |
| `CMD_SHUTDOWN` | `0x03` | none | 4 rc |
| `CMD_SET_LOCALITY` | `0x05` | u8 locality | 4 rc |
| `CMD_SET_DATAFD` | `0x10` | none (fd via SCM_RIGHTS ancillary data on the **same** `sendmsg`) | 4 rc |
| `CMD_SET_BUFFERSIZE` | `0x11` | u32 requested size (0 = default) | 4 rc + 3×u32 (buffersize, min, max) |

Observed exchanges (all in this session, raw hex from driver + swtpm log):

```
ctrl GET_CAPABILITY:
  req: 00 00 00 01
  rsp: 00 00 00 00 00 01 FF FF        ; rc=0, caps=0x0001ffff
ctrl INIT:
  req: 00 00 00 02 00 00 00 00
  rsp: 00 00 00 00                    ; rc=0 (after libtpms self-test)
ctrl SET_BUFFERSIZE(0):
  req: 00 00 00 11 00 00 00 00
  rsp: 00 00 00 00 00 00 10 00 00 00 0A F8 00 00 10 00
      ; rc=0, buffersize=4096, min=2808, max=4096
```

### 2.3 Data channel: `CMD_SET_DATAFD` (SCM_RIGHTS)

Driver creates `socketpair(AF_UNIX, SOCK_STREAM)`, sends the 4-byte
`CMD_SET_DATAFD` command **and** passes the peer end as an SCM_RIGHTS
ancillary fd in the same `sendmsg`, then closes its copy. swtpm reads TPM
commands from that fd. Verified working: every TPM 2.0 command afterwards
round-trips with a well-formed response (swtpm log shows `SWTPM_IO_Read`/
`SWTPM_IO_Write` pairs).

### 2.4 TPM 2.0 framing

Both command and response headers are **10 bytes, big-endian**:

```
u16 tag (0x8001 no-sessions / 0x8002 sessions) | u32 size | u32 code (cmd: commandCode, rsp: responseCode)
```

The full size field includes the header; the body is `size − 10` more bytes
(plain stream framing, no outer length prefix).

> **Framing bug warning (cost several hours of this spike):** an 8-byte
> header (`>HHI`: u16 u16 u32) makes swtpm parse `commandSize` as
> e.g. `0x000A0000` (655360) and block waiting for bytes that never come —
> the process stays alive, both channels go silent. All "wedged TPM"
> symptoms observed earlier in this spike were this driver bug, not swtpm.
> Every builder in `spike3.py` uses `>HII` and was verified byte-exact
> against the reference strings below.

### 2.5 TPM 2.0 command bytes used (verified byte-exact)

```
TPM2_Startup(CLEAR)  (12 B, tag 0x8001):
  80 01 00 00 00 0C 00 00 01 44 00 00

TPM2_PCR_Read(PCR17)  (20 B, tag 0x8001) — body: TPML_PCR_SELECTION{count=1,
hashAlg=SHA256(0x000B), sizeofSelect=3, bitmap}:
  PCR17: 80 01 00 00 00 14 00 00 01 7E 00 00 00 01 00 0B 03 00 00 02
  PCR18: ... 00 00 04   (bitmap bit 2 of byte 2)
  PCR7:  ... 00 01 00

TPM2_PCR_Extend(PCR, SHA256 digest)  (65 B, tag 0x8002, empty TPM_RS_PW
auth session: authorizationSize=9, authHandle=0x40000009, zero nonce/attrs/HMAC,
then TPML_DIGEST_VALUES{count=1, alg=SHA256, digest}):
  PCR17: 80 02 00 00 00 41 00 00 01 82 00 00 00 11 00 00 00 09 40 00 00 09
         00 00 00 00 00 00 00 01 00 0B <32-byte digest>
  PCR18: same with handle 0x00000012

TPM2_PCR_Reset(PCR)  (27 B, tag 0x8002, handle + empty auth, no body):
  PCR17: 80 02 00 00 00 1B 00 00 01 3D 00 00 00 11 00 00 00 09 40 00 00 09 00 00 00 00

GetCapability(TPM_CAP_PCRS=0x5, prop=0, count=40)  (22 B):
  80 01 00 00 00 16 00 00 01 7A 00 00 00 05 00 00 00 00 00 40
```

Digests (all `sha256` of the labelled strings): A=`"txt-spike digest A: L4 PCR17"`,
B=`"txt-spike digest B: L4 PCR18"`, C=`"txt-spike digest C: L3 PCR17"`,
D=`"txt-spike digest D: L0 PCR17"`, E=`"txt-spike digest E: L0 PCR7 control"`.

Expected extend semantics: `PCR_new = sha256(PCR_old || digest)`; the driver
verifies this on every read-after-extend.

## 3. Protocol findings (all observed, none inferred)

1. **`CMD_INIT` does not require a prior data-socket connection.** It
   succeeded on an instance whose data fd was only handed over afterwards;
   the historical rc-9/EBADF theory (INIT before data socket) was not
   reproduced in this environment. QEMU's actual order (SET_DATAFD →
   version probe → GET_CAPABILITY → INIT) is used throughout and works.
2. **QEMU's pre-INIT version probe is answered by swtpm.** QEMU sends
   `ReadClock` (the 12 B… actually 10 B command
   `80 01 00 00 00 0A 00 00 01 81`) on the data fd before INIT, purely to
   detect TPM 1.2 vs 2.0 by the response tag. swtpm 0.10.2 replies
   `80 01 00 00 00 0A 00 00 01 01` — tag 0x8001 (TPM 2.0), rc `0x00000101`
   (TPM_RC_FAILURE, TPM not initialised yet). QEMU only inspects the tag,
   so this is harmless.
3. **Corrected TPM 2.0 response-code meanings** (earlier in this spike the
   table was wrong; the values below are what swtpm/libtpms return):
   `0x000` success; `0x100` TPM_RC_INITIALIZE (before `TPM2_Startup`);
   `0x101` TPM_RC_FAILURE; `0x143` TPM_RC_COMMAND_CODE (unknown command
   code); warnings at RC_WARN base `0x900`: `0x904` memory, `0x907`
   locality, `0x909` canceled.
4. **`TPM2_Startup(CLEAR)` must be the first TPM 2.0 command after
   INIT.** `ReadClock` after INIT, before Startup: rc `0x100`
   (TPM_RC_INITIALIZE). After Startup: rc `0x000`.
5. **Command codes verified live** (swtpm log prints
   `IsEnEnabled(0xNNN = 'Name')` for each accepted command):
   `0x144 Startup`, `0x17A GetCapability`, `0x181 ReadClock`.
   PCR codes `0x17E PCR_Read`, `0x182 PCR_Extend`, `0x13D PCR_Reset` are
   the ones used in the matrix below. Note: an early memory-based guess
   (`0x005E PCR_Allocate`) is **not a valid TPM 2.0 command code** in this
   build (rc `0x143` TPM_RC_COMMAND_CODE) — it is unnecessary anyway, see §5.
6. **`--locality allow-set-locality`.** `swtpm 0.10.2` exposes
   `--locality [reject-locality-4][,allow-set-locality]`. `CMD_SET_LOCALITY(4)`
   was accepted (rc 0) and the matrix run uses `allow-set-locality`
   explicitly. If a QEMU-facing swtpm is started without it, locality
   setting is the first thing that may silently misbehave; the QEMU TPM
   backend docs should call this out.
7. **`CMD_SET_BUFFERSIZE(0)`** returns the negotiated max buffersize
   4096 (min 2808) — the same query QEMU performs in
   `tpm_util_get_buffer_size()`.
8. **CMD_INIT runs libtpms self-tests** (RSA/Camellia/3DES) before
   responding; expect a noticeable delay, not a hang.

## 4. TPM 2.0 startup sequence used (QEMU-faithful)

```
connect ctrl socket
CMD_SET_DATAFD (socketpair fd via SCM_RIGHTS, same sendmsg)
ReadClock probe (version detection; expect tag 0x8001)
CMD_GET_CAPABILITY            -> caps 0x0001ffff
CMD_INIT(flags=0)             -> rc 0
CMD_SET_BUFFERSIZE(0)         -> 4096/2808/4096
data: TPM2_Startup(CLEAR)     -> rc 0x000
data: GetCapability(TPM_CAP_PCRS)   -> §5
data: (locality matrix, §6)
ctrl CMD_SHUTDOWN             -> rc 0
```

## 5. PCR allocation (no `PCR_Allocate` needed)

`GetCapability(TPM_CAP_PCRS=0x5, 0, 40)` response (43 B, rc `0x000`):

```
80 01 00 00 00 2B 00 00 00 00
00 00 00 05 00 00 00 04
04 00 04 03 FF FF FF 00 0B 03 FF FF FF 00 0C 03 FF FF FF 00 0D 03 FF FF FF
```

Decode (per parent-supervisor reading of this response): capability `0x05`,
count `4` hash banks — `0x0004` SHA1, `0x000B` SHA256, `0x000C` SHA384,
`0x000D` SHA512 — each with selection bitmap `FF FF FF`, i.e. **all 24 PCRs
allocated in every bank**. PCR 17 and PCR 18 therefore exist by default in
the SHA-256 bank; `TPM2_PCR_Allocate` is not needed and was removed from the
driver.

(One wire-level quirk of this build: in the raw response there is an
extra byte `04` between the count field and the first selection entry —
4 selections × 6 B start at offset 19 of the body, not 18. Irrelevant to
the conclusion; flag for anyone writing a strict parser.)

## 6. Locality matrix results

Sequence: baseline reads at locality 0 (post-Startup-CLEAR) → locality 4:
extend/read PCR 17, extend/read PCR 18, reset/read PCR 17, reset/read PCR 18
→ locality 3: extend/read PCR 17 → locality 0: extend/read PCR 17,
extend/read PCR 7 (control, must succeed at locality 0 per PTP).

**Results:** complete. Run `run_output3e.txt` (final, with the response
parser corrected); `run_output3d.txt.gz` is the earlier run with the same
rc outcomes but unverified digests. Digest column "MATCH" means the
observed PCR value equals the independently computed
`SHA256(previous_value || extend_digest)`.

Baseline after `Startup(CLEAR)`, before any DRTM activity:

| PCR | value |
|---|---|
| 17 | `ff` x 32 (all-ones = DRTM "never launched") |
| 18 | `ff` x 32 |
| 7  | `00` x 32 (SRTM PCR, normal zero init) |

| step | locality | rc | digest check |
|---|---|---|---|
| PCR_Read 17 / 18 / 7 (baseline) | 0 | `0x000` SUCCESS | see table above |
| SET_LOCALITY(4) | - | `0x000` SUCCESS | - |
| **PCR_Extend 17 (digest A)** | **4** | **`0x000` SUCCESS** | `9222...3879` **MATCH** |
| PCR_Read 17 | 4 | `0x000` SUCCESS | - |
| **PCR_Extend 18 (digest B)** | **4** | **`0x000` SUCCESS** | `1ea4...3bf4` **MATCH** |
| PCR_Read 18 | 4 | `0x000` SUCCESS | - |
| PCR_Reset 17 | 4 | **`0x907` TPM_RC_LOCALITY** | value unchanged (not zeroed) |
| PCR_Reset 18 | 4 | **`0x907` TPM_RC_LOCALITY** | value unchanged (not zeroed) |
| SET_LOCALITY(3) | - | `0x000` SUCCESS | - |
| PCR_Extend 17 (digest C) | 3 | `0x000` SUCCESS | `bc2d...73b3` **MATCH** |
| SET_LOCALITY(0) | - | `0x000` SUCCESS | - |
| **PCR_Extend 17 (digest D)** | **0** | **`0x907` TPM_RC_LOCALITY** | value unchanged - correctly denied |
| PCR_Extend 7 (digest E, control) | 0 | `0x000` SUCCESS | **MATCH** |

Answers to the questions posed:

1. **Locality-4 `PCR_Extend` of PCR 17: YES**, rc `0x000`, digest chain verified.
2. **PCR 18: YES**, same.
3. **Locality 3**: extend of PCR 17 also **succeeds** (PCR 17 is extendable
   from both locality 3 and 4, consistent with the PTP DRTM PCR attributes).
4. **Locality 0 control**: extend of PCR 17 is **refused** with
   `TPM_RC_LOCALITY (0x907)` and the value is unchanged, while PCR 7 at the
   same locality succeeds. Locality restrictions are therefore genuinely
   enforced by libtpms - not silently ignored.
5. **`TPM2_PCR_Reset` of PCR 17/18 fails even at locality 4** with
   `TPM_RC_LOCALITY`. The DRTM PCRs are not resettable by that command.

## 7. Caveats and version notes

- swtpm **0.10.2** specifically; libtpms behaviour may differ in other
  releases. The locality question is about libtpms, not the transport.
- `--tpm2` state: `--tpmstate dir=…`; each matrix run used a **fresh state
  dir** so PCR baselines were all-zero.
- The "data socket must exist before INIT" finding from earlier spike
  attempts was **not reproduced** (finding §3.1); treat the QEMU order as
  the safe one anyway.
- All earlier "TPM silent/wedged" observations in this spike were the
  8-byte-vs-10-byte header bug (§2.4), now fixed and byte-verified.

## 8. Implication for QEMU M3 (semantic SENTER)

**The core question is answered YES: a QEMU TXT device can drive
locality-4 DRTM measurements into PCR 17/18 through a swtpm backend**, and
the emulated TPM enforces the DRTM locality policy properly, so the
measurements mean something rather than being a rubber stamp. Three
concrete constraints fall out for M3:

1. **`--locality allow-set-locality` is mandatory.** Without it swtpm
   refuses `CMD_SET_LOCALITY` and no locality-4 work is possible. This is a
   *user-visible command-line requirement* for `-machine q35,txt=on` and must
   be documented in `docs/specs/intel-txt.rst` and any test harness that
   starts swtpm. It is not something QEMU can set on the guest's behalf.

2. **The semantic SENTER cannot zero the DRTM PCRs with `TPM2_PCR_Reset`** -
   that command is refused at every locality including 4. On real hardware
   PCRs 17-22 are reset by the TIS `_TPM_Hash_Start` / `_TPM_Hash_Data` /
   `_TPM_Hash_End` sequence asserted at locality 4 by the CPU during
   `GETSEC[SENTER]`, not by a TPM 2.0 command. **M3 open question:** does
   QEMU's `hw/tpm/tpm_tis_common.c` implement that hash-start/end path, and
   does the swtpm backend forward it? If not, M3 must either add it or
   accept that PCRs 17/18 start from the all-ones "never launched" value and
   extend from there - which changes the expected PCR values and therefore
   what any attestation/`txt-stat` comparison should expect.

3. **Locality must actually be set, not assumed.** Because libtpms enforces
   the policy, the TXT device has to issue the locality change through the
   backend before measuring; a semantic SENTER that extends at locality 0
   will be rejected with `0x907`, exactly as observed here.

Supporting detail for the implementation: the baseline all-ones value of
PCRs 17/18 confirms libtpms models the DRTM "no measured launch yet" state
correctly, and the verified digest chain
(`SHA256(previous || extend_digest)`) gives M3 a cheap self-check - after a
semantic SENTER the emulator can recompute the expected PCR value and assert
it, which is how this spike proved the extends were real.

---

*Report maintained live by the spike driver; raw outputs:
`run_output.txt` (spike.py A/B/B0), `run_output2.txt` (C/D),
`run_output3.txt`/`run_output3b.txt`/`run_output3c.txt` (spike3.py,
diagnostics + framing fixes), `run_output3d.txt` (matrix).*
