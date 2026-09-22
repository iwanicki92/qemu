# M3 — DRTM measurement path (GETSEC[SENTER] → locality-4 PCR extend)

Prerequisite: M2 (GETSEC/SMX decode + CAPABILITIES/PARAMETERS) is committed as
`c372060105`, reviewed `mergeable`.

This plan covers the TPM side of `GETSEC[SENTER]`: resetting and extending the
DRTM PCRs. The rest of the SENTER flow (ACM/heap validation, MLE hashing,
`sinit_mle_data_t`, MLE entry state) is specified in
`docs/specs/intel-txt.rst` "Steps performed by QEMU" a–i and is tracked
separately; M3 delivers steps **a** and **d** plus the plumbing they need.

## 1. Decision: QEMU synthesizes the measurement; no `hw/tpm/` changes

`_TPM_Hash_Start` / `_TPM_Hash_Data` / `_TPM_Hash_End` are **not** implemented
anywhere in QEMU's TPM stack, and M3 does not add them.

That absence is not a gap. Those are not TPM commands — they are LPC-bus
signals the chipset asserts to instruct a *physical* TPM to perform a DRTM
measurement. In this design QEMU stands in for the chipset (spec: "Steps
performed by QEMU (standing in for SINIT)"), so it produces the *effect* of the
sequence with ordinary TPM2 commands issued at locality 4:

- `TPM2_PCR_Reset` on PCRs 17–22 (resettable only from locality 4)
- `TPM2_PCR_Extend` on PCR 17/18/19 with the computed digests

swtpm exposes no hash-sequence command on either socket, so any design would
have to bottom out in this translation regardless.

This restates what `docs/plans/intel-txt.md` §2 and §3.4 and
`docs/specs/intel-txt.rst` (lines 23, 64, 346–354, 403) already specified.

### Rejected alternatives

- **Guest-visible locality-4 hash MMIO in `tpm_tis_common.c`.** Models an
  interface real hardware does not expose: the MLE uses localities 1–2 (opened
  via `TXT.CMD.OPEN.LOCALITY1/2`), the SINIT ACM uses locality 3, and locality
  4 is hardware-only. No real payload (tboot, TrenchBoot GRUB) would call it.
  It also puts TXT-specific code in the TPM frontend shared by every board,
  which will not survive upstream review, and risks `tpm-tis-test` regressions.
- **Driving swtpm's sockets directly from a test harness.** Useful as an
  independent oracle for expected PCR values, but not an implementation:
  `-machine q35,txt=on` would still measure nothing.

## 2. Locality 4 is already plumbed end to end — verified, zero new code

| Layer | Evidence |
|---|---|
| TIS accepts locality 4 | `hw/tpm/tpm_tis.h:30,34` — `TPM_TIS_NUM_LOCALITIES 5`, so `TPM_TIS_IS_VALID_LOCTY(4)` is true |
| Locality travels with the command | `TPMBackendCmd.locty` (`include/system/tpm_backend.h:29`) |
| Backend applies it per request | `backends/tpm/tpm_emulator.c:269` → `tpm_emulator_set_locality()` (`:230`) → `CMD_SET_LOCALITY` on the control channel |
| swtpm honours it | 0.10.2: locality 4 accepted by default; `--locality reject-locality-4` is opt-in *rejection* |

Consequence: a `TPMBackendCmd` with `.locty = 4` reaches swtpm at locality 4
today. M3 adds no code under `hw/tpm/` or `backends/tpm/`.

> Note: the earlier `~/txt-m0/spike/REPORT.md` locality-4 spike artifact is no
> longer on disk (`/home/michal/txt-m0` does not exist). The table above was
> re-derived from the QEMU sources and `swtpm --help` and supersedes it as the
> evidence base. Re-running the spike is optional; §5 covers it as a test.

## 3. Work items

### 3.1 TXT device gains a TPM backend link
`include/hw/i386/intel_txt.h` has no TPM field yet. Add a `TPMBackend *` to
`IntelTXTState`, resolved at realize. `hw/i386/pc_q35.c:346` already refuses
`txt=on` without a backend, so the lookup cannot fail late. Not migratable
state — it is a device link, re-resolved on incoming migration.

### 3.2 TPM2 command marshalling in the TXT device
`include/system/tpm_util.h` provides only header accessors (`tpm_cmd_set_tag`,
`tpm_cmd_set_size`, `tpm_cmd_get_errcode`, …) — there is no TPM2 command
builder in QEMU. M3 hand-rolls two commands in `hw/i386/intel_txt.c`:

- `TPM2_PCR_Reset(pcr)` — `TPM_ST_SESSIONS`, one password auth area
- `TPM2_PCR_Extend(pcr, digests)` — `TPML_DIGEST_VALUES` over the active banks

Keep these `static` and TXT-local. If a second consumer ever appears, promote
to `tpm_util.h` then, not now.

### 3.3 Submission discipline (the part that needs care)
`tpm_backend_deliver_request()` (`backends/tpm/tpm_backend.c`) has a **single**
`s->cmd` slot and bails with `"There is a TPM request pending"` when busy. So:

- Submit strictly one command at a time, each followed by
  `tpm_backend_finish_sync()`. Precedent: `hw/tpm/tpm_crb.c:247` (deliver) and
  `:350` (finish_sync).
- Guard against submitting while a TIS command is in flight. SENTER is a
  natural quiesce point (APs are parked), but the guard must be explicit.
- `tpm_emu->cur_locty_number` is cached in the backend and the TIS keeps its
  own per-locality state. Out-of-band locality-4 injection moves the backend's
  cached locality under the TIS. It self-heals — `set_locality()` re-sends
  whenever the number differs — but the two frontends must not interleave
  in-flight commands.

### 3.4 Resolved: inline in the helper, under the BQL

`tpm_backend_finish_sync()` spins `aio_poll(qemu_get_aio_context(), true)`,
and SENTER runs in **vCPU context** inside a TCG helper, so the question was
whether that call is legal there at all.

It is, conditionally. `aio_poll()` asserts
`in_aio_context_home_thread(ctx)` (`util/aio-posix.c`), and for the main
context that predicate is not "am I the main thread" but the BQL:

```c
/* include/qemu/aio-wait.h:139-150 */
static inline bool in_aio_context_home_thread(AioContext *ctx)
{
    if (ctx == qemu_get_current_aio_context()) {
        return true;
    }
    if (ctx == qemu_get_aio_context()) {
        return bql_locked();      /* <-- any thread, if it holds the BQL */
    } else {
        return false;
    }
}
```

So a vCPU thread may poll the main AioContext **provided it holds the BQL**.
A TCG helper does not hold it on entry, so the measurement path must take it
explicitly — `BQL_LOCK_GUARD()` (`include/qemu/main-loop.h:410`), or
`bql_lock()`/`bql_unlock()` as `misc_helper.c:302` does around
`apic_msr_write()`. Taking the BQL from an i386 TCG helper to reach a device
is already routine: `misc_helper.c:114,302,480`, `seg_helper.c:137`,
`fpu_helper.c:35`.

**Decision: shape (a), inline in the helper under the BQL.** It keeps the
launch sequence as straight-line code, which matters because spec steps e–i
must run strictly after the extends complete. Deferring to a bottom half
(shape (b)) buys nothing here: the vCPU has to be parked across the wait
either way, and the state machine would have to reconstitute the launch
context on resume.

Caveats to respect in the implementation:

- **We would be the first in-tree caller to do this from an instruction
  helper.** The nearest analogue, `spapr_nvdimm_finish_flushes()`
  (`hw/ppc/spapr_nvdimm.c:581`), carries a comment claiming a guest
  `h_client_architecture_support` path, but its only actual caller is
  `spapr_machine_reset()` (`hw/ppc/spapr.c:1830`) — the main thread. The
  other `aio_poll(qemu_get_aio_context(), true)` users (`hw/9pfs/9p.c:4562`,
  `:4569`) are reset paths too. Expect upstream to ask about this; the
  aio-wait.h contract above is the justification.
- **Reentrancy.** Spinning `aio_poll` runs main-loop AIO callbacks from the
  vCPU thread. Do not call into it from anywhere already inside an
  `aio_poll` dispatch, and keep the TXT device's own submit path
  non-reentrant (cf. the recursion warning at `hw/hyperv/vmbus.c:2178`).
- **Other vCPUs keep running** — plain TCG execution needs no BQL. Real
  SENTER rendezvouses the APs; M3 measures on the BSP only, so this is a
  known gap to close when GETSEC[WAKEUP] lands, not a blocker now.
- While the BSP holds the BQL and polls, the main loop thread blocks waiting
  for it. That is the standard pattern, but it means a hung swtpm stalls the
  whole VM rather than one vCPU. Bound it if swtpm proves flaky in practice.

### 3.5 Synthetic SINIT ACM fixture (needed only for loader-level tests)
QEMU never executes an ACM — it *is* the SINIT (master plan Option A). But a
blob must still sit in guest RAM, because the loader validates one and writes
`TXT.SINIT_BASE/SIZE` before it ever calls SENTER.

A synthetic, unsigned blob is sufficient: **tboot performs no crypto on the
ACM.** `grep -iE 'rsa|signature|pubkey|modulus' tboot/txt/acmod.c` is empty,
despite `acmod.h:74,76` declaring `rsa2048_pubkey[256]` / `rsa2048_sig[256]`.
Signature verification is the CPU's job on real hardware — the step this
design deliberately omits. So no Intel binary and no licence-encumbered blob
in-tree.

Constraints the fixture must satisfy (all structural — see the corrected
precondition 3 in `docs/specs/intel-txt.rst`):

- base 4 KiB aligned; `hdr->size * 4` == actual size; size % 64 == 0
  (`verify_acmod()`)
- size <= `params.acm_max_size` — **our M2 GETSEC[PARAMETERS] value, 32 KiB**
  (`verify_acmod()`)
- `module_type` 0x02, `module_vendor` 0x8086, `module_subtype` 0 (`is_acmod()`)
- info table UUID `ACM_UUID_V3`, `version >= 3`, `chipset_acm_type` 0x01
  (`is_acmod()`, `acmod.c:539`)
- `entry_point < size`; `seg_sel` non-zero, not LDT/PL!=0,
  `seg_sel + 8 <= gdt_limit` (`verify_acmod()`)
- capability intersection with the MLE on `rlp_wake_getsec` or
  `rlp_wake_monitor`, plus `ecx_pgtbl` (`verify_acmod()`)
- `chipset_id_list` contains our emulated `TXT.DIDVID`
  (`does_acmod_match_platform()`, `acmod.c:556,603-608`)

No executable code is needed — header + info table + chipset-id list +
padding, a few KiB. Two couplings worth noting:

- The size bound ties the fixture to M2's `GETSEC_PARAM_MAX_ACM_SIZE`, so that
  value is load-bearing rather than cosmetic.
- `chipset_id_list` must agree with whatever DIDVID the device reports. We
  control both sides for a synthetic ACM; the master plan's M6 item ("pin
  `didvid` against real SINIT ACM chipset-id lists") only matters if a real
  Intel ACM is ever used.

GRUB is more permissive than tboot: `grub-core/loader/slaunch/txt.c` checks
none of the ACM header fields, gating only on GETSEC[CAPABILITIES]
chipset-present (`:91`) and `grub_txt_verify_platform()`. It sets
`slr_intel_policy_staging.pcr = 18` for the OS-MLE data, which is directly
relevant to the PCR18 digest content.

**Scope note:** this fixture is a prerequisite for an end-to-end
loader-driven SENTER test, *not* for the locality-4 PCR path in §3.1–3.4.
That can be exercised from qtest with no ACM at all. Build the measurement
path first; add the fixture when the test moves up to a real loader.

### 3.6 Carried into M4: out-of-band completion disturbs the TIS frontend

`tpm_backend_request_completed()` (`backends/tpm/tpm_backend.c`) has no
notion of *who* submitted a command — it unconditionally calls the frontend's
`request_completed` for every completion:

```c
TPMIfClass *tic = TPM_IF_GET_CLASS(s->tpmif);
tic->request_completed(s->tpmif, ret);
```

So each TXT-issued DRTM command also runs `tpm_tis_request_completed()`
(`hw/tpm/tpm_tis_common.c:235-268`), which sets
`TPM_TIS_STS_VALID | TPM_TIS_STS_DATA_AVAILABLE`, moves the TIS to
`TPM_TIS_STATE_COMPLETION` at whatever locality the *guest* last used,
resets `rw_offset` and raises an IRQ — while the actual response bytes went
into the TXT device's private buffer, which the guest cannot read. The guest's
TPM driver therefore sees a completion for a command it never sent.

Plan §3.3 anticipated only the locality-cache interaction; this is a second,
larger side effect of sharing one backend between two frontends. It is
unreachable while SENTER is a `#UD` stub, but **the M4 SENTER increment must
address it** — either by saving and restoring the TIS locality/STS state
around the measurement, or by suppressing the frontend notification for
device-originated commands. The latter needs an API change under
`hw/tpm/`/`backends/tpm/`, which this design has so far avoided, so expect
that to be the point where the "no TPM-subsystem changes" property has to be
re-argued.

Two smaller items deferred with it:

- `TPMBackend::cmd` is marked `/*< protected >*/`
  (`include/system/tpm_backend.h:44-50`) but is the only way to detect an
  in-flight request, because `tpm_backend_deliver_request()` returns void and
  merely `error_report`s when busy. A public
  `tpm_backend_request_pending()` predicate would be the clean fix.
- The `txt_drtm_*` trace points fire before the send returns, so they log
  intent rather than success. Fine for tracing; do not read them as proof a
  measurement landed.

### 3.7 DECIDED: reset+extend the DRTM PCRs via the swtpm hash sequence

**Supersedes the `TPM2_PCR_Reset` half of §1.** That part of §1 was wrong.

#### What was wrong

§1 claimed QEMU could synthesise spec step a with `TPM2_PCR_Reset` at
locality 4. It cannot. Measured against swtpm 0.10.2 through the real device
path, `TPM2_PCR_Reset(17)` with `.locty = 4` returns **TPM_RC_LOCALITY
(0x907)**. This is not a transport fault: had `CMD_SET_LOCALITY` failed,
`tpm_emulator_handle_request()` would have written a `TPM_FAIL` (9) fatal
response instead. Locality 4 was applied and the TPM still refused, because on
real hardware PCRs 17-22 are not command-resettable at all.

The original M0/M3 spike had already established this ("semantic SENTER cannot
zero PCRs 17-22 via TPM2_PCR_Reset"). The §1 text mis-summarised it as
"extend + reset verified at L4", conflating extend (which does work) with
reset (which does not), and the implementation faithfully built the wrong
thing.

#### The mechanism that does work

swtpm's control channel implements the TIS hash signals, and QEMU already
vendors the protocol definitions in `backends/tpm/tpm_ioctl.h` without ever
using them:

    CMD_HASH_START  (0x06)      PTM_CAP_HASHING (1 << 4)
    CMD_HASH_DATA   (0x07)      struct ptm_hdata { u32 length; u8 data[4096]; }
    CMD_HASH_END    (0x08)

Measured directly against swtpm 0.10.2 (`caps=0x1ffff`, so
`PTM_CAP_HASHING` is present):

| step | PCR 17 (SHA-256 bank) |
|---|---|
| after `TPM2_Startup(CLEAR)` | `ffff…ff` (power-on DRTM value) |
| `CMD_SET_LOCALITY(4)` → `HASH_START` → `HASH_DATA` → `HASH_END` | `71120181fce97de7…` |

and that final value equals `SHA256(0x00*32 ‖ SHA256(data))` — i.e.
**HASH_START reset the PCR to zero and HASH_END extended it with the hash of
the data.** Exactly the hardware DRTM semantics, in one sequence, covering
spec step a and the PCR 17 part of step d together.

Two conditions matter:

- **`CMD_SET_LOCALITY(4)` must precede `CMD_HASH_START`.** Without it all
  three commands still return success but are silent no-ops — PCR 17 stays
  `ffff…ff`. A caller that only checks return codes would believe it had
  measured. This is the single most dangerous property of the interface.
- **`--locality allow-set-locality` is not required.** Tested both ways with
  identical results. (An earlier note claiming it mandatory was wrong for this
  path; that flag governs the TPM2 `SetLocality` *command*, not the control
  channel.)

#### Why this is not the rejected "Path 1"

§1 rejected adding guest-visible locality-4 hash MMIO to
`tpm_tis_common.c`, on the grounds that real hardware never exposes locality
4 to software. That reasoning stands and is untouched. This is the opposite
shape: the sequence is driven **out-of-band by the TXT device over the backend
control channel**, exactly as `CMD_SET_LOCALITY` already is, because QEMU is
standing in for the chipset that asserts those signals. No TIS change, no
guest-visible interface.

#### Work required

1. `TPMBackendClass` gains optional `hash_start` / `hash_data` /
   `hash_end` methods, with public wrappers in `tpm_backend.c`.
2. `tpm_emulator.c` implements them via
   `tpm_emulator_ctrlcmd(CMD_HASH_*)`, and must set locality 4 first.
   Do **not** add `PTM_CAP_HASHING` to the required-capability set in
   `tpm_emulator_probe_caps()` — that would reject backends that work fine
   for every non-TXT user. Check it only where TXT needs it.
3. `intel_txt_senter()` replaces the `PCR_Extend`-only measurement with
   the hash sequence over the measured region, and drops
   `intel_txt_drtm_reset_pcrs()`.
4. The guest test gains a PCR 17 readback asserting the value is no longer
   `ffff…ff` and equals the expected extend-from-zero — the first assertion
   in this project that actually proves a measurement landed.

This widens the TPM-subsystem footprint from two files to three
(`include/system/tpm_backend.h`, `backends/tpm/tpm_backend.c`,
`backends/tpm/tpm_emulator.c`). That is the "no TPM-subsystem changes"
property bending, as §3.6 predicted it would have to; it bends for the
mechanism the hardware actually uses, which is the right reason.

### 3.8 Verified locality-4 behaviour, and the step-c design it unblocks

Measured against swtpm 0.10.2 through the control channel, after
`TPM2_Startup(CLEAR)`. Recorded here because these facts are load-bearing
and an earlier spike's results were lost:

| operation | locality | result |
|---|---|---|
| PCR 17/18/19 initial read | 0 | `ffff…ff` (DRTM power-on value) |
| `CMD_HASH_START` | 4 | **resets all of PCR 17-22 to zero**, not just 17 |
| `CMD_HASH_END` | 4 | extends PCR 17 with the hash of the fed data |
| `TPM2_PCR_Extend(18)` | 4 | **succeeds**, result is extend-from-zero |
| `TPM2_PCR_Extend(18)` | 0 | rejected, `TPM_RC_LOCALITY` (0x907) |
| `TPM2_PCR_Reset(17)` | 0, 3, 4 | rejected, `TPM_RC_LOCALITY` (0x907) — see §3.7 |

Three consequences:

1. **Spec step a is already fully satisfied** by `_TPM_Hash_Start`. It zeroes
   the whole DRTM range, so no separate per-PCR reset is needed for 18-22
   either. The §3.7 wording ("resets the DRTM PCRs") is now verified beyond
   PCR 17.
2. **Step c is unblocked and needs no new mechanism.** PCR 18 takes the MLE
   hash via `intel_txt_drtm_extend_pcr()` — the helper deliberately retained
   in `d68257ff6a` — at locality 4, which is what the real SINIT ACM does.
   Because `_TPM_Hash_Start` has already zeroed PCR 18, the expected value is
   a clean `H(0…0 ‖ mle_hash)` and is therefore assertable in the guest test
   exactly as PCR 17 now is.
3. **The locality-0 rejection is the control.** It proves `.locty = 4` is
   doing real work rather than being ignored: the identical command fails at
   locality 0 and succeeds at locality 4. Any future regression in the
   locality plumbing will show up as `TPM_RC_LOCALITY` rather than as a
   silent wrong-locality measurement.

#### Step c work items

- Parse the TXT heap: `os_sinit_data` → `mle_ptab`, the MLE header at
  `mle_hdr_base` (which must lie inside `[mle_ptab, mle_ptab + mle_size)`,
  spec precondition 4), then `mle_start_off` / `mle_end_off` /
  `first_valid_page`.
- Hash the MLE pages in each active bank and extend PCR 18.
- Extend the guest test with a PCR 18 assertion mirroring the PCR 17 one.
- Precondition 4 currently only checks that HEAP_BASE/SIZE are non-zero and
  below 4 GiB; the structural parsing checks land with this slice.

## 4. Deliberate fidelity gap to document
QEMU does not gate locality-4 MMIO the way a real chipset does, so a guest can
reach locality 4 through the existing TIS and extend PCR 17/18 itself. This is
acceptable for a development platform but must be stated explicitly: the
emulation is **not** a trust boundary. Add as a numbered item under
"Deviations from real hardware" in `docs/specs/intel-txt.rst`, alongside the
existing caveat that PCR values are not valid for remote attestation.

## 5. Test plan
- **qtest** (`tests/qtest/txt-test.c`): with a real `tpmdev emulator` backend,
  drive SENTER's measurement step and read PCR 17/18 back at locality 0;
  assert they moved off the pre-launch all-ones value and match digests
  computed in the test. Extends the existing M1 txt-test.
- **Locality enforcement**: `TPM2_PCR_Reset(17)` must fail from locality 0 and
  succeed from locality 4 — this is the property the whole design rests on, so
  assert it directly rather than assuming it.
- **Build with `--enable-docs`.** M1 and M2 were both verified with
  `--disable-docs`, so Sphinx never ran and two reST defects sat in
  `docs/specs/intel-txt.rst` undetected — one of them (a malformed table)
  silently dropped the entire register map from the rendered output. The
  configure line for this work is:

  ```
  ./configure --target-list=i386-softmmu --enable-docs --disable-tools
  ```

  `make` then builds `docs/manual/specs/intel-txt.html` as part of the
  normal target list, and any reST regression shows up as a build warning.
  Spot-check with `grep -c '<tr' build/docs/manual/specs/intel-txt.html`
  (expect 28 register rows) if the table is touched.

- **Regression**: `tpm-tis-test`, `q35-test`, `txt-test` must stay green.
  M3 touches no TPM frontend code, so any movement here is a real bug.
- **ACM validation** (once §3.5 lands): the fixture is accepted, and each
  mutated field from §3.5 is rejected with the right `TXT.ERRORCODE`. Include
  a `module_subtype = 0x01` (reset ACM) case — the pre-correction spec wording
  would have *accepted* that one and rejected every real SINIT.

### Carried over from the M2 review (`d99ea234`, verdict `mergeable`)
- `#GP(0)` on `GETSEC` at CPL≠0 is verified by code reading only
  (`smx_helper.c:67-75`); the guest test skips it because it needs a CPL3 drop.
  Add CPL3 coverage here.
- The AAA-opcode regression argument for the GETSEC decode entry was
  by-construction, never run. Do one `check-tcg-i386` pass
  (`tests/tcg/i386/test-i386.c:1099-1106` covers `aaa`).

## 6. References
- M2 commit `c372060105`; M2 review run `d99ea234` (verdict `mergeable`)
- Spec: `docs/specs/intel-txt.rst` — SENTER steps a–i (lines 344–370),
  device/backend wiring (line 403), deviations (line 413)
- Master plan: `docs/plans/intel-txt.md` §3.4 (TPM integration), §3.5 (wiring)
- Code: `hw/tpm/tpm_tis.h:30`, `backends/tpm/tpm_emulator.c:230,269`,
  `backends/tpm/tpm_backend.c` (deliver/finish_sync), `hw/tpm/tpm_crb.c:247,350`
- Intel TXT MLE Software Development Guide 315168-017 §1.9 (DRTM PCR digests)
