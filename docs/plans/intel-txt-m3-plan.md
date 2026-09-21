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

### 3.4 Open design question — resolve before writing the submit path
`tpm_backend_finish_sync()` spins `aio_poll(qemu_get_aio_context(), true)`.
The CRB calls it from a reset handler; SENTER runs in **vCPU context** inside a
TCG helper. Blocking a vCPU thread there needs BQL care.

Two candidate shapes, to be decided first:

- **(a) Inline in the helper** — simplest control flow, blocks the vCPU across
  several swtpm round trips.
- **(b) Deferred to a bottom half** with the vCPU parked, resuming the launch
  on completion. More machinery, but it matches how QEMU normally treats
  long-running device work and composes better with steps e–i, which must run
  after the extends.

Recommendation: prototype (a) to get PCR values on the wire, then move to (b)
if the vCPU stall is observable or if step ordering forces it. Do not design
the full state machine before the measurement path is proven.

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
