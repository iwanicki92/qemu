# Intel TXT (SMX / DRTM) support in QEMU — implementation plan

Status: M0 complete (spec extracted, Option A decided). Target tree:
qemu.git @ master. Target accel: **TCG only** (KVM
cannot virtualize SMX; nested DRTM launch is out of scope).

**Single source of truth for the register map, heap layout and launch
flow: `docs/specs/intel-txt.rst`** (extracted from coreboot
`src/security/intel/txt/txt_register.h`, tboot `include/txt/*` and
TrenchBoot GRUB `loader/slaunch/`; sources under `~/txt-m0` — may need
re-cloning, see daily notes).

---

## 1. What "TXT support" actually means for QEMU

A full TXT measured launch involves four cooperating domains:

1. **CPU (SMX)**: `GETSEC` leaves (`SENTER`, `SEXIT`, `EXITAC`, `PARAMETERS`,
   `WAKEUP`, `SMCTRL`, `ENTERACCS`), gated on `CR4.SMXE`, `CPUID.1.ECX.SMX`,
   and a TXT-capable chipset (detected via power-on configuration / chipset
   TXT registers DID/VID).
2. **Chipset (MCH / TXT config space)**: public registers at `0xFED3_0000`,
   private registers at `0xFED2_0000`, TPM decode window at `0xFED4_0000`
   (= the existing tpm-tis MMIO region, localities 0–4),
   TXT heap pointers, SINIT.BASE/SIZE, `TXT.STS`, `TXT.ESTS`, `TXT.ERRORCODE`,
   DPR (DMA Protected Range) in MCH config space + TXT MMIO offset 0x330.
3. **TPM**: DRTM PCRs 17–22, extended from **locality 3/4** (TIS localities,
   TPM decode region) during SENTER; locality 4 for the MLE/launch policy
   measurements.
4. **Guest firmware/bootloader/kernel**: coreboot TXT init (DPR, heap, BIOS
   data elements), GRUB Secure Launch or tboot (loads SINIT ACM + MLE, calls
   `GETSEC[SENTER]`), Linux `slaunch`/tboot to continue after measured launch.

QEMU today: CPUID `smx` flag exists (propagated, settable via `-cpu ...,+smx`),
`CR4_SMXE_MASK` exists, tpm-tis implements all 5 localities. **Everything else
is missing**: GETSEC is #UD, no TXT MMIO, no DPR, no DRTM flow.

---

## 2. The central architecture decision: semantic SENTER vs. real ACM execution

### Option A (recommended first): semantic / functional emulation
`GETSEC[SENTER]` is implemented by QEMU itself performing the DRTM steps that
the SINIT ACM performs on real hardware:

- validate MLE range + FIT/heap inputs against TXT registers,
- "measure" the MLE (hash via QEMU crypto, sha1/sha256 per TPM bank),
- extend TPM PCRs 17/18/19 at locality 4 through the tpm-tis backend,
- populate/verify TXT heap (MLE elements), set `TXT.STS` MLE-JOIN,
- rendezvous APs (WAKEUP semantics), perform the equivalent of
  `GETSEC[EXITAC]` and transfer control to the MLE entry point with the
  documented measured-launch CPU state.

Rationale: the goal is a *platform for developing and testing DRTM software*
(coreboot, GRUB/trenchboot, kernel slaunch, tboot, attestation tooling), not
an adversarially faithful model of Intel's signed ACM — whose internals are
NDA'd and include chipset-undocumented interfaces. Existing precedent:
QEMU never executes real Intel-ACP code anywhere else (SGX models semantics
rather than the real ucode flows).

### Option B (later, optional): execute a real SINIT ACM under TCG
- verify ACM RSA signature with Intel's public key (QEMU crypto + crypto
  subsection), authenticate chipset/table values, run ACM code from an
  "authenticated RAM" region with AC-mode CPU state, then transfer to MLE.
- Interesting for security research (cf. CheckM8 / 9eLabs txt-suite work), but
  depends on undocumented private-space behavior and per-generation ACMs.
  Do **not** block the project on this; design hooks so it can be added as
  `txt-mode=acm-exec` later.

**Decision needed early, affects everything downstream. Default: Option A.**

---

## 3. Component breakdown

### 3.1 New device: Intel TXT chipset (`hw/i386/txt.c` or `hw/misc/intel_txt.c`)
`TYPE_INTEL_TXT` (SysBusDevice), instantiated by the machine when
`-machine txt=on` (q35 only initially):

- MMIO region 1 — TXT **public** config @ `0xFED3_0000` (size 0x10000):
  `TXT.STS` (0x00), `TXT.ESTS` (0x08), `TXT.ERRORCODE` (0x30),
  `TXT.CMD_RESET` (0x38), `TXT.CMD_CLOSE_PRIVATE` (0x48),
  `TXT.SINIT.BASE` (0x270)/`SIZE` (0x278),
  `TXT.HEAP_BASE` (0x300)/`SIZE` (0x308), `TXT.MLE_JOIN` (0x290),
  DPR (0x330), locality open/close (0x380–0x398), DID/VID (0x110),
  `VER_FSBIF` (0x100)/`VER_QPIIF` (0x200), `TXT.PUBLIC_KEY` (0x400),
  `TXT.E2STS` (0x8f0) — full map extracted in
  `docs/specs/intel-txt.rst` (M0 deliverable, single source of truth).
- MMIO region 2 — TXT **private** config @ `0xFED2_0000` (0x10000): mostly
  write-once, used by SINIT in real HW; under Option A keep minimal stubs +
  lock-down semantics.
- MMIO region 3 — **TPM decode** @ `0xFED4_0000`: this is exactly the existing
  tpm-tis region (base 0xFED40000, 5 localities at +n*0x1000). No new mapping
  needed; the TXT device only needs a backend link to issue locality-4
  measurements itself.
- TXT heap lives in guest RAM; device only stores base/size registers +
  validation callbacks.
- VMStateDescription for everything; trace events for every register access
  (`trace_txt_reg_read/write`, `trace_txt_senter_*`).

### 3.2 Chipset-presence + DPR in q35 MCH (`hw/pci-host/q35.c`)
- Add DPR PCI config register(s) (offset per extracted register map) with
  lock-bit semantics; DPR cover is enforced by converting the covered guest
  RAM range to ROM/protected via memory region after lock (phase M5 —
  register-only stub first).
- TXT device sets the "TXT-capable chipset" VID/DID values the CPU model and
  GETSEC emulation consult (SENTER preconditions include chipset checks).

### 3.3 CPU / TCG work (`target/i386/`)
- `target/i386/tcg/translate.c`: decode `0F 37` (GETSEC); currently #UD.
  Gate on `CR4.SMXE` and CPL0 → otherwise #UD/#GP per SDM.
- New `target/i386/tcg/smx_helper.c`: `helper_getsec(env, leaf)`:
  - `GETSEC[PARAMETERS]` — report supported leaves;
  - `GETSEC[SENTER]` — hand off to the TXT device via a CPU state /
    qom link (cf. how TCG reaches APIC/KVM for similar chipset asks);
  - `GETSEC[EXITAC]`, `GETSEC[SEXIT]` — MLE → OS handoff / teardown
    (SEXIT resets platform: full machine reset);
  - `GETSEC[WAKEUP]` — AP wakeup in measured environment;
  - `GETSEC[SMCTRL]` — SMM control in measured environment (stub);
  - `GETSEC[ENTERACCS]` — only relevant for Option B (stub → #UD first).
- CPU state: AC-mode / measured-environment flags in `CPUX86State` (must be
  migrated; add to `env` VMState + forbid migration mid-launch or snapshot
  states carefully — simplest: migration allowed only outside a launch
  sequence).
- CPU model: default-enable `smx` for the TXT machine's default CPU; keep
  `-cpu ...,+smx` as manual override on other machines.

### 3.4 TPM integration (`hw/tpm/`)
- tpm-tis is reused as-is (localities 0–4 ✓, `TPM_TIS_ADDR_BASE` 0xFED4_0000).
- New code path: helper API for the TXT device to issue
  `TPM2_PCR_Extend` at locality 4 against the configured tpmdev backend
  (follow the pattern of existing tpm_be calls; PCR banks per TPM
  capabilities: sha1/sha256/… — hash the MLE for every active bank).
- Verify swtpm (TPM 2.0) allows locality-4 PCR 17–22 extends and locality
  3 "DRTM locality" behavior; add tests.
- Guest ACPI: TPM2/TCPA table emission already exists — no new ACPI table
  strictly required for TXT (Linux TXT/tboot use CPUID + TXT MMIO +
  boot-params slaunch blob, not a TXT ACPI table).

### 3.5 Machine wiring (`hw/i386/pc_q35.c`)
- `txt` machine property: creates `intel-txt` device, requires tpm-tis +
  `-object tpm-backend` (error out otherwise), sets SMX by default,
  maps the three MMIO regions, links TXT ↔ CPU ↔ TPM.
- Consider a dedicated `q35-txt` machine alias if default-on is intrusive.

---

## 4. Milestones

### M0 — Spec & reference-code extraction (foundation; ~1–2 weeks)
Extract the *authoritative register map and flows* from code that runs on real
HW (no NDA required):
- coreboot: `src/security/intel/txt/` (register map, heap structures, DPR
  programming, launch validation) + `src/include/…/txt.h`.
- Linux: `arch/x86/kernel/intel_txt.c`, `arch/x86/kernel/tboot.c`,
  `Documentation/arch/x86/intel_txt`, secure-launch (TrenchBoot) slaunch code,
  `Documentation/arch/x86/boot` for the slaunch boot-params handoff.
- tboot + 9eLabs/coreboot txt-tools: heap/ACM structure headers,
  `txt-stat` parsing logic (use as an oracle for dumpable state).
- Intel public docs: TXT SW Dev Guide (315168), TXT MLE Dev Guide (315168-01),
  GETSEC/SENTER SDM pages, corebook `security/intel/txt.md`.
- Deliverable: `docs/specs/intel-txt.rst` in-tree documenting the emulated
  register map + the Option A launch flow + explicit deviations from HW
  (no signature check, semantic SENTER, simplified private space).

### M1 — TXT chipset device skeleton ✅ DONE (implemented + reviewed + verified)
- Delivered: `hw/i386/intel_txt.c` + `include/hw/i386/intel_txt.h` (public MMIO
  @ 0xFED30000/64K + private @ 0xFED20000/64K, full M1 register set, DPR
  write-once lock, ESTS W1C, locality/secrets/close-private/reset commands,
  VMState, `didvid` property, default `0x29C0:0x8086` placeholder),
  `-machine q35,txt=on` wiring with TPM-backend requirement
  (`qemu_find_tpm_be_any()` in system/tpm.c), trace events,
  `tests/qtest/txt-test.c` (12 tests, all passing; build clean, regressions
  tpm-tis 5/5 + q35 6/6).
- Deferred (explicit tasks, do not lose):
  - M3: SINIT.SIZE-vs-DPR bounds check on SENTER preconditions
    (spec §public register map, 0x278).
  - M5: MCH PCI-config DPR mirror (offset unverified vs Q35 datasheet;
  TXT MMIO DPR at 0x330 is complete since M1).
  - M6: pin `didvid` against real SINIT ACM chipset-id lists
    (tboot/grub only sanity-check format today).
  - M7 hardening: qtest for the no-TPM-backend machine-init error exit
    (needs expected-process-death harness; CLI smoke-verified manually).
  - P2 from review: copyright attribution on new files is currently
    "Intel Corporation" — replace with the author's real attribution
    before any upstream posting.

### M2 — GETSEC decode + static semantics (~1 week)
- translate.c decode, helper skeleton; `GETSEC[PARAMETERS]` correct;
  `SENTER`/`SEXIT` reach the device but return defined errorcodes;
  #UD/#GP gating tested (qtest + TCG boot test).

### M3 — Semantic measured launch (the core; ~3–5 weeks)
- SENTER input validation (CR4.SMXE, CPL0, MLE/heap/SINIT registers
  consistency, monitored MLE memory sizing per PARAMETERS/MONITOR ht).
- MLE hash → PCR extend 17 (MLE), 18 (policy/control), 19 via tpm backend
  locality 4 (bank-aware hashing).
- Heap population (MLE elements), `TXT.STS` MLE-JOIN, AP rendezvous
  (`WAKEUP`), `EXITAC`-equivalent transfer to MLE entry, CPU state per MLE
  guide (mode, cr0/cr4 masks, APIC state).
- Guest-side unit driver: a minimal bare-metal MLE test payload (qtest/
  pxe-able ELF) — lets us test M3 before any real guest stack is ready.

### M4 — Teardown + error semantics (~1–2 weeks)
- `GETSEC[SEXIT]`: **not** a platform reset. Execution continues at the
  instruction after the leaf, in the pre-SENTER CPU state; the chipset
  clears `STS.SENTER_DONE`, closes private space, releases DPR/PMR and
  sets `STS.SEXIT_DONE`, while SINIT/HEAP/DPR stay programmed so a
  further SENTER can follow in the same power cycle. The earlier
  "SEXIT = full machine reset" wording in this plan was wrong: tboot
  runs `__getsec_sexit()` and then keeps executing to hand off to the
  OS (`tboot/txt/txt.c`, `txt_shutdown()`). It requests a real platform
  reset via `TXT.CMD.RESET` only when APs are stuck in wait-for-SIPI,
  which is a separate path. See `docs/specs/intel-txt.rst`.
- PCR 17-22 lifecycle sanity (PCRs survive SEXIT; a later SENTER
  re-measures through the hash sequence), DPR teardown.
- Error injection: `-global intel-txt.errorcode-inject=…` or a qtest
  write to ESTS/ERRORCODE; LT error handling (reset, no-go), txt-stat
  readable failure codes.

### M5 — DPR enforcement + lockdown (~1 week)
- After launch: make DPR-covered RAM + TXT private space actually
  write-protected via memory region mode flips; DMA (device) access denied
  via IOMMU-ish hook or region permission (QEMU trusts itself — this is
  functional, not adversarial, protection).

### M6 — Real guest stack end-to-end (~2–4 weeks, parallelizable)
- coreboot qemu-q35: TXT init (DPR, SINIT region, BIOS heap), building on
  existing coreboot TXT code — the QEMU board now exposes everything it needs.
- GRUB2 slaunch (TrenchBoot) or tboot as measured launcher; Linux
  secure-launch kernel as MLE; `txt-stat`/tpm2-tools in guest for
  verification; PCR quote via swtpm outside the guest.
- This is the acceptance test for the whole project.

### M7 — Hardening + upstreaming (~2 weeks)
- Migration blockers/VMState, docs (`docs/system/i386/txt.rst`), coverity
  clean, split into reviewable series (device / TCG / machine / tests),
  RFC to qemu-devel. Expect heavy review; keep TCG-only scope crisp.

Total: roughly **3–4 person-months** to a TrenchBoot-viable prototype, with
M0–M2 giving an early demoable checkpoint.

---

## 5. Key risks & open questions

| Risk | Mitigation |
|---|---|
| Register map drift across TXT generations (FSB vs QPI-era, Q35-era vs modern) | Pin to **one** generation for v1 (pick what coreboot+kernel target today); document deviations. |
| ACM internals NDA'd | Option A sidesteps; Option B explicitly out-of-scope initially. |
| Locality-4/3 semantics in swtpm | Early spike in M0/M3: raw TIS locality 4 PCR-extend test against swtpm. |
| GETSEC from TCG vs KVM divergence | Explicitly disable on KVM (error at machine init), document. |
| SENTER CPU-state fidelity (MLE entry state is intricate) | Use MLE dev guide + tboot/GRUB as oracle; the guest loaders tolerate real HW variance anyway. |
| q35 emulation of DPR affecting normal boot (e.g. SeaBIOS/grub writes) | Keep protected-range enforcement behind launch state machine. |
| Upstream resistance to security-semantics emulation ("fake trust") | Frame as DRTM *software development platform*, akin to tpm-tis itself; upstream-worthy parts (GETSEC decode, chipset regs) are cleanly separated. |

---

## 6. Immediate next actions

1. ~~M0 extraction~~ **DONE**: register map + heap + SENTER calling
   convention extracted from coreboot/tboot/GRUB into
   `docs/specs/intel-txt.rst` (single source of truth). Sources under
   `~/txt-m0` (coreboot sparse, tboot, TrenchBoot/grub `grub-sl-2.12-v16`).
2. Decide Option A (recommended) and record the decision. — recorded in the
   spec; treat as decided unless contradicted.
3. Spike: swtpm locality-4 PCR extend from a tiny TIS test in QEMU
   (qtest), before any SENTER code exists.
4. ~~M1 device skeleton + qtest~~ **DONE** — reviewed "OK with notes",
   review P2s fixed (PUBLIC_KEY non-zero marker + 4-qword range, ESTS W1C /
   capabilities / SPAD/ERRORCODE tests, comment + spec wording fixes).
   Remaining background: scout handoff + swtpm locality-4 spike reports
   (still running) — fold into M2/M3 planning.
