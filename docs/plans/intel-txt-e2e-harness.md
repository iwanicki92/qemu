# Intel TXT full-system acceptance harness

## Objective and status

Run the real tboot boot chain under the modified QEMU, and evaluate the whole
TXT lifecycle rather than infer integration correctness from component tests.
This is a functional emulation acceptance suite, not proof of a security boundary
against the host or a proof of complete architectural correctness.

Initial baseline:

- QEMU source: `db42739ebe` (record the full resolved commit and dirty diff for
  every actual build/run).
- tboot source: `c9ca81f41b4a3eaa8e00c12a3d1d6d3c783782d4`, currently available at
  `/home/michal/qemu-txt-work/tboot`. This path is a development convenience,
  not a portable runner requirement.
- Full-system boot: **not yet attempted by this harness**.
- Current SENTER is staged. A passing component test expecting
  `LAUNCH_INCOMPLETE` is not evidence of a successful measured boot.
- The master plan places MLE entry/transfer in M3; M4 is teardown and error
  semantics. Completion of the recent M3 test tasks did not complete M3 itself.

## Target boot chain

```
host runner -> fresh swtpm + QEMU TCG/Q35/TXT
            -> firmware -> GRUB -> tboot -> Linux -> test initramfs
```

Tboot itself is the MLE. QEMU supplies the modeled chipset/processor/SINIT
behaviour, including entering tboot's post-launch path. A synthetic unsigned
SINIT module is allowed by the emulation contract; its contents must pass real
tboot's checks, not merely QEMU's current unit-test validator.

Use pinned sources/configurations and generated artifacts with hashes. Do not
patch tboot to skip platform checks, skip GETSEC, or force a success branch.
Keep any observability-only patch separately identified and reviewable. The
firmware must supply the required platform initialization; which implementation
can do this is a discovery item, not an assumption that stock firmware works.

## Oracle boundaries

- Real tboot checks loader/platform compatibility and executes the measured
  launch, OS handoff and shutdown paths.
- Intel architecture and TPM/PTP specifications define hardware semantics.
  Tboot is not a reference implementation of SINIT's internals. In particular,
  verify SEXIT versus subsequent platform reset behaviour before implementing it.
- Independently generated fixture hashes, event-log replay and TPM quote
  verification check measurements. Do not copy expected digests out of QEMU's
  implementation or accept a PCR readback alone as evidence of a full launch.
- A small diagnostic MLE may inspect entry state precisely, but cannot replace
  successful execution of the real tboot/Linux chain.

## Required acceptance groups

| Group | Evidence required for pass |
| --- | --- |
| Provenance | Source revisions, configurations and artifact hashes recorded |
| Firmware/loader | Consistent heap, memory map, DPR and SINIT placement; real tboot accepts the platform and ACM |
| Launch | Actual SENTER followed by tboot post-launch execution, valid TXT state and populated output heap |
| Entry state | Required CPU registers/state and page mappings verified by diagnostic checks and real MLE execution |
| SMP | Single-CPU baseline first. AP rendezvous/wakeup and all configured CPUs online is gated on the MWAIT-parking dependency noted below, not assumed reachable |
| OS handoff | Linux recognises the tboot shared handoff; initramfs reports measured-launch status |
| Measurements | Event log replay agrees with selected active PCR banks; quote signature, fresh nonce and PCR digest verified |
| TPM sharing | Ordinary guest TPM commands remain usable after launch; no unsolicited frontend completions |
| Protection | CPU/DMA and locality access restrictions match the declared emulation contract |
| Teardown | Tboot shutdown paths and SEXIT follow the verified architecture; reset/relaunch lifecycle checked separately |
| Failure handling | Invalid launch inputs/backend failures cannot produce a passing measured boot |

These groups start as **not implemented/not run**, not implicit passes.
An ordinary Linux fallback boot must never satisfy launch or handoff acceptance.

## Runner contract

Use a host-side runner with explicit artifact paths and a per-run output
directory. Prefer standard-library Python for process/QMP orchestration unless
existing QEMU test infrastructure provides a better fit.

- Fresh swtpm state for independent cases; preserve state only for explicitly
  labeled lifecycle tests.
- Unique sockets and process ownership per run; bounded startup, boot and
  shutdown deadlines; terminate only processes created by this run.
- Preserve serial/debug logs, QEMU stderr, QMP events, TPM evidence, command
  arguments, versions, configurations and artifact hashes even on failure.
- Distinguish infrastructure errors, timeouts, launch rejection, unimplemented
  phases and assertion failures in machine-readable results.
- Full acceptance returns success only when every mandatory assertion passes.
  Capturing an expected baseline failure is a development result, not a full
  acceptance pass.
- Classifiers themselves need tests: ordinary boot, missing markers, truncated
  logs, backend startup failure, timeout, and clean measured-boot evidence.
- Avoid privileged host setup, host disk modifications, network exposure and
  automatic package installation. Build in dedicated output directories.

## Implementation sequence

1. Inspect the pinned tboot build and boot contract, available boot-image tools,
   firmware prerequisites and suitable Linux artifacts. Return concrete recipes
   and source-cited prerequisites before selecting artifacts.
2. Build the real boot image and a minimal evidence-preserving runner. Run it
   against current QEMU and capture the **actual first failure**. It may precede
   SENTER; do not pre-label it as the known missing transfer step.
3. Map observed failures to implementation gaps. Add phase-specific assertions
   and negative controls before changing emulation to advance a phase.
4. Advance through launch, Linux handoff, measurements, SMP, protection and
   teardown. Keep the full acceptance checklist visible while individual groups
   turn green.
5. Retain existing qtest/TCG tests for fault isolation and regression coverage;
   run them alongside, never as a substitute for end-to-end acceptance.

## Direct reconnaissance findings

Delegated reconnaissance was stopped at the operator's request; these findings
come from direct source and host inspection. No full-system boot has run yet.

### Build and boot artifacts

- Host tools available: GCC, ld, grub-mkrescue, grub-mkstandalone, xorriso,
  cpio, swtpm and Docker. GRUB's `i386-pc/multiboot.mod` is installed.
  A `gcc -m32 -ffreestanding` compile-only probe succeeded. BusyBox is absent.
- Build only tboot's freestanding target first, not the host policy tools:
  `make -C <isolated-source-copy>/tboot`. `tboot/Makefile` produces `tboot.gz`;
  `tboot/Config.mk` forces 32-bit code and a freestanding header environment.
  This recipe is source-derived, not yet build-verified. Use an isolated copy
  of the pinned revision because this Makefile writes into its source tree.
- `README:73-83` and `tboot/20_linux_tboot:144-152` establish the GRUB order:
  multiboot tboot, module Linux, module initramfs, module SINIT last.
  Serial defaults are `115200,8n1,0x3f8` (`tboot/common/cmdline.c:77-81`).
- All three inspected host kernel configurations under
  `/usr/lib/modules/*/build/.config` have `CONFIG_INTEL_TXT` unset. These cannot
  serve as the final Linux handoff oracle. Select/build a pinned TXT-enabled
  kernel and a dedicated initramfs; do not reuse the host root/initramfs setup.

### Launch prerequisites and expected gaps

- `tboot/common/tboot.c:320-461` is the actual pre/post-launch dispatch.
  It locates and copies SINIT, validates it, detects the TPM, checks SVN/policy,
  validates TXT/platform/loader state and then launches. This ordering matters:
  an ACM-placement failure can precede the expected CPU/platform diagnostic.
- `tboot/txt/acmod.c:696-754` requires a BIOS-reserved nonzero SINIT base and
  sufficient SINIT size before copying the boot module. QEMU resets these and
  HEAP_BASE/SIZE to zero (`hw/i386/intel_txt.c:1280-1284`). Firmware initialization
  is therefore a real prerequisite, not something GRUB module loading supplies.
- `verify_acmod()` (`tboot/txt/acmod.c:867-983`) checks selector/GDT bounds,
  compatible RLP wake capabilities and OS-to-SINIT version in addition to the
  fields covered by our unit fixture. `does_acmod_match_platform():581-648`
  checks production/debug signing flags and, for info-table version >=4,
  processor identity. Generate an integration fixture for these real checks;
  do not simply reuse the unit fixture or weaken tboot.
- `supports_txt()` (`tboot/txt/verify.c:122-237`) checks Intel identity, SMX,
  locked/enabled feature-control MSR and required GETSEC capabilities. It also
  requires VMX *unless* `use_mwait()` is true, in which case the VMX check is
  skipped entirely. **Decision: run tboot with `ap_wake_mwait=true`.** The
  reasoning is recorded in `docs/specs/intel-txt.rst`; in short, tboot's default
  parks APs in a VMX mini-guest and QEMU TCG implements no VMX at all, while the
  MWAIT parking loop still makes progress because TCG resolves MWAIT on an AP to
  `helper_pause()`, a yield rather than a halt. This also means QEMU never has to
  advertise a VMX capability it cannot honour.
  Note the RLP *wake* stays GETSEC[WAKEUP] and is chosen separately, by what the
  ACM advertises (`txt/txt.c:607-620`); only the *parking* is the MWAIT path.
  `use_mwait()` additionally requires SSE3, so the CPU model must carry it.
- Open dependency for SMP: with MWAIT parking the OS wakes each AP by writing
  `ap_wake_trigger` in the tboot shared page, so Linux needs tboot MWAIT support.
  The tboot README warns the system "can never boot up" without it. Unverified
  here (no kernel source tree available). Irrelevant at one vCPU, where there are
  no APs at all, but it gates the SMP acceptance group.
- `txt_verify_platform()` (`tboot/txt/verify.c:364-391`) also requires VT-d BIOS
  enablement and valid BIOS heap data. A firmware image and matching DMAR/VT-d
  configuration must be selected and verified, not assumed.

### Evidence and teardown semantics

- `tboot/common/tboot.c:358,430-432` emits `SINIT ACM successfully returned...`
  and `Post_launch started ...` on the launched path. These are phase markers,
  not sufficient alone for full success. Correlate with launch state and Linux
  handoff. `tboot/common/linux.c:432-435` writes `tboot_shared_addr`.
- `tboot/txt/txt.c:1225-1268` clears secrets, unlocks memory configuration,
  closes private space and calls SEXIT; it then prints
  `measured environment torn down`. A distinct stuck-AP path requests TXT reset.
  Thus the master plan's unconditional identification of SEXIT with machine
  reset is inconsistent with this consumer and must be checked against the SDM
  before implementing teardown.

Next: build the isolated, unmodified tboot target, select the firmware setup
path and TXT-enabled kernel, then create and boot the baseline image. The first
observed failure remains unknown until that run occurs.
