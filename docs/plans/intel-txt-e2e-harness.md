# Intel TXT full-system acceptance harness

## Objective and status

Run the real tboot boot chain under the modified QEMU, and evaluate the whole
TXT lifecycle rather than infer integration correctness from component tests.
This is a functional emulation acceptance suite, not proof of a security boundary
against the host or a proof of complete architectural correctness.

Baseline (record the full source revisions and hashes for subsequent runs):
- tboot source: `c9ca81f41b4a3eaa8e00c12a3d1d6d3c783782d4`, currently available at
  `/home/michal/qemu-txt-work/tboot`. This path is a development convenience,
  not a portable runner requirement.
- First full-system baseline run: **2026-09-23, failed before measured launch**.
  QEMU `44c9fefab0` (binary SHA-256
  `2ed81dd1eb9bda7052d1f1467f9744c404fab0ce4c81f1f18ccaf837fdfca549`)
  booted real tboot `c9ca81f` from a BIOS-only GRUB ISO under q35/TCG/TXT,
  swtpm, one vCPU and `intel-iommu`. Tboot first reported
  `IA32_FEATURE_CONTROL_MSR: 00000000` and
  `ERR: IA32_FEATURE_CONTROL_MSR_LOCK is not locked`, then
  `TXT.SINIT.BASE: 0x0`, `TXT.SINIT.SIZE: 0x0` and
  `SINIT ACM not provided`. It fell back to an unmeasured host Linux
  (whose `CONFIG_INTEL_TXT` is disabled); the runner timed out after 75 s.
  This is a captured baseline failure, **not** a measured-boot pass.
- Artifacts: `/home/michal/qemu-txt-work/e2e-baseline/` (ISO SHA-256
  `dea5da6015c50f09b2fb1d49e1fe59ff2c3d866ab2af3d4e9e65b006699d9556`,
  tboot.gz SHA-256
  `b4a2490c03cdb8e1998cf79a949c7016f10d53a339e5aa0f78e24cd85963e2ed`,
  run logs `run-20260923-011536/`). Tboot was built in an isolated source
  copy with warning-specific GCC compatibility overrides and one build-only
  replacement of obsolete GNU ld relinking with `objcopy --strip-debug`.
  No tboot runtime or platform checks were modified.
- SENTER now transfers a single vCPU to the synthetic test MLE, but real
  tboot entry, complete PCRs and AP sleep/wakeup remain unverified.

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
| SMP | Single-CPU launch first; AP rendezvous/wakeup and all CPUs online require a verified AP sleep strategy and are currently rejected |
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

These findings come from direct source inspection and the baseline run
recorded above. The boot is not a successful TXT launch.

### Build and boot artifacts

- Host tools available: GCC, ld, grub-mkimage, xorriso, cpio and swtpm.
  `grub-mkrescue` is installed but failed because `mformat` is missing;
  `grub-mkstandalone -O i386-pc` exceeded the 0x78000 core size limit.
  The baseline ISO was built with `grub-mkimage -O i386-pc`, prepended
  `cdboot.img` and `xorriso -as mkisofs` instead. BusyBox is absent.
- Build only tboot's freestanding target, not the host policy tools:
  `make -C <isolated-source-copy>/tboot` with
  `TBOOT_CFLAGS='-Wno-error=address-of-packed-member
  -Wno-error=array-parameter -Wno-error=maybe-uninitialized'` and the
  isolated copy's second ld pass replaced by `objcopy --strip-debug`.
  Do not patch runtime checks or use the host source tree as a build output.
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
  locked/enabled feature-control MSR and required GETSEC capabilities. It
  requires VMX unless `use_mwait()` is true. **Selected path: tboot's default
  VMX/GETSEC[WAKEUP], scoped to one vCPU.** A TXT-machine-specific VMX
  capability opt-in may be needed, despite TCG not executing VMXON: at one
  vCPU tboot checks CPUID/MSR bits but never runs the AP's VMX code. Do not
  add VMX to all TCG guests. The MWAIT path is not the chosen escape hatch:
  tboot's README warns that AP parking needs OS cooperation, and TCG does
  not model the monitored-address wake semantics. Current SENTER rejects
  SMP before PCR measurement; real AP sleep/wakeup remains future work.
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

Next: implement a firmware-owned q35 TXT initialization path (or an explicit,
non-firmware QEMU bring-up mode for diagnostic runs): lock and enable
IA32_FEATURE_CONTROL, reserve/program SINIT and heap regions, fill BIOS Data,
program DPR, and provide suitable DMAR/VT-d configuration. The generic
coreboot TXT option cannot simply be enabled for emulation/qemu-q35: it
requires platform DRAM-clear/reset capabilities and invokes a BIOS ACM that
QEMU does not emulate. Run the baseline ISO after each gate and record the
next observed tboot failure. Only then add TXT-scoped VMX capability bits if
tboot reaches that check. A TXT-enabled Linux kernel and purpose-built
initramfs remain necessary for full acceptance.
