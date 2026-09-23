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
  capability opt-in is available as ``txt-vmx-compat=on``; at one vCPU
  tboot checks CPUID/MSR bits but never runs the AP's VMX code. Do not
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

### q35 coreboot firmware spike (2026-09-23)

The separate coreboot worktree `/home/michal/qemu-txt-work/coreboot-q35-txt`
(branch `qemu-txt-firmware`, starting at commit `2c1f14972b`) adds an **opt-in
firmware path**: `CONFIG_QEMU_Q35_TXT_FIRMWARE_INIT` locks
`IA32_FEATURE_CONTROL` with all SENTER localities and the VMX-in-SMX bit,
only if the CPU advertises SMX. Its next increment reserves 4 MiB of guest
RAM as DPR, initializes a version-3 BIOS Data region in a 1 MiB TXT heap,
and programs TXT.SINIT and TXT.HEAP. It does not execute a BIOS ACM or ship a
SINIT module; the guest still needs to supply one. The original coreboot
checkout has unrelated local changes and was not modified.

The unmodified q35 coreboot/SeaBIOS payload and the opt-in variant both built
successfully with `coreboot/coreboot-sdk:testing` (image digest
`sha256:9404e005efe8c29409835327cb3a03de62fee5181d80146a6adadc31ab0aea21`).
In this isolated git worktree, pass `XGCCPATH=/opt/xgcc/bin`, initialize
`3rdparty/vboot`, and mount the parent checkout's `.git` read-only at its host
path in the container so worktree metadata resolves. The existing baseline
runner accepts a `coreboot.rom` argument and hashes it in its manifest.

The opt-in image printed `QEMU TXT: IA32_FEATURE_CONTROL = 0x0000ff03 (locked)`.
With the normal `qemu32,smx,sse` CPU it stopped after SeaBIOS's `Press ESC for
boot menu.` (even with unmodified coreboot and `txt=off`). At timeout the BSP
was halted at `f000:b983`, IF=1, with PIC IRQ0 pending. Disabling the guest
APIC capability with `TXT_CPU='qemu32,-apic,smx,sse'` in the local runner
allowed GRUB and **real tboot** to run (`run-20260923-013829/`); this is an
interrupt-routing diagnostic workaround, not a validated final platform.

Tboot read back `IA32_FEATURE_CONTROL_MSR: 0000ff03`, reported SMX enabled and
TXT chipset capabilities present, and then reported **`ERR: CPU does not
support VMX`**. It also reported zero SINIT base/size and no SINIT ACM before
falling back to an unmeasured Linux kernel. Thus the firmware MSR gate is
observably passed, but the boot is **not** a measured-launch pass.

A further run with `-machine q35,txt=on,txt-vmx-compat=on` and the same
`-apic` diagnostic CPU (`run-20260923-083753/`) reports `CPU is VMX-capable`.
The property is off by default and rejects non-TXT and multi-vCPU machines;
it does not implement VMX instructions or imply measured-boot success.

Coreboot's 32-bit compiler emits two 32-bit MMIO transactions for each
64-bit TXT register access. QEMU initially rejected both, so the first
firmware run halted at DPR readback. The TXT MMIO device now supports aligned
low/high 32-bit accesses as well as 64-bit accesses, with W1C and DPR lock
semantics retained (qtest covers both widths). With this change, the
`run-20260923-084726/` serial log shows DPR `[3e000000,3e400000)`, SINIT
`3e200000/40000`, heap `3e300000/100000`, and tboot's E820 marks all 4 MiB
reserved. Tboot passes the VMX check, reads the nonzero SINIT base/size, and
stops at **`SINIT ACM not provided`**. It falls back to unmeasured Linux.
The following experiment supplies that fixture and exercises the heap.

### Single-vCPU tboot post-launch diagnostic (2026-09-23)

An **unsigned QEMU-only** synthetic SINIT module, generated by
`/home/michal/qemu-txt-work/e2e-baseline/make-sinit-fixture.py`, was
packaged as the last GRUB module in `tboot-sinit.iso`. This is **not** a
real SINIT ACM, hardware trust anchor or production attestation source.
QEMU validates its platform fields but does not execute its code or verify
its RSA signature. With the opt-in firmware, TXT-scoped VMX compatibility,
TCG, one vCPU, swtpm and the **diagnostic `-apic` workaround**, unmodified
real tboot passed its SINIT, heap and TXT platform checks. The first attempts
failed at the MLE entry because QEMU had incorrectly left CR0.PG enabled;
tboot's first post-SENTER instructions access absolute physical TXT MMIO.
The BSP now enters at the resolved physical MLE address with paging off.
Tboot then invoked post-launch GETSEC[SMCTRL] and GETSEC[WAKEUP], so QEMU
accepts SMCTRL(EBX=0) and a single-vCPU WAKEUP no-op after SENTER. QEMU
**does not** inhibit SMIs or park/wake APs.

`run-20260923-091958/` records the first observed full **tboot
post-launch-to-kernel handoff**: serial markers include `SINIT ACM
successfully returned...`, `Post_launch started ...`, `GETSEC[WAKEUP]
completed`, PCR17/18 event-log entries, `TPM: tpm2 context save successful`
and `transfering control to kernel @0xc00000...`. QEMU's `-d int` output
shows no post-SENTER exception. The run **timed out after 22 seconds**, so
there is no validated Linux boot or TXT-aware kernel callback. The ISO
SHA256 is `a5a802d7b1f7aad2d7e72b25f1c5617cf5c3e3b46ff8d175aec120ae6086f98c`;
the QEMU and BIOS SHA256 values and full argv are preserved in the run
manifest. The preexisting runner manifest labels it a baseline failure;
that label is stale for the tboot phase, but must **not** be interpreted as
measured-boot acceptance. PCR17 composition, VT-d protection, SMI
inhibition, SEXIT and the Linux TXT contract remain incomplete.

### 64-bit (x86_64) harness (2026-09-23)

The harness originally ran `qemu-system-i386` with `-cpu qemu32`, which
forced a 32-bit guest kernel. That was an artifact of the emulator choice,
not a TXT constraint: tboot must be a 32-bit MLE (SENTER enters in 32-bit
protected mode), but it hands off to an ordinary Linux bzImage that may be
x86_64, exactly as on real hardware. The harness now defaults to
`qemu-system-x86_64`, and QEMU is configured with
`--target-list=i386-softmmu,x86_64-softmmu`. The TXT device is built for
both (it is gated on `CONFIG_Q35`), and `tests/qtest/txt-test` now runs on
both targets (14 subtests each).

Two real bugs were found by moving to 64 bits:

1. **`EFER.LME` was never cleared on MLE entry.** Clearing `CR0.PG` drops
   `LMA`, but with `LME` still set the MLE's first `CR0.PG` write would
   have entered *long mode* instead of its own 32-bit paging. SENTER now
   clears `LME`/`LMA` and the matching hflags. The entry state was also
   corrected to `CR4 = SMXE` only and `CR0.AM/WP` clear, per the MLE Dev
   Guide, instead of the previous "set CR4.PAE" behaviour. The guest test
   asserts the new state, and its MLE landing code now re-enables
   `CR4.OSFXSR` itself before using SSE-staged MMIO -- which is what a real
   MLE has to do.
2. **`qemu64` reports `AuthenticAMD`.** tboot's `supports_txt()` requires
   `GenuineIntel`, so it bailed before enabling `CR4.SMXE` and failed with
   `SMXE not enabled, can't read parameters`. The harness therefore uses an
   Intel model (`Nehalem,smx,sse`). This was a harness bug, not a QEMU one.

An unrelated pre-existing build break also surfaced: this host's GCC is
configured with `--enable-default-ssp`, so the freestanding
`tests/tcg/x86_64/system` images failed to link against `__stack_chk_fail`.
Added `-fno-stack-protector` to those cflags, matching what the i386 SMX
test already passed.

With `-cpu Nehalem,-apic,smx,sse` on `qemu-system-x86_64`, real tboot again
reaches `Post_launch started ...`, `GETSEC[WAKEUP] completed` and
`transfering control to kernel` (`run-20260923-094048/`). The x86_64 host
kernel that the ISO currently carries then panics with `Attempted to kill
init!`, because that ISO reuses the host's `vmlinuz-linux` and host
initramfs, which cannot find a root filesystem here. That panic is a
harness-payload gap, not a TXT failure -- but it does mean **there is still
no validated Linux-side measured boot**.

### PCR verification: established (2026-09-23)

Measured launch is now observed **from inside the booted OS**.

A purpose-built payload replaced the host kernel/initramfs the ISO had been
carrying: Linux **6.12.111** x86_64 with `CONFIG_INTEL_TXT=y`,
`CONFIG_TCG_TPM=y`, `CONFIG_TCG_TIS=y`, plus a ~13 KB `-nostdlib` static
`/init` that mounts `/proc`, `/sys`, `/dev`, dumps the DRTM PCRs and powers
off. (`/init` must avoid AVX: this host's GCC targets `x86-64-v3`, which
`SIGILL`s on the `Nehalem` model the harness uses.) Artifacts and a
`README.md` with every URL/SHA256 live in
`/home/michal/qemu-txt-work/linux-txt/`.

The kernel confirms the launch independently:
`tboot: found shared page at phys addr 0x843000`. In-guest sysfs reports:

- PCR 17 sha1 `24A461E9F450FEC827BDECA80EADF8C073DFABED`,
  sha256 `6FA805A6...F7C14344`
- PCR 18 sha1 `E537EEC63168D8CB48AD7AC95B4E39BAD4991B6A`,
  sha256 `190DF146...BB020170`
- PCR 19-22 all zero

That shape is itself evidence of a DRTM: 17-22 read all-ones before any
launch, `_TPM_Hash_Start` resets them to zero, and only 17 and 18 are then
extended -- which is exactly what this implementation extends.

Two checks establish the values are real rather than constant:

- **Deterministic**: two independent runs of identical inputs produced
  byte-identical PCR 17/18 in both banks
  (`run-20260923-103351/`, `run-20260923-103451/`).
- **Sensitive, and bound to the right input**: flipping a single byte at
  offset 8000 inside the SINIT ACM changed **PCR 17** (sha1
  `0DA6F132...`, sha256 `D32634A6...`) while leaving **PCR 18** bit-identical
  (`run-20260923-103550/`). PCR 17 covers the SINIT ACM and PCR 18 covers
  the MLE, so only PCR 17 should move when the ACM changes. It did.

A full digest replay against tboot's TCG event log has **not** been done;
the above is behavioural evidence, not an independent recomputation.

The post-hoc swtpm route (`read-pcrs.py`) remains **non-working** -- swtpm
did not emit `tpm2-00.volatilestate` even after `swtpm_ioctl -v`/`-s` -- and
must not be cited. The in-guest read supersedes it.

### VT-d / DMAR (2026-09-23)

The first run of the TXT-enabled kernel panicked with `tboot: Failed to
initialize DMAR table`. Linux under tboot deliberately ignores the firmware
DMAR (the ACPI tables are not DMA protected) and instead reads the measured
copy SINIT stashes in the TXT heap, at
`sinit_mle_data + vtd_dmars_off - sizeof(u64)`
(`arch/x86/kernel/tboot.c`, `tboot_get_dmar_table()`). QEMU was writing
`num_vtd_dmars = 0`, so the kernel got NULL and died.

SENTER now locates the guest DMAR (RSDP scan of 0xE0000-0xFFFFF, then
RSDT/XSDT walk) and appends a copy after the MDRs. tboot now reports
`num_vtd_dmars: 1`, `vtd_dmars_off: 0xb0`, and the kernel brings VT-d up:
`DMAR: Forcing Intel-IOMMU to enabled`, `DMAR: dmar0: reg_base_addr
fed90000`, `DMAR: Intel(R) Virtualization Technology for Directed I/O`.
Guests without intel-iommu have no DMAR and the fields stay zero.

### Virtual-wire ExtINT: why `-apic` was needed, and the fix (2026-09-23)

**Resolved.** The `-cpu ...,-apic` workaround is no longer required.

With a local APIC present, coreboot+SeaBIOS halted after `Press ESC for boot
menu.` with the BSP in HLT, IF=1. Tracing (`--trace ioapic_set_irq
--trace apic_local_deliver --trace pic_interrupt`) showed the PIT toggling
GSI 0 forever while **neither** `apic_local_deliver` nor `pic_interrupt`
ever fired -- nothing was being delivered or acknowledged. Monitor state at
the hang:

- `LVT0 = 0x00010700` -- ExtINT but **masked**, LAPIC enabled (`SPIV=0x10f`)
- IOAPIC pin 0 = ExtINT, unmasked
- IOAPIC pin 2 = **masked**
- `pic0: irr=11 isr=00` -- IRQ0 pending, never acknowledged

Coreboot's `lapic_enable_extint()` prefers routing virtual-wire ExtINT
through IOAPIC GSI0 and deliberately leaves LINT0 masked when that
succeeds. That is valid on real chipsets, where the 8259 INTR output is
wired to IOAPIC INTIN0.

**QEMU does not model that wire.** It connects the i8259 INTR output
directly to the local APIC LINT0 input (`apic_deliver_pic_intr()`), and its
IOAPIC never sees it. `ioapic_set_irq()` additionally remaps ISA IRQ0 onto
pin **2**, so pin 0 is never asserted by anything. Coreboot's GSI0 ExtINT
route therefore had no path to the CPU, and SeaBIOS waited forever for a
timer tick.

This is a QEMU fidelity gap rather than a coreboot bug. Modelling the
8259->INTIN0 wire would touch the most heavily used interrupt path in every
PC machine type, so it is left as separate future work. The harness instead
gains coreboot `IOAPIC_NO_EXTINT_GSI0_WIRE` (selected by
`emulation/qemu-q35`), which makes `route_i8259_irq0()` report failure so
`lapic_enable_extint()` unmasks LINT0 -- the only virtual-wire path QEMU
offers. With that, real tboot completes measured launch and reaches
`transfering control to kernel` on a stock `-cpu Nehalem,smx,sse`
(`run-20260923-095210/`).

Note `qemu64` cannot be used: it reports `AuthenticAMD`, and tboot's
`supports_txt()` requires `GenuineIntel`.

Next: finish the TXT-enabled x86_64 kernel and initramfs and read the PCRs
from inside the guest; validate DMAR/VT-d; implement required teardown
semantics; and consider modelling the 8259->IOAPIC INTIN0 wire in QEMU.
Generic coreboot TXT cannot simply be enabled for q35: it expects platform
DRAM-clear/reset features and a BIOS ACM that QEMU does not execute.
