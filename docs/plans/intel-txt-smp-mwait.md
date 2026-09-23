# TXT SMP bring-up with tboot MWAIT AP parking

Status: two-vCPU functional bring-up validated (2026-09-23). This is semantic emulation, not hardware-equivalent attestation; see open gaps below.

## Two independent wakeups

1. SENTER puts the non-initiating logical processors (RLPs) to TXT sleep. Post-launch tboot writes a 16-byte `mle_join_t` (GDT limit, GDT base, CS selector, physical entry point) address to `TXT.MLE_JOIN`, then invokes GETSEC[WAKEUP]. The emulated SINIT offers GETSEC wake, **not** MONITOR wake; retain this choice. RLPs enter `_txt_wakeup` in 32-bit protected mode; only CS is guaranteed usable. The entry stub reloads GDT and other segments.
2. Once joined, tboot's `ap_wake_mwait=true` makes each AP wait for a subsequent OS wake request with MONITOR/MWAIT instead of entering tboot's VMX mini-guest. This choice is independent of GETSEC versus MONITOR **RLP** wake. Default tboot uses VMX, for which TCG lacks VMXON/VMLAUNCH.

On SMP, current TCG `helper_mwait()` yields via `helper_pause()`, so tboot's surrounding loop can recheck its RAM trigger by cooperative polling. `helper_monitor()` ignores the address: this is **not** faithful address-sensitive MONITOR/MWAIT and must be documented/tested as a limitation, but it is not a progress blocker for this tboot loop. Single-vCPU MWAIT takes the HLT path; the AP loop is only relevant to SMP. The SMP CPU model must expose `monitor`: without `+monitor`, AP 1 #UDs on its MONITOR instruction.

## Firmware and reproducer

The out-of-tree coreboot checkout at `/home/michal/qemu-txt-work/coreboot-q35-txt` previously refused any CPU count other than one and set `bios_data.num_logical_procs=1`. It now uses `fw_cfg_max_cpus()` for the BIOS data count; the `coreboot/coreboot-sdk:testing` build passed. Beware that fw_cfg reports the maximum CPU count, so test configurations must have `maxcpus == cpus` unless a present-CPU enumeration is implemented.

The harness `/home/michal/qemu-txt-work/e2e-baseline/run-baseline.py` now accepts `TXT_SMP` (default 1). A separate `tboot-mwait.iso` was generated from `tboot-sinit.iso` with `ap_wake_mwait=true` using `xorriso -boot_image any replay` (local `grub-mkrescue` lacks `mformat`). With `TXT_SMP=2`, firmware booted, tboot confirmed `num_logical_procs: 2`, passed SMX checks and reached GETSEC[SENTER]; QEMU rejected it by design. Run `run-20260923-114605/serial.log` is the pre-implementation failing baseline, not a passing test.

## Implementation order and safety gates

1. Add a synthetic 2-vCPU QTest/TCG test for stopped AP, rejected launch with a running AP, failed SENTER without stranded APs, and invalid `MLE_JOIN` without half-waking processors. Confirm how the APIC's `wait_for_sipi`, `CPUState.halted`, and TCG interrupt dispatch interact. Do not infer an AP is asleep merely because it was halted once.
2. SENTER must establish an atomic AP rendezvous and prevent each parked RLP from executing or accepting INIT/SIPI/SMI until WAKEUP. Perform all pre-measure checks first. On *every* failure path (including TPM and heap writes after measurement), release or reset any newly parked APs; never leave TXT asleep when launch failed. Multithreaded TCG requires synchronization with each AP's own thread, not unsynchronized cross-thread register reads/writes. Model reset/migration for new state.
3. WAKEUP validates `TXT.MLE_JOIN` and both GDT descriptors/selector types and ranges before changing *any* AP. Transfer each sleeping AP to its own `_txt_wakeup` entry state on the AP thread. Track SEXIT/reset semantics and pending interrupts. Preserve the existing single-vCPU behavior.
4. Rebuild QEMU, run targeted negative/positive SMP tests, then run the tboot MWAIT ISO with `-smp 2` and validate `cpu 1 waking up from TXT sleep`, both APs in wait-for-SIPI, Linux handoff and PCR replay. Test `-smp 1` regression. An `rc=0` without the AP evidence is insufficient.

The old draft that merely set a CPU bool under a presumed BQL, before SENTER validation, was discarded: it neither compiled nor protected failure paths or cross-thread state.

## Validation (2026-09-23)

- Synthetic TCG guest tests `i386-softmmu-test-smx-getsec`, `i386-softmmu-test-smx-getsec-smp`, and `i386-softmmu-test-smx-busy-ap` pass. The busy-AP test sends INIT/SIPI to an AP running a real-mode RAM-writing spin loop, requires SENTER to return APS_UNSUPPORTED with SENTER_DONE clear, and verifies the AP keeps running after rejection. The two-vCPU variant checks that WAKEUP without MLE_JOIN or with an undersized GDT raises #GP without releasing the AP, then publishes a valid join block and requires AP 1 to execute its own landing code. Earlier failed SENTER attempts followed by final success exercise rollback. TXT QTests pass for both i386 and x86_64.
- End-to-end: `tboot-txtlinux-mwait.iso`, CPU `Nehalem,smx,sse,+monitor`, `-smp 2`, run `run-20260923-120537` (exit 0). Trace confirms AP 1 parked and joined at `0x804200`; tboot prints `cpu 1 waking up from TXT sleep` and `all APs in wait-for-sipi`; Linux brings up **2 CPUs**, sees the tboot shared page, and tboot tears down the measured environment. `verify-pcrs.py` independently matches **4/4** PCR17/PCR18 SHA-1/SHA-256 values. The `-d int` log has no unexpected #UD/#GP/double fault.
- Single-vCPU regression `run-20260923-121112`: exit 0, shared page and teardown present, PCR replay **4/4** matched.
- Final repeat `run-20260923-121946` after the SEXIT sleep guard: exit 0, AP join/2-CPU Linux/shared-page/teardown all present, 4/4 PCR replay, no unexpected #UD/#GP/double fault in `-d int`.
- The earlier `tboot-mwait.iso` was made from the *generic* SINIT ISO; it brought up two CPUs but its generic initramfs panicked on AVX. It is not the TXT-Linux acceptance artifact.

Reproduce with the prepared local artifacts (test harness and coreboot checkout live outside this repository):

```sh
TXT_ISO=/home/michal/qemu-txt-work/e2e-baseline/tboot-txtlinux-mwait.iso \
TXT_SMP=2 TXT_CPU='Nehalem,smx,sse,+monitor' TXT_TRACE_SMP=1 TXT_DEBUG=int \
python3 /home/michal/qemu-txt-work/e2e-baseline/run-baseline.py \
    /home/michal/qemu-txt-work/coreboot-q35-txt/build/coreboot.rom
# Pass the run-YYYYMMDD-HHMMSS directory reported above to verify-pcrs.py.
meson test -C build --print-errorlogs i386-softmmu-test-smx-getsec-smp \
    i386-softmmu-test-smx-busy-ap i386-softmmu-test-smx-getsec \
    qtest-i386/txt-test qtest-x86_64/txt-test
```

Open gaps: full address-sensitive MONITOR/MWAIT semantics; VT-d PMR and SMI inhibition (tracked separately). The busy-AP test verifies rejection and that the AP keeps executing; it does not directly read back PCRs, but the code rejects before invoking the TPM measurement sequence.
