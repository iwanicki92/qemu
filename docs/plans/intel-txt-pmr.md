# TXT VT-d PMR implementation plan

Status: **done.** SENTER validates the four PMR fields and checks MLE/page-table
coverage **before PCR reset**, then programs the VT-d Protected Memory Regions
on the intel-iommu device before any DRTM measurement; SEXIT releases them.
Qtest, TCG (single + SMP) and the 1/2-vCPU tboot E2E with 4/4 independent PCR
replay all pass (`run-20260923-151949`, `run-20260923-152157`).

## Contract

`tboot/txt/verify.c:set_vtd_pmrs()` rounds down each base and size to 2 MiB.
The current one-GiB test machine supplies low `[0,0x3e000000)` and an empty
high pair. The four little-endian u64 fields start at `os_sinit_data+0x20`
(low base/size then high base/size). SINIT must validate alignment, overflow,
low/high placement and that every physical MLE page (and its page tables) is
inside a PMR window, before resetting any DRTM PCRs. No silent acceptance of
an absent VT-d device or an unprotected MLE.

**PMR denies device DMA into the protected windows**, not outside them. The
low PMR ends at 0x3e000000; TXT heap at 0x3e300000 is in the **DPR**, not the
PMR. PMR enforcement by itself cannot protect the heap/DMAR copy. DPR DMA
enforcement is scoped separately.

Linux `drivers/iommu/intel/iommu.c:iommu_disable_protect_mem_regions()` clears
PMEN.EPM (bit 31), then waits for PMEN.PRS (bit 0) to clear. That guest-visible
handshake releases PMR protection without losing register state. Windows use
inclusive VT-d limit registers; half-open base/size converts to
`limit=base+size-1`.

## Implemented model

### `hw/i386/intel_txt.c`

- `intel_txt_validate_pmrs()` runs **before** PCR reset: alignment, 32/64-bit
  placement, overflow, and per-page MLE + page-table coverage. Failure keeps
  the DRTM PCRs untouched and records `TXT_ERRORCODE_PMR_INVALID` (0x80080001).
- SENTER then programs the IOMMU immediately: `intel_iommu_clear_txt_pmr()`
  (pre-clear so a retry re-programs from a released state) then
  `intel_iommu_set_txt_pmr()`. Failure records
  `TXT_ERRORCODE_PMR_PROGRAM_FAILED` (0x80080002, progress code 0x09).
- Fail closed: `txt=on` without an intel-iommu device rejects the launch;
  devices with cached translations outside the IOMMU (host vIOMMU, notifiers)
  refuse PMR enable rather than claim software enforcement.
- `GETSEC[SEXIT]` releases the PMR (`intel_iommu_clear_txt_pmr()`).

### `hw/i386/intel_iommu.c`

- CAP.PLMR (bit 5) / CAP.PHMR (bit 6) are advertised only when the machine
  is TXT-capable (`txt=on`); on non-TXT machines the bits stay clear, PMEN
  stays read-only and behavior is unchanged.
- PMR registers: `DMAR_PMEN_REG` (0x64, wmask EPM only; PRS set internally on
  enable), low PMR base/limit as 32-bit longs (0x68/0x6c), high PMR as 64-bit
  quads with split 32-bit hi accessors (0x70/0x78). Base/limit are writable
  across the host address width; the device normalizes to 2 MiB granularity
  in `vtd_pmr_blocks()`, so an inclusive-limit write of any sub-granularity
  value yields the same effective window.
- **Enforcement while remapping is disabled:** when PMR is active the
  per-device IOMMU address space is selected even though DMA remapping is
  off (the default `nodmar` passthrough is bypassed), and
  `vtd_iommu_translate()` denies translations whose **translated host-
  physical** address falls in a PMR window. Base > limit disables the range.
- PMEN write handling (`vtd_handle_pmen_write()`): guest clearing EPM
  releases the PMR (Linux's release path); PMEN is re-written internally as
  `EPM|PRS` when enabled, `0` when released; base/limit writes are ignored
  while PRS is set (hardware behavior).
- Conservative enable: `vtd_pmr_update()` refuses to enable while
  `vtd_as_with_notifiers` or `vtd_host_iommu_dev` is non-empty (cached
  mappings outside the translated path).
- Migration/reset: the CSR array is already serialized; `vtd_post_load()`
  re-derives `pmr_enabled` from the migrated PMEN.
- Trace events: `vtd_pmr_update`, `vtd_pmr_dma_blocked`.

### Tests

- `tests/qtest/iommu-intel-pmr-test.c` (i386 + x86_64): CAP bits, initial
  PMEN=0, DMA passthrough before enable, program `[0,2 MiB)` + enable, PRS
  set, base/limit locked while PRS, in-window DMA denied (TX_FAIL),
  out-of-window DMA succeeds, release via guest PMEN write, DMA succeeds
  again. Requires the in-process TPM emulator (`tpm-emu.c`) because
  `txt=on` demands a TPM backend.
- `tests/tcg/i386/system/test-smx-getsec.c` (single + SMP build):
  step 8a baseline (CAP advertises PLMR/PHMR, PMEN=0, DMA passes), step 8b
  SENTER programs the 16 MiB os_sinit window, step 8c verifies
  PMEN=EPM|PRS, PLMBASE/PLMLIMIT readback, DMA into the window denied and
  outside it allowed, and SEXIT releases the PMR (DMA passes again).
- Regressions: `txt-test` (i386/x86_64), `intel-iommu-test`,
  `iommu-intel-test`, `iommu-intel-inv-test`, `test-smx-getsec`
  (single/SMP/busy-ap) — all pass.
- E2E: 1-vCPU `run-20260923-152157` and 2-vCPU `run-20260923-151949` — AP
  wake + join, Linux 2 CPUs, SEXIT, teardown, 4/4 independent PCR replay,
  no unexpected #UD/#GP in `-d int`. The measured environment performs no
  device DMA in this setup (no NIC, no `root=`, AHCI idle), so the live PMR
  window `[0, 0x3e000000)` does not interfere with the boot; the MLE
  (0x801000–0x83A000) and the kernel image sit inside it as intended.

## Remaining

- DMA denial covers devices that go through the IOMMU translate path.
  Bypass paths (VFIO/host-vIOMMU, notifiers) are refused at PMR enable
  (fail-closed), not emulated.
- DPR DMA protection of the heap/DMAR copy: separate scope.
- #5 SMI inhibition, #7 upstream preparation remain.
