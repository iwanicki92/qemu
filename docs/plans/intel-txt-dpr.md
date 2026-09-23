# TXT DPR enforcement and private-space scope

Status: in progress. Upstream RFC is blocked until this work is implemented and verified.

## Contract

- TXT heap (including the copied DMAR table) and SINIT reservation sit in the
  chipset DMA Protected Range, **not** in the VT-d PMRs. PMR coverage cannot
  substitute for DPR coverage.
- Retain existing pre-launch TXT private-register reads for firmware probes.
  After a measured launch closes private space, private reads return all ones
  and writes are ignored; public registers remain usable. SENTER reopens it.
  This access gate and its single-/multi-CPU TCG tests landed separately as
  `e00c6180ab`.
- After a locked, nonempty DPR is configured, DMA into its half-open window
  must be denied independently of PMR enablement, including when VT-d DMA
  remapping is disabled. Validate the 1 MiB size/top encoding without wrapping.
  CPU reads and writes remain available: firmware must populate the heap and
  SINIT reservation after locking DPR.
- Fail closed rather than claim DMA safety if a DMA source bypasses the
  enforcement path. Do not change non-TXT machines. A guest-visible DPR lock
  alone is **not** evidence that DMA is excluded.
- MSEG/STM and the unverified MCH PCI DPR mirror are unsupported; disclose
  them explicitly instead of inventing register offsets or emulating an STM.
  No claim of remote-attestation equivalence.

## Implementation investigation / gates

1. Choose the enforcement point for *all* guest device DMA, not just PCI DMA
   routed through the Intel IOMMU. Existing VT-d PMR protection checks
   translated host-physical addresses in `vtd_iommu_translate()`, and forces
   the IOMMU path even with DMAR disabled via `vtd_switch_address_space()`.
   Extending that path to DPR would cover the modeled PCI test device but
   **does not cover ISA DMA**: Q35's `hw/isa/lpc_ich9.c` instantiates the
   i8257, whose `hw/dma/i8257.c` read/write callbacks use
   `physical_memory_read/write()` directly. Protect that path too, and
   inventory other direct `address_space_memory` users before claiming DPR
   complete; otherwise narrow the documented contract with explicit approval.
2. Bind the TXT DPR source to the IOMMU without relying on `current_cpu`:
   DMA callbacks can run without a vCPU. On lock, refresh device address
   spaces and invalidate translations; ensure PMR and DPR coexist. Account
   for reset, migration, guest PMEN writes, missing VT-d, and notifiers or
   host devices that cache translations outside this path. Do not alter
   non-TXT VT-d capability or passthrough behavior.
3. Add qtest and TCG tests: inside/outside DPR before SENTER, disabled
   remapping, exact lower/upper edges, invalid/empty ranges, PMR overlap,
   reset/migration and device bypass. Use bounded DMA waits so a denied
   request cannot hang tests. Test that the live heap/DMAR copy cannot be
   overwritten via DMA, but remains CPU-writable for the launch sequence.
4. Run the 13 focused TCG/qtests, two-vCPU and one-vCPU tboot/Linux E2E,
   independently replay PCR17/18 in SHA-1 and SHA-256, check AP wake and
   Linux 2-CPU handoff, SEXIT teardown, `-d int` exceptions, and checkpatch.
   Only then update `docs/specs/intel-txt.rst` to claim DPR enforcement.

The existing test harness runs with idle AHCI and no NIC or guest root disk,
so a successful E2E by itself **does not exercise device DMA into DPR**.
