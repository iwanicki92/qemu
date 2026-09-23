# TXT DPR enforcement and private-space scope

Status: implemented and locally verified. Upstream contributions are deferred.

## Contract

- TXT heap (including the copied DMAR table) and SINIT reservation sit in the
  chipset DMA Protected Range, **not** in the VT-d PMRs. PMR coverage cannot
  substitute for DPR coverage.
- Retain existing pre-launch TXT private-register reads for firmware probes.
  After a measured launch closes private space, private reads return all ones
  and writes are ignored; public registers remain usable. SENTER reopens it.
  This access gate and its single-/multi-CPU TCG tests landed separately as
  `e00c6180ab`.
- A locked, nonempty, nonwrapping DPR must cover both SINIT and the entire
  TXT heap before SENTER. This input check landed as `71e320daaa`; it is
  **not** DMA exclusion. DMA into the half-open DPR window must be denied
  independently of PMR enablement, including when VT-d DMA remapping is
  disabled. Validate the 1 MiB size/top encoding without wrapping.
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
   complete. The PCI PCnet adapter's `physical_memory_*` wrappers actually
   call `pci_dma_*` and traverse the PCI address space. PCI EHCI normally uses
   `pci_get_address_space()` while bus mastering is enabled but retains a
   direct-memory fallback when disabled; verify it cannot DMA in that mode.
   Otherwise narrow the documented contract with explicit approval.
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

## Verification and boundaries

- Locked DPR activates a separate VT-d physical-address check independent of
  PMR/PMEN and DMAR enablement, and keeps PCI DMA routed through VT-d while
  locked. Q35 i8257 callbacks deny overlapping direct ISA DMA; PCI EHCI uses
  the PCI address space even with bus mastering off on TXT machines.
- TXT refuses a default Q35 PCI root bus or a PCI expander root bus configured
  to bypass the IOMMU. Non-TXT device routing is unchanged. A nonempty DPR
  cannot lock without intel-iommu, nor with existing host notifiers or host
  IOMMU devices; new host attachments are rejected while DPR/PMR is active.
- The qtest uses actual PCI DMA and floppy/i8257 DMA at DPR boundaries,
  including unprotected adjacent addresses, PMR coexistence, CPU writes and
  reset. Single-/SMP TCG tests verify that locked DPR excludes DMA to the
  populated heap, including the copied DMAR table, both before and after
  SENTER. All DMA-result polls are bounded.
- A live QEMU/swtpm file-migration check verified locked DPR at source and
  destination and PCI DMA failure at the same protected address on both,
  after incoming migration completed. DPR is restored from TXT VMState; it is
  not a separate migrated VT-d property.
- The 13 focused TCG/qtests and single-/two-vCPU tboot/Linux boots passed;
  both boots independently replayed all four SHA-1/SHA-256 PCR17/18 values.
  SMP boot woke the AP and handed two CPUs to Linux; both boots tore down via
  SEXIT with no logged exceptions. Checkpatch found only the missing commit
  Signed-off-by header before committing.

The E2E harness itself runs with idle AHCI and no NIC or guest root disk:
**E2E alone does not exercise DMA into the DPR**. Dedicated qtest/TCG DMA
transfers establish that narrower functional behavior. The model does not
provide malicious-device containment, MSEG/STM, a verified MCH DPR PCI mirror,
or hardware-backed remote attestation.
