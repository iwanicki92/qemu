# TXT VT-d PMR implementation plan

Status: in progress. SENTER now validates the four PMR fields and checks MLE/page-table coverage **before PCR reset**; two negative PMR tests and the 2-vCPU boot with 4/4 independent PCR replay pass (`run-20260923-123853`). QEMU's intel-iommu still advertises neither CAP.PLMR (bit 5) nor CAP.PHMR (bit 6), treats PMEN (offset 0x64) as read-only, and has no PMR translation policy. **Input validation is not DMA protection.**

## Contract

`tboot/txt/verify.c:set_vtd_pmrs()` rounds down each base and size to 2 MiB. The current one-GiB test machine supplies low `[0,0x3e000000)` and empty high pair. The four little-endian u64 fields start at `os_sinit_data+0x20` (low base/size then high base/size). SINIT must validate alignment, overflow, low/high placement and that every physical MLE page (and its page tables) is inside a PMR window, before resetting any DRTM PCRs. No silent acceptance of an absent VT-d device or an unprotected MLE.

**PMR denies device DMA into the protected windows**, not outside them. The low PMR ends at 0x3e000000; TXT heap at 0x3e300000 is in the **DPR**, not the PMR. The current spec incorrectly conflates this; PMR enforcement by itself cannot protect the heap/DMAR copy. DPR DMA enforcement must be scoped separately.

Linux `drivers/iommu/intel/iommu.c:iommu_disable_protect_mem_regions()` clears PMEN.EPM (bit 31), then waits for PMEN.PRS (bit 0) to clear. That guest-visible handshake must release PMR protection without losing register state. Windows have inclusive VT-d limit registers; convert half-open base/size to `limit=base+size-1`. CAP bits and registers must be exposed only for the TXT-capable device configuration; non-TXT VT-d behavior must not silently change.

## QEMU model integration

- `hw/i386/intel_txt.c`: **done:** pre-measure heap validation and actual MLE physical page/page-table coverage; distinct ERRORCODE. **Remaining:** after *all* launch steps pass, request PMR programming on the realized IntelIOMMUState before reporting SENTER_DONE. Fail closed when TXT needs protection and there is no compatible intel-iommu device. Roll back on failure, disable PMR on SEXIT and reset.
- `hw/i386/intel_iommu.c`: CAP.PLMR/PHMR, PMR base/limit and PMEN registers, PMR-enabled IOMMU address-space selection **even while DMA remapping is disabled**, and a protected-range check on the *translated physical address* in `vtd_iommu_translate()`. Today `vtd_switch_address_space()` aliases the entire system RAM through `nodmar` whenever translation is disabled: a check inside `vtd_iommu_translate()` alone is bypassed and is NOT enforcement. On PMR enable/disable, switch per-device regions, invalidate IOTLB and notifier mappings, and account for cached translations. Handle migration (CSR is already serialized, but address-space recomputation must use PMEN), reset and guest PMEN writes. Prefer rejecting VFIO/vhost bypasses to claiming software enforcement for DMA outside QEMU's translated path.
- Tests: negative os_sinit PMR mutation before measurement (including PMR not covering the MLE); QTest VT-d CAP/CSR/PMEN status and DMA into/outside the window while remapping disabled and after enabling it; clean release via guest PMEN write; migration/reset. Re-run single-vCPU and two-vCPU tboot E2E with `-device intel-iommu` and 4/4 PCR replay. A passing boot alone does not prove DMA denial.
