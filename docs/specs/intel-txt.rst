===========================================
Intel TXT / SMX (DRTM) emulation for QEMU
===========================================

:Status: proposal / work in progress (M0)
:Target: TCG only, q35 machine (``-machine txt=on``)
:Reference documents: Intel TXT Software Development Guide
    (Doc 315168), Intel TXT MLE Software Development Guide (315168-01),
    Intel SDM Vol. 2 (GETSEC), TCG PC Client TPM Profile (PTP)

This document specifies an emulated Intel TXT (Trusted Execution
Technology) platform for QEMU, sufficient to boot and develop the
TrenchBoot stack (coreboot TXT init, GRUB Secure Launch / tboot,
Linux secure-launch kernel) under TCG.

Design decision: *semantic SENTER* (Option A)
=============================================

QEMU does not execute a real, signed SINIT ACM. Instead,
``GETSEC[SENTER]`` is implemented as a helper that performs the
semantic steps that the SINIT ACM performs on real hardware:
validate the launch inputs, measure the MLE, extend the DRTM PCRs
through the TPM backend at locality 4, populate the SINIT-to-MLE TXT
heap region, and transfer control to the MLE entry point in the
documented measured-launch CPU state.

Rationale: the goal is a *software development platform for DRTM
code* (loaders, kernels, attestation tooling), not a faithful model
of Intel's NDA'd ACM. A real-ACM-execution mode can be added later as
``txt-mode=acm-exec``; the device interface below keeps the ACM
parsing (header, sizes) separate from the launch flow so both modes
share the same machinery.

There is deliberately **no signature verification** of the ACM in
this design; PCR values produced by the emulator describe QEMU's
semantic actions and are not attestation-worthy against real
hardware. This is analogous to how tpm-tis models TPM semantics
without modeling TPM hardware security.

Platform address map
====================

The TXT chipset occupies part of the fixed platform MMIO range::

  0xFED1_0000 - 0xFED1_FFFF  (Intel HD Audio etc. - unrelated)
  0xFED2_0000 - 0xFED2_FFFF  TXT private config space   (64 KiB)
  0xFED3_0000 - 0xFED3_FFFF  TXT public config space    (64 KiB)
  0xFED4_0000 - 0xFED4_4FFF  TPM decode area: TIS localities 0-4
                              (already provided by tpm-tis)
  0xFED4_5000 - 0xFED4_FFFF  (unused / reserved)
  0xFED5_0000 - 0xFED8_FFFF  TXT reserved space

Source: coreboot ``src/security/intel/txt/txt_register.h`` and tboot
``include/txt/config_regs.h`` agree on this layout.

Notes:

- The public and private config spaces have **separate MMIO regions
  with the same register offsets** (tboot reads/writes both with
  offset-based accessors).
- The TPM decode area is exactly the existing QEMU tpm-tis device
  (base ``0xFED40000``, five localities at ``base + n*0x1000``). No
  new mapping is required; the TXT device only needs a reference to
  the TPM backend to perform locality-4 measurements outside the
  guest's own TPM driver.
- Under ``-machine txt=on`` the machine requires a TPM backend
  (tpm-tis + swtpm); instantiation fails otherwise.
- ``-machine q35,txt=on,txt-vmx-compat=on`` is an explicit single-vCPU
  bring-up option: it advertises ``CPUID.1.ECX.VMX`` only on that TXT
  machine, so real tboot can pass its prelaunch VMX capability check.
  TCG **does not execute VMX instructions**. The option rejects
  ``txt=off``, more than one possible vCPU, or a CPU without SMX; it
  is unsafe for general guest use. Default: off.

TXT public config register map
===============================

All registers are 64-bit unless noted. Aligned 64-bit accesses and aligned
32-bit accesses to either half are supported: 32-bit coreboot firmware
emits separate low/high accesses. Writes to the high halves of command
registers do not execute those commands; W1C and DPR-lock behavior also
applies to 32-bit writes. Offsets from ``0xFED30000`` (public) and
``0xFED20000`` (private).

===== ========================= ============= ===========================================
Off   Name                      Access        Semantics (QEMU)
===== ========================= ============= ===========================================
0x000 TXT.STS                   RO            Status. See *STS bits* below.
0x008 TXT.ESTS                  RO/W1C        Error status. bit0 ``TXT_RESET_STS`` (TXT
                                              forced reset occurred); bit6
                                              ``WAKE_ERROR_STS`` (modern).
0x030 TXT.ERRORCODE             RO/RW         ACM error code (details below).
0x038 TXT.CMD_RESET             WO            Write 1: perform a full platform reset
                                              (machine reset, like SINIT
                                              ``ACMINPUT_RESET``).
0x048 TXT.CMD_CLOSE_PRIVATE     WO            Write: close private config space (sets
                                              ``STS.private_open`` = 0).
0x0A0 TXT.SPAD                  RO/RW         Scratchpad / ACM status (modern platforms;
                                              see ACMSTS bits below).
0x100 TXT.VER.FSBIF             RO            Bit31 ``PRODUCTION_FUSED``. Always 1
                                              (production) on QEMU.
0x110 TXT.DIDVID                RO            Chipset VID/DID/revision. Must match what
                                              coreboot/GRUB/tboot expect for a
                                              TXT-capable chipset (value pinned in M1;
                                              expose as device property).
0x200 TXT.VER.QPIIF             RO            QPI-era interface version; on FSB-era
                                              chipsets this offset reads reserved. QEMU
                                              reports a modern (server-style) value;
                                              alternatively 0x200 is TXT.CAPABILITIES on
                                              newer client parts (bit26 DPR support) —
                                              QEMU implements TXT.CAPABILITIES here.
0x218 TXT.CMD_UNLOCK_MEM_CONFIG WO            (server) unlock memory config.
0x270 TXT.SINIT.BASE            RW            Physical address of SINIT ACM (below 4
                                              GiB).
0x278 TXT.SINIT.SIZE            RW            Size in bytes; plain RW in M1. The
                                              base+size vs DPR bounds check is enforced
                                              from M3 (SENTER preconditions).
0x290 TXT.MLE_JOIN              RW            RLP join structure: ``gdt_limit``,
                                              ``gdt_base``, ``seg_sel``, ``entry_point``
                                              (4 x u32).
0x300 TXT.HEAP_BASE             RW            Physical address of TXT heap.
0x308 TXT.HEAP_SIZE             RW            Heap size in bytes.
0x310 TXT.MSEG_BASE             RW            MSEG (SMM monitor) base.
0x318 TXT.MSEG_SIZE             RW            MSEG size.
0x328 TXT.BIOSACM_ERRORCODE     RO            (modern) BIOS ACM error code.
0x330 TXT.DPR                   RW (lock bit) DMA Protected Range; layout in *DPR* below.
                                              Also mirrored in MCH PCI config space.
0x380 TXT.CMD_OPEN_LOCALITY1    WO            Open locality 1 for OS use.
0x388 TXT.CMD_CLOSE_LOCALITY1   WO            Close locality 1.
0x390 TXT.CMD_OPEN_LOCALITY2    WO            Open locality 2.
0x398 TXT.CMD_CLOSE_LOCALITY2   WO            Close locality 2.
0x400 TXT.PUBLIC_KEY            RO            Hash of Intel's ACM public key (4 x 64-bit,
                                              SHA-384-sized). QEMU reports a fixed
                                              non-zero placeholder (marker "QEMUTXT",
                                              ``TXT_PUBLIC_KEY_PLACEHOLDER``) —
                                              semantically "the key the semantic SENTER
                                              trusts".
0x8E0 TXT.CMD_SECRETS           WO            Declare memory contains secrets.
0x8E8 TXT.CMD_NO_SECRETS        WO            Declare memory has no secrets (clears
                                              ``E2STS.SECRET_STS``).
0x8F0 TXT.E2STS                 RO            Extended status. bit1 ``SECRET_STS``.
===== ========================= ============= ===========================================

STS bits (tboot ``txt_sts_t``)::

  bit 0  SENTER.DONE.STS
  bit 1  SEXIT.DONE.STS
  bit 6  MEM-CONFIG-LOCK.STS
  bit 7  PRIVATE-OPEN.STS
  bit 15 LOCALITY1-OPEN.STS
  bit 16 LOCALITY2-OPEN.STS

ACMSTS bits in TXT.SPAD (modern; coreboot ``txt_register.h``)::

  bit 63 IBB_MEASURED        bit 59 BIOS_TRUSTED
  bit 62 VERIFICATION_ERROR  bit 47 MEM_CLEAR_POWER_DOWN
  bit 61 BG_STARTUP_ERROR   bit 60 TXT_DISABLED
  bit 30 TXT_STARTUP_SUCCESS

TXT.ERRORCODE (ACMERROR) layout (coreboot)::

  bit 31 VALID         bit 30 EXTERNAL (0 = processor / SINIT)
  [29:24] reserved
  [23:16] PROGRESS_CODE
  bit 15  MINOR_CODE
  [14:10] MAJOR_CODE
  [ 9: 4] CLASS_CODE
  [ 3: 0] TYPE_CODE (0 = BIOS ACM, 1 = SINIT ACM)

On reset TXT.ERRORCODE reads 0 (bit 31 VALID clear = no error
recorded; coreboot/tboot parse 0 as "no error"). DRTM PCRs 17-22
read all-ones before any launch; a successful SENTER resets them
to zero and extends its measurements.

QEMU-specific TXT.ERRORCODE values (all VALID = 1, EXTERNAL = 0,
TYPE_CODE = 1 (SINIT ACM); the reason is the PROGRESS_CODE):

  +-------------+------------------------+----------------------------------------------------------------+
  | Value       | Name                   | Meaning                                                        |
  +=============+========================+================================================================+
  | 0x80010001  | SINIT_REGION_INVALID   | TXT.SINIT_BASE/SIZE zero, region not below 4 GiB, overflowing, |
  |             |                        | or SENTER ACM size > reserved slot / max ACM size              |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80020001  | SINIT_NOT_IN_DPR       | SINIT region not entirely inside the (nonzero) DPR range       |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80030001  | HEAP_INVALID           | TXT heap registers or size-prefixed SINIT-MLE section invalid  |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80040001  | LAUNCH_INCOMPLETE      | Historical staged-launch code; no longer issued on success     |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80050001  | MEASURE_FAILED         | DRTM measurement or MLE image/entry validation failed          |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80060001  | ACM_INVALID            | The region TXT.SINIT_BASE/SIZE points at does not              |
  |             |                        | structurally describe a SINIT ACM for this chipset - bad ACM   |
  |             |                        | header, malformed or out-of-bounds info table, or a chipset    |
  |             |                        | id list that does not cover TXT.DIDVID.                        |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80070001  | APS_UNSUPPORTED        | An AP was not halted or could not enter TXT sleep              |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80080001  | PMR_INVALID            | VT-d PMR fields invalid, or an MLE page not protected          |
  +-------------+------------------------+----------------------------------------------------------------+

TXT private config space
========================

On real hardware the private space (``0xFED20000``) is writable only
by the SINIT ACM while the private space is open
(``STS.private_open`` = 1). The semantic SENTER does not need it for
its function; the device implements:

- pre-launch reads returning the same register set as public space
  (some loaders poke private registers during bring-up debugging),
- after launch, reads return all ones when private space is closed,
  including after SEXIT; public config remains accessible,
- writes ignored except ``TXT.MLE_JOIN`` when ``STS.SENTER_DONE`` and
  ``STS.PRIVATE_OPEN`` are both set (the MLE publishes its AP entry),
- ``TXT.CMD_CLOSE_PRIVATE`` closes it.

DPR — DMA Protected Range
=========================

Two locations, same register layout (coreboot ``union
dpr_register``)::

  bit  0   LOCK    (write once; locks the register)
  bit  1   PRS     (PCI config variant only: protected range status)
  bit  2   EPM     (PCI config variant only: execution protect)
  [11:4]   SIZE    (number of 1 MiB blocks)
  [31:20]  TOP     (address bits [31:20] of the top of the range)

The protected range is ``[TOP - SIZE*1MiB, TOP)``. coreboot locks DPR
before SENTER; the SINIT ACM verifies DPR covers the SINIT region
(and on server platforms the launch is aborted otherwise).

QEMU behavior:

- SENTER requires a locked, nonempty, nonwrapping DPR covering the full
  SINIT reservation and TXT heap before resetting any DRTM PCR.
- Locking a nonempty DPR without a compatible intel-iommu device, or
  while a host device caches mappings outside VT-d, is refused.
- While locked, the VT-d path denies PCI DMA into the DPR even when
  guest DMA remapping is disabled or PMEN is cleared. Q35's i8257 ISA
  DMA path also denies overlapping transfers; refused ISA reads return
  zeroes and writes are dropped. These checks use physical addresses
  and cover the entire DMA transfer, not just its first byte.
- CPU access remains available: firmware and SINIT must populate the
  protected region. DPR persists across SEXIT, unlike VT-d PMRs, and
  resets with the chipset. This is functional guest-software protection,
  **not** an adversary model or remote-attestation equivalent.

The MCH PCI config mirror remains unsupported: its offset has not
been verified against the Q35 datasheet. The TXT MMIO DPR lives at
0x330.

GETSEC (SMX) CPU interface
==========================

Encoding ``0F 37``; ``CR4.SMXE`` must be set (else #UD); CPL must be 0
(else #GP). GETSEC is implemented only for TCG; a ``-machine txt=on``
under KVM is rejected at startup.

Leaf numbering (SDM / tboot ``smx.h``)::

  0 CAPABILITIES   2 ENTERACCS    3 EXITAC       4 SENTER
  5 SEXIT          6 PARAMETERS   7 SMCTRL       8 WAKEUP

GETSEC[CAPABILITIES] (EAX=0, EBX=index)
  index 0 returns the available-leaf bitmap, consultable with the
  TXT device for chipset presence::

    bit 0  CHIPSET_PRESENT   (1 when intel-txt device present)
    bit 2  ENTERACCS         (0 initially; Option B)
    bit 3  EXITAC            1
    bit 4  SENTER            1
    bit 5  SEXIT             1
    bit 6  PARAMETERS        1
    bit 7  SMCTRL            1
    bit 8  WAKEUP            1
    bit 31 EXTENDED_LEAFS    0

GETSEC[PARAMETERS] (EAX=6, EBX=index)
  Returns the parameter table in EAX/EBX/ECX; terminated by entry type 0.
  (The index register is EBX per the SDM, matching tboot and GRUB; an
  earlier revision of this spec incorrectly said ECX.)
  QEMU reports:

  - ACM version mask 0xFFFFFFFF, version 0
  - max ACM size 32 KiB (EAX masked with ~0x1f is 0x8000 bytes),
    acquirable memory UC
  - SENTER controls 0
  - TXT extensions: processor-based SCRTM (bit 5) supported

GETSEC[SENTER] (EAX=4, EBX=SINIT ACM phys base, ECX=ACM size, EDX=0)
  See *Semantic measured launch* below. QEMU currently records
  ERRORCODE and returns on failure instead of a hardware TXT reset.

GETSEC[SEXIT] (EAX=5)
  Leaves the measured environment and **returns to the next
  instruction**; see *Teardown* below.  #GP outside a measured
  environment.

GETSEC[WAKEUP] (EAX=8)
  After SENTER, validates the four-word ``TXT.MLE_JOIN`` block and
  its 32-bit flat ring-0 CS/data descriptors before releasing any
  sleeping RLP. Each AP resumes at the MLE's physical entry on its
  own vCPU thread. An invalid join block raises #GP without waking
  any AP. With one vCPU there is nothing to wake.

GETSEC[EXITAC] (EAX=3, EBX=near jump target)
  Not needed for the semantic flow (no AC mode is entered); returns
  via the near jump, or #UD until Option B.

GETSEC[SMCTRL] (EAX=7, EBX=0)
  Accepted after SENTER.  Releases the SMI inhibition that SENTER
  engaged: SMIs that arrived while the measured environment was
  being established are held per CPU and redelivered on release,
  and new SMIs flow normally until SEXIT (see *SMI inhibition*
  below).

TXT heap
========

The heap lives in guest RAM at ``TXT.HEAP_BASE``/``HEAP_SIZE``. It
contains four size-prefixed tables, in order (tboot ``heap.h``)::

  +---------------------------------+
  | u64  bios_data_size             |
  | bios_data_t  [bios_data_size-8] |
  +---------------------------------+
  | u64  os_mle_data_size           |
  | os_mle_data_t [...]             |
  +---------------------------------+
  | u64  os_sinit_data_size         |
  | os_sinit_data_t [...]           |
  +---------------------------------+
  | u64  sinit_mle_data_size        |
  | sinit_mle_data_t [...]          |
  +---------------------------------+

- ``bios_data_t`` — written by firmware (coreboot): version,
  bios_sinit_size, LCP policy data base/size, num_logical_procs,
  flags (sinit_flags/mle_flags for TPM2), extended data elements
  (BIOS spec version, ACM addresses, event log pointer, END).
- ``os_mle_data_t`` — loader-private scratch, passed through
  unmodified by SINIT (saved MTRR state is placed here by loaders).
- ``os_sinit_data_t`` — written by the loader, consumed by SINIT:
  version (4-7), flags (TPM2 PCR-extend policy), ``mle_ptab``,
  ``mle_size``, ``mle_hdr_base``, vtd PMR lo/hi base+size, LCP
  policy data, ``capabilities`` (txt_caps_t), EFI RSDT pointer,
  ext data elements (TPM2 event log descriptors).
- ``sinit_mle_data_t`` — written by SINIT, consumed by the MLE:
  version, ``edx_senter_flags``, ``mseg_valid``, hashes
  (bios_acm_id, sinit, mle, stm, lcp_policy — TPM1.2 SHA-1),
  lcp_policy_control, ``rlp_wakeup_addr``, MDR list
  (memory range descriptors), VT-d DMAR list, proc_scrtm_status,
  ext data elements.

The semantic SENTER *writes* the sinit_mle_data region (fills in the
hashes, RLP wakeup addr, MDRs) and treats the first three regions as
inputs.

MLE header
==========

The MLE occupies linear addresses ``[0, mle_size)`` in the
address space established by the page table at ``mle_ptab``
(a *physical* address, below the image); both tboot
(``txt/txt.c build_mle_pagetable``) and GRUB
(``loader/slaunch/txt.c grub_txt_setup_mle_ptab``) build a flat
map, but the table is walked, not assumed. ``mle_hdr_base`` is a
*linear offset* into that space -- tboot computes it as
``&g_mle_hdr - &_mle_start`` and comments it "linear addr
(offset from MLE base)" -- not a physical address. The header
itself (grub/tboot ``mle.h``)::

  u64  uuid (MLE_HDR_UUID), u32 length, u32 version
       (0x00020001 = 2.1), u32 entry_point, u32
       first_valid_page, u32 mle_start_off, u32 mle_end_off,
  u32  capabilities (txt_caps_t), u32 cmdline_start_off,
  u32  cmdline_end_off

``mle_start_off``/``mle_end_off`` are the loader's own bookkeeping
for deriving ``mle_size``; neither SINIT nor QEMU uses them to
bound the measurement.

``txt_caps_t`` bits select RLP wake method (GETSEC[WAKEUP] vs
MONITOR), whether EBX-page-table support is in use, TPM1.2 PCR
mapping (legacy / DA), platform type, max-phy-addr, TPM2 event log
support. The semantic SENTER honors ``rlp_wake_getsec`` /
``rlp_wake_monitor`` from the intersection of MLE and os_sinit_data
capabilities.

The emulated SINIT advertises ``rlp_wake_getsec`` and **not**
``rlp_wake_monitor``, which pins the RLP wake to GETSEC[WAKEUP].  The
choice is the ACM's to make: an MLE takes MONITOR whenever the ACM
offers it and only falls back to GETSEC otherwise (tboot
``txt/txt.c``, ``txt_launch_environment()``).  GETSEC[WAKEUP] is the
leaf this model implements, so offering MONITOR as well would only
let the MLE select a mechanism QEMU does not provide.

RLP wake is a separate question from how the MLE then *parks* its
APs, and the two are chosen independently -- the wake method comes
from this capability intersection, while the parking method is the
MLE's own decision (in tboot, the ``ap_wake_mwait`` command-line
option).  The distinction matters to this emulation because the two
parking strategies have very different requirements:

- With tboot ``ap_wake_mwait=true``, joined APs use MONITOR/MWAIT
  while waiting for Linux to start them. TCG's MONITOR ignores the
  address and its SMP MWAIT yields via ``helper_pause()``, so tboot's
  loop polls its wake flag rather than waking on a memory write. This
  is a functional bring-up path, **not** faithful MWAIT semantics;
  guests expecting a real monitored-address wake are unsupported.
- Parking APs in a VMX mini-guest (tboot's default) executes VMXON,
  VMPTRLD, a long run of VMWRITEs and VMLAUNCH, and relies on
  intercepting INIT/SIPI. **QEMU TCG implements no VMX instructions**.

The original single-vCPU path uses tboot's default VMX option, with
``txt-vmx-compat=on`` for its capability check only. The SMP path uses
``ap_wake_mwait=true`` and a CPU exposing ``monitor``; it does **not**
advertise VMX instructions TCG cannot execute. SENTER requires every
AP to be halted, rendezvouses with each vCPU and parks it before PCR
measurement. Failed launches release the APs parked by that attempt.
GETSEC[WAKEUP] transfers them to the validated join entry.

Semantic measured launch (GETSEC[SENTER])
=========================================

Preconditions checked by the helper; failures set TXT.ERRORCODE and
return without a machine reset (a QEMU semantic deviation):

1. CR4.SMXE, CPL0, chipset present (CAPABILITIES bit0).
2. EBX/ECX: SINIT ACM in guest RAM, below 4 GiB, within a nonempty,
   locked DPR (invalid or wrapping DPR bounds are rejected), ``size``
   consistent with the ACM header (header.size*4).
3. SINIT ACM validation (``intel_txt_validate_acm()`` in
   ``hw/i386/intel_txt.c``), mirroring tboot's ``is_acmod()`` /
   ``verify_acmod()`` / ``does_acmod_match_platform()``
   (``tboot/txt/acmod.c``). A failure of any of these records
   ``ACM_INVALID`` (0x80060001) and measures nothing. The region is
   checked to be:

   - sized at least the 0x4c0 fixed ACM header and a multiple of 64
     bytes; ``TXT.SINIT_BASE`` 4 KiB aligned; and the header's ``size``
     field (in dwords) * 4 equal to the GETSEC[SENTER] ACM size, which
     may be smaller than the firmware-reserved ``TXT.SINIT_SIZE``.
   - ``module_type`` = ``ACM_TYPE_CHIPSET`` (0x02),
     ``module_subtype`` = 0, and ``module_vendor`` = 0x8086. Note 0x02
     is used by *both* SINIT and BIOS ACMs — there is no
     "module_type = SINIT" value. The only defined subtype,
     ``ACM_SUBTYPE_RESET`` (0x01), marks a *reset* ACM, not a SINIT,
     and is rejected.
   - ``entry_point`` non-zero and < size.
   - to carry its info table at ``(header_len + scratch_size) * 4``,
     bounds-checked against the module, with UUID = ``ACM_UUID_V3``,
     ``version`` >= 3, and ``chipset_acm_type`` =
     ``ACM_CHIPSET_TYPE_SINIT`` (0x01). **The SINIT-vs-BIOS
     distinction lives in the info table, not the header.**
   - to carry a ``chipset_id_list``, bounds-checked, of at least one
     entry matching ``TXT.DIDVID`` (vendor, device, and revision —
     where flags bit 0 makes the entry's revision a mask). The list
     is what loaders match against; the header's own ``chipset_id``
     field is not used for this.

   The ACM ``seg_sel`` and ``gdt_limit`` are checked before the
   transfer; the ACM GDT describes the BSP's entry selectors. Not
   checked: RSA signature and public-key fields, the processor id
   list (no emulated platform id), or SINIT/MLE capability intersection.
   ``MLE_JOIN`` is for later AP wakeup, not the BSP entry.

   **No signature check**: ``rsa2048_pubkey``, ``pub_exp`` and
   ``rsa2048_sig`` are ignored. On real hardware the CPU verifies
   them before executing the ACM; that is precisely the step QEMU
   omits (see Deviations 1 and 2). Loaders do not verify the
   signature either, so an unsigned ACM that satisfies the
   structural checks above is accepted by tboot and GRUB.
4. Heap: HEAP_BASE/SIZE set, nonempty and entirely inside the DPR
   before any PCR reset (an uncovered heap records ``HEAP_INVALID``);
   the size-prefixed sections (bios_data, os_mle_data, os_sinit_data)
   parse and fit in HEAP_SIZE; os_sinit_data version in range (>= 4);
   ``mle_ptab``
   non-zero, page-aligned, below 4 GiB; ``mle_size`` non-zero,
   page-aligned and at most 2 MiB (one page table); ``mle_hdr_base``
   leaves room for an MLE header inside ``[0, mle_size)``; the MLE
   header's UUID matches ``MLE_HDR_UUID`` and its length fits in
   the image; ``entry_point`` is inside the image and resolves to a
   physical address below 4 GiB. The fourth size-prefixed section
   (sinit_mle_data) is created when its prefix is zero and must fit
   the heap together with its GOOD memory descriptors.
5. PMR input validation (before any PCR reset): low/high base and size
   must be 2 MiB aligned, non-overflowing and placed in their proper
   32-bit/64-bit address ranges. The nonempty low window must cover
   the MLE page tables and every physical page mapped by ``mle_ptab``
   for the MLE. An uncovered page records ``PMR_INVALID`` (0x80080001).
   An invalid MLE page-table entry records ``MEASURE_FAILED`` instead.
   **This validates guest inputs only; the DMA enforcement happens
   in step g.**

SINIT-equivalent sequence (unimplemented portions noted):

a. Reset DRTM PCRs 17-22 (to zero; they read all-ones before any
   launch).
b. Keep private space open for the MLE; set ``STS.private_open`` on
   successful entry.
c. Compute the MLE hash (SHA-1 for TPM1.2; for TPM2, per active
   bank: SHA-1/SHA-256/...) over ``[0, mle_size)`` as mapped by
   the page table at ``mle_ptab``, and extend PCR 18 with it.
   Ordered after the step-d hash sequence, because
   ``_TPM_Hash_Start`` zeroes PCR 18 as well.
d. Extend the first PCR17 component at **TIS locality 4** through
   the TPM backend. The remaining launch-policy/context digests
   (including PCR19) are not yet implemented.
e. Populate ``sinit_mle_data_t`` version and GOOD MDRs from guest
   E820_RAM entries, and append a copy of the guest's DMAR ACPI
   table after the MDRs, setting ``num_vtd_dmars``/``vtd_dmars_off``.
   The DMAR is located the way firmware and SINIT do: scan the first
   KiB of the EBDA (segment at 0x40E) and then 0xE0000-0xFFFFF for a
   checksum-valid ACPI RSDP, then walk its RSDT or XSDT.  The RSDP
   (both the 20-byte and, for revision 2+, the extended checksum),
   the RSDT/XSDT and the DMAR are all checksum-validated before
   anything is copied, so a stray ``RSD PTR `` string cannot be
   mistaken for a real one.  A DMAR that fails validation is reported
   as *absent* rather than copied -- handing the MLE garbage would be
   worse than handing it nothing -- and the rejection is visible via
   the ``txt_dmar_rejected`` trace point.  This copy is not optional for a VT-d
   guest: Linux under tboot deliberately ignores the firmware DMAR,
   because the ACPI tables are not DMA protected, and reads the
   measured copy out of the TXT heap instead
   (``arch/x86/kernel/tboot.c``, ``tboot_get_dmar_table()``, which
   computes ``sinit_mle_data + vtd_dmars_off - sizeof(u64)``).
   Without it such a guest panics with "tboot: Failed to initialize
   DMAR table".  A guest with no intel-iommu has no DMAR and the
   fields stay zero.  The remaining hash/policy fields remain zero.
f. The MLE writes ``TXT.MLE_JOIN`` in private MMIO after SENTER;
   GETSEC[WAKEUP] validates that block and its GDT before joining
   every sleeping AP. It is a no-op on a single-vCPU machine.
g. Program and enforce the VT-d protected memory regions. SENTER
   validates the ``os_sinit_data`` low/high PMR inputs before
   measuring (precondition 5), clears any stale PMR, programs the
   2 MiB-granularity PMR base/limit and PMEN registers, and the VT-d
   model then denies device DMA into those windows until SEXIT,
   which clears them.  SENTER fails closed when there is no VT-d
   device or a host device caches mappings outside the IOMMU.  TXT
   heap protection (including the copied DMAR) is provided by the
   separate DPR, not by the PMRs. QEMU enforces the DPR on its modeled
   PCI/ISA DMA paths, but the measured DMAR copy is **not** evidence
   of hardware-backed protection or remote attestation.
h. Set ``STS.SENTER_DONE``, ``STS.MEM_CONFIG_LOCK``.  Private space
   stays **open**: the MLE runs with it open and closes it itself
   (see below).
i. Transfer BSP control to the MLE entry point (see below). APs were
   halted and put into TXT sleep before measurement; a running AP
   rejects the launch rather than executing outside the MLE.

SMI inhibition
--------------

Once every precondition has passed (before the DRTM PCRs are
reset), SENTER engages SMI inhibition for the whole measured
environment.  An SMI that arrives while it is engaged is held for
that CPU instead of entering SMM; SEXIT or GETSEC[SMCTRL] releases
the inhibition and redelivers the held SMIs.  Because QEMU's SMM
entry is real-mode only (``smbase`` + 0x8000), the inhibition is
observable and enforceable, but it is a semantic model, not
chipset SMI masking: there is no SMM-monitor involvement, and
several SMIs held on one CPU collapse into a single redelivery.

Private space is opened at step b and is *not* closed by SENTER.  An
earlier revision of this document had step h close it, which no MLE
could survive: tboot's post-launch entry path reads ``TXT.HEAP_BASE``
from the private region before it does anything else
(``tboot/common/boot.S``, ``_post_launch_entry``), writes
``TXT.MLE_JOIN`` there to wake the APs, and only closes the region
from its own teardown path via ``CMD_CLOSE_PRIVATE``
(``tboot/txt/txt.c``, ``txt_shutdown()``).  The region is therefore
open from reset, stays open across SENTER for the MLE's use, and is
closed by the MLE or by a TXT reset.

Current implementation: SENTER parks each halted AP on its own thread,
checks the launch inputs, measures the SINIT ACM and MLE, writes the
SINIT-MLE heap section, sets the SENTER_DONE / MEM_CONFIG_LOCK /
PRIVATE_OPEN status bits, and transfers BSP execution to the physical
MLE entry with paging off. An AP that is still executing causes a
pre-measure rejection; a failed launch rolls back the newly parked APs.
The SINIT measurement uses the TIS ``_TPM_Hash_Start`` /
``_TPM_Hash_Data`` / ``_TPM_Hash_End`` signal sequence at locality 4.
``_TPM_Hash_Start`` resets the DRTM PCRs and ``_TPM_Hash_End`` extends
PCR 17 with the hash of the region in every active bank, so the TPM
does the hashing exactly as it does on real hardware.  Step c then
reads the heap, resolves the MLE through its page table, and hashes
it and extends PCR 18 host-side, standing in for the TXT hardware,
which on real systems walks the MLE page table and extends PCR 18
itself (deviation 6).

Note this sequence is the *only* mechanism that works:
``TPM2_PCR_Reset`` cannot reset PCRs 17-22 even from locality 4 (swtpm
answers ``TPM_RC_LOCALITY``), because on HW those PCRs respond to the
signal rather than to a command.  The sequence travels on the TPM
backend's control channel, so it requires ``-tpmdev emulator``; the
passthrough backend cannot express it, and ``txt=on`` refuses a
backend that does not implement it.

PCR 17 remains only the first component of the eventual composite;
launch-context digests are not yet extended, so it is not final or
attestable. PCR 18 receives the measured MLE hash.

Neither input digest is observable from the guest: the ACM digest is
computed inside the TPM by the ``_TPM_Hash_*`` sequence and never
returned, and the MLE digest is consumed directly by the extend.  The
``txt_drtm_digest`` trace point reports both, which makes a PCR value
reproducible offline -- replaying ``Extend()`` from zero over these
plus the MLE's own TCG event log must yield exactly what the guest
reads back from ``/sys/class/tpm/tpm0/pcr-sha1|sha256/<N>``.  That is
an internal-consistency check, not attestation: the fixture is
unsigned and no signature is verified (deviation 1). Invalid ACM inputs
and unsupported SMP are rejected before TPM commands; malformed MLE
or missing SINIT-MLE heap data may be rejected after DRTM measurement,
with STS.SENTER_DONE clear. A successful single-vCPU launch clears
TXT.ERRORCODE and enters the MLE instead of returning to the loader.

MLE entry CPU state (BSP), per MLE Dev Guide:

- 32-bit protected mode with **CR0.PG clear** (AM and WP clear too);
  SINIT uses the MLE page tables (from ``os_sinit_data.mle_ptab``) to
  validate/measure the image, but the first MLE instructions execute
  at physical addresses until the MLE enables its own paging,
- **CR4 = SMXE only** (0x4000).  SMXE has to survive because the MLE
  issues its own GETSEC leaves after launch; everything else the MLE
  wants (PAE, MCE, OSFXSR, ...) it must re-enable itself,
- **long mode fully disabled**: clearing CR0.PG drops ``EFER.LMA``,
  and QEMU also clears ``EFER.LME``.  This matters on a
  64-bit-capable vCPU: if LME survived, the MLE's first ``CR0.PG``
  write would enter long mode instead of the 32-bit paging it just
  built.  (tboot is a 32-bit MLE even when it boots an x86_64
  kernel, so this is the normal case, not a corner case.)
- GDTR from the **SINIT ACM header** (``gdt_base`` at offset 0x2c,
  ``gdt_limit`` at 0x28), CS = the ACM header's ``seg_sel`` (0x30,
  32-bit code, RPL0), DS/ES/SS = seg_sel+8,
- EIP = the physical address resolved from the MLE header's
  ``entry_point`` through the MLE page tables (CS.base = 0, PG=0),
- EBX = that physical entry address, ECX = physical address of
  the MLE page table, EDX = 0.  Hardware leaves CR3 undefined; QEMU
  hands over the MLE page table there as a defined value,
- EFLAGS = 0x2, so interrupts are masked; the MLE installs its own
  IDT before enabling them.

``TXT.MLE_JOIN`` is **not** the source of the BSP's entry state.  It
cannot be: tboot only writes MLE_JOIN *after* it is already running
post-launch (``tboot/txt/txt.c``, ``txt_wakeup_cpus()``), purely so
that GETSEC[WAKEUP] has somewhere to send the APs.  The ACM header is
the only GDT description available to SINIT at entry, which is also
why tboot's ``verify_acmod()`` validates ``seg_sel`` and checks it
against ``gdt_limit``.

How much of this the consumers actually rely on differs.  tboot
checks EBX against its own entry symbol and requires the MLE page
table's last PTE to map its last page (``_post_launch_entry``), so
EBX and the page table are load-bearing.  For the segment state it
assumes only that CS is usable -- ``__start`` comments "on entry only
CS is guaranteed good" and immediately reloads GDT, the data
segments and its own stack.  ESP is therefore not consumed, and
EFLAGS is overwritten by the MLE once it has a stack.  QEMU still
installs the full documented state rather than only what tboot
inspects, so that a stricter MLE is not silently accommodated.

Deviation: the ESP and EFLAGS values above, and the assumption that
the ACM header's GDT remains loaded at MLE entry, are inferred from
the consumer code rather than read from the MLE Dev Guide, which was
not available when this was written.  They are recorded here so they
can be checked against §2.4 of the guide rather than rediscovered.

Teardown (GETSEC[SEXIT])
========================

Implemented (``intel_txt_sexit()``).

- Requires measured environment; otherwise #GP.
- Clears secrets (QEMU: clears ``E2STS.SECRET_STS``), closes private
  space, clears ``STS.SENTER_DONE``, ``STS.MEM_CONFIG_LOCK`` and the
  locality-open bits, and sets ``STS.SEXIT_DONE``.
- Disables the VT-d PMRs so device DMA into the former PMR windows is
  permitted again. DPR stays programmed, locked, and DMA-excluding.
- Releases SMI inhibition and redelivers held SMIs if SMCTRL did not
  already release them.

An MLE normally arrives at SEXIT having already issued
``CMD_NO_SECRETS``, ``CMD_UNLOCK_MEM_CONFIG`` and
``CMD_CLOSE_PRIVATE`` itself, so most of that is idempotent; SEXIT
does it anyway, because the instruction has to be sufficient on its
own.

SEXIT is **not** a platform reset, and an earlier revision of this
document (and of the master plan) was wrong to describe it as one.
Execution continues at the instruction after ``GETSEC[SEXIT]``:
tboot's ``txt_shutdown()`` runs the command sequence
``CMD_NO_SECRETS`` -> ``CMD_UNLOCK_MEM_CONFIG`` ->
``CMD_CLOSE_PRIVATE``, re-asserts ``CR4.SMXE``, calls
``__getsec_sexit()`` and then *prints* "measured environment torn
down" (``tboot/txt/txt.c``) before handing off to the OS.  A reset
there would make the whole handoff unreachable.  tboot does request a
platform reset through ``TXT.CMD.RESET`` in one specific case, when
APs are still parked in wait-for-SIPI at shutdown, which is a
separate path from SEXIT itself.

SEXIT does not clear the TXT configuration registers either:
SINIT.BASE/SIZE, HEAP_BASE/SIZE and DPR stay programmed, which is
what allows a further SENTER in the same power cycle.  Only a TXT
reset clears them.  ``ESTS.TXT_RESET_STS`` remains sticky.

Machine/device wiring
=====================

- New device ``intel-txt`` (``hw/i386/intel_txt.c``), sysbus,
  created by q35 when ``-machine txt=on``.
- MMIO regions: public (64 KiB @ 0xFED30000), private (64 KiB @
  0xFED20000). TPM decode region is the existing tpm-tis; the device
  holds a link to the TPM backend for locality-4 measurements.
- MCH (q35): DPR config register + TXT-capable DIDVID reporting.
- CPU: ``smx`` CPUID bit default-enabled on the TXT machine; GETSEC
  decode in ``target/i386/tcg``; chipset SENTER_DONE state gates
  WAKEUP and SMCTRL requests. A TXT-sleep CPU flag has its own
  migration subsection and machine reset clears it.
- Migration: blocked while a launch sequence is in progress
  (measured-environment flag set, SENTER not completed); VMState
  otherwise covers all registers.

Deviations from real hardware
=============================

1. No ACM signature or key-hash verification; TXT.PUBLIC_KEY is a
   placeholder. (PCR values are *not* trustworthy for remote
   attestation of QEMU guests.)
2. SINIT executes as QEMU helper code, not from authenticated RAM;
   no GETSEC[ENTERACCS]/AC-mode. FIT, BootGuard and CBnT features
   are out of scope.
3. VT-d PMR and chipset DPR are enforced on the modeled PCI and Q35
   ISA DMA paths; other host DMA mechanisms must not bypass those paths.
   SMI inhibition between SENTER and
   SEXIT/SMCTRL is modeled semantically (held per CPU and
   redelivered, multiple held SMIs collapse to one), not as chipset
   SMI masking.  SMM-monitor (MSEG/STM) is not implemented.
4. Private config space is largely a facade (see above).
5. Only one TXT generation is modeled; the register map is the
   intersection documented above (FSB-era offsets + modern
   additions), pinned per generation as loaders require.
6. DRTM PCR values reflect QEMU's semantic measurements, which can
   differ from what a real SINIT would extend (exact per-generation
   digest lists, e.g. for PCR17, are normalized to the MLE guide's
   documented sequence).
7. SMP APs must already be halted at SENTER. GETSEC[WAKEUP] joins
   them to the MLE, but the tboot MWAIT path uses polling rather than
   memory-write-triggered wake; VMX AP parking is unsupported. The
   PCR 17 composite and VT-d enforcement remain incomplete: a
   successful transfer does not imply production-grade TXT attestation.
8. SENTER takes the SINIT base/size from the pre-programmed
   TXT.SINIT_BASE/SIZE registers; it does not latch the
   GETSEC[SENTER] EBX/ECX operands into them (on HW the chipset
   latches the operands).

Sources
=======

- coreboot ``src/security/intel/txt/`` (register map, heap, DPR,
  GETSEC parameter handling; ``txt_register.h``)
- tboot ``tboot/txt/`` + ``include/txt/`` (config_regs.h, heap.h,
  acmod.h, smx.h; launch/verify flows)
- GRUB (TrenchBoot ``grub-sl-2.12-v16``) ``loader/slaunch/`` and
  ``include/grub/i386/txt.h`` (Slaunch flow, MLE header, GETSEC
  calling conventions, SLRT)
- Intel TXT MLE Software Development Guide 315168-017 §1.9
  (DRTM PCR digests, MLE entry state)
- Linux ``arch/x86/kernel/tboot.c``, secure-launch code (runtime
  contract with the MLE)
