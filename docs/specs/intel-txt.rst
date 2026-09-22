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

TXT public config register map
===============================

All registers are 64-bit unless noted. Offsets from
``0xFED30000`` (public) and ``0xFED20000`` (private).

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
  |             |                        | or size > max ACM size                                         |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80020001  | SINIT_NOT_IN_DPR       | SINIT region not entirely inside the (nonzero) DPR range       |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80030001  | HEAP_INVALID           | TXT.HEAP_BASE/SIZE zero or region not below 4 GiB              |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80040001  | LAUNCH_INCOMPLETE      | Preconditions passed and the DRTM measurement succeeded, but   |
  |             |                        | the launch stopped short of the MLE transfer (deviation 7)     |
  +-------------+------------------------+----------------------------------------------------------------+
  | 0x80050001  | MEASURE_FAILED         | Preconditions passed but the DRTM measurement itself failed    |
  |             |                        | (TPM backend error). Distinct from LAUNCH_INCOMPLETE on        |
  |             |                        | purpose: one shared value made a rejected measurement          |
  |             |                        | indistinguishable from a staged-but-successful one             |
  +-------------+------------------------+----------------------------------------------------------------+

TXT private config space
========================

On real hardware the private space (``0xFED20000``) is writable only
by the SINIT ACM while the private space is open
(``STS.private_open`` = 1). The semantic SENTER does not need it for
its function; the device implements:

- reads returning the same register set as public space (some
  loaders poke private registers during bring-up debugging),
- writes ignored unless a launch is in progress (or always ignored,
  in semantic mode),
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

- M1: register storage + lock semantics, no enforcement.
- M5: after lock, the covered guest-RAM range is made inaccessible
  to devices (DMA) via memory-region permission changes, and to CPU
  writes outside of a launch sequence. This is *functional* (guest
  software correctness) protection, not an adversary model.

The MCH PCI config mirror is deferred to M5 (the TXT MMIO DPR at
0x330 is fully implemented from M1); its config-space offset must
be pinned from the Q35 datasheet and coreboot's
``txt_get_chipset_dpr()`` implementations.

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
  QEMU reports (GRUB defaults are a compatible baseline):
  - ACM version mask 0xFFFFFFFF, version 0
  - max ACM size 32 KiB (encoded), acquirable memory UC
  - SENTER controls 0
  - TXT extensions: processor-based SCRTM (bit 5) supported

GETSEC[SENTER] (EAX=4, EBX=SINIT ACM phys base, ECX=ACM size, EDX=0)
  See *Semantic measured launch* below. On failure the machine
  performs an TXT reset with ERRORCODE set (no return).

GETSEC[SEXIT] (EAX=5)
  Leaves the measured environment: platform reset (machine reset in
  QEMU), ``STS.SEXIT_DONE`` set after reset.

GETSEC[WAKEUP] (EAX=8)
  RLP (AP) wakeup inside the measured environment: the AP resumes at
  the entry point from the MLE_JOIN register with the documented RLP
  register state.

GETSEC[EXITAC] (EAX=3, EBX=near jump target)
  Not needed for the semantic flow (no AC mode is entered); returns
  via the near jump, or #UD until Option B.

GETSEC[SMCTRL] (EAX=7)
  SMM-control; accepted as no-op in measured environment (SMM is
  modeled as normal SMM in QEMU).

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

Located at ``mle_hdr_base`` inside the MLE image (grub/tboot
``mle.h``)::

  u32  version (0x00020001 = 2.1), u32 entry_point,
  u32  first_valid_page, mle_start_off, mle_end_off,
  u32  capabilities (txt_caps_t), cmdline offsets

``txt_caps_t`` bits select RLP wake method (GETSEC[WAKEUP] vs
MONITOR), whether EBX-page-table support is in use, TPM1.2 PCR
mapping (legacy / DA), platform type, max-phy-addr, TPM2 event log
support. The semantic SENTER honors ``rlp_wake_getsec`` /
``rlp_wake_monitor`` from the intersection of MLE and os_sinit_data
capabilities.

Semantic measured launch (GETSEC[SENTER])
=========================================

Preconditions checked by the helper, each failure raising
TXT.ERRORCODE + machine reset (as on HW):

1. CR4.SMXE, CPL0, chipset present (CAPABILITIES bit0).
2. EBX/ECX: SINIT ACM in guest RAM, below 4 GiB, within DPR cover,
   ``size`` consistent with the ACM header (header.size*4).
3. ACM header sanity, following tboot's ``is_acmod()`` /
   ``verify_acmod()`` / ``does_acmod_match_platform()``
   (``tboot/txt/acmod.c``):

   - ``module_type`` = ``ACM_TYPE_CHIPSET`` (0x02) and
     ``module_vendor`` = 0x8086. Note 0x02 is used by *both* SINIT
     and BIOS ACMs — there is no "module_type = SINIT" value.
   - ``module_subtype`` = 0. The only defined subtype,
     ``ACM_SUBTYPE_RESET`` (0x01), marks a *reset* ACM, not a SINIT.
   - ACM info table (at ``(header_len + scratch_size) * 4``): UUID =
     ``ACM_UUID_V3``, ``version`` >= 3, and ``chipset_acm_type`` =
     ``ACM_CHIPSET_TYPE_SINIT`` (0x01). **The SINIT-vs-BIOS
     distinction lives in the info table, not the header.**
   - ``entry_point`` < size; ``seg_sel`` non-zero, not LDT/PL!=0,
     ``seg_sel`` + 8 <= ``gdt_limit``.
   - base 4 KiB aligned; size a multiple of 64 and <= the max ACM
     size reported by GETSEC[PARAMETERS].
   - TXT.DIDVID (vendor/device/revision) appears in the info
     table's ``chipset_id_list``. The list is what loaders match
     against; the header's own ``chipset_id`` field is not used for
     this.

   **No signature check**: ``rsa2048_pubkey``, ``pub_exp`` and
   ``rsa2048_sig`` are ignored. On real hardware the CPU verifies
   them before executing the ACM; that is precisely the step QEMU
   omits (see Deviations 1 and 2). Loaders do not verify the
   signature either, so an unsigned ACM that satisfies the
   structural checks above is accepted by tboot and GRUB.
4. Heap: HEAP_BASE/SIZE set; bios_data and os_sinit_data parse,
   versions in range; MLE header at ``mle_hdr_base`` inside
   ``[mle_ptab, mle_ptab + mle_size)``.

Steps performed by QEMU (standing in for SINIT):

a. Reset DRTM PCRs 17-22 (to zero; they read all-ones before any
   launch).
b. Open private space, set ``STS.private_open``.
c. Compute MLE hash (SHA-1 for TPM1.2; for TPM2, hash per active
   bank: SHA-1/SHA-256/...) over the MLE pages indicated by the MLE
   header (``mle_start_off`` .. ``mle_end_off``, first_valid_page).
d. Extend at **TIS locality 4** through the TPM backend:
   PCR17 (launch policy / DRTM control digests, MLE guide Table 1),
   PCR18 (MLE hash — SinitMleData.MleHash digest), PCR19 (launch
   context digests). Locality 3 is used for the SINIT-authority
   digests where applicable.
e. Populate ``sinit_mle_data_t``: version, edx_senter_flags,
   sinit_hash, mle_hash, stm_hash, lcp_policy_hash, rlp_wakeup_addr,
   MDRs (from the guest memory map), num_vtd_dmars=0,
   proc_scrtm_status.
f. Set ``TXT.MLE_JOIN`` semantics: record the RLP join (from
   os_sinit_data or MLE header) so GETSEC[WAKEUP] can send APs there.
g. Enforce VT-d PMR-equivalent protection on the MLE range
   (M5-level functional enforcement).
h. Set ``STS.SENTER_DONE``, ``STS.MEM_CONFIG_LOCK``; close private
   space.
i. Transfer BSP control to the MLE entry point (see below). APs are
   held in the TXT sleep state until GETSEC[WAKEUP] / MONITOR wake.

Current staged state (deviation 7): the helper implements the
preconditions plus steps a and d over the SINIT ACM region
(TXT.SINIT_BASE/SIZE), using the TIS ``_TPM_Hash_Start`` /
``_TPM_Hash_Data`` / ``_TPM_Hash_End`` signal sequence at locality 4.
``_TPM_Hash_Start`` resets the DRTM PCRs and ``_TPM_Hash_End`` extends
PCR 17 with the hash of the region in every active bank, so the TPM
does the hashing exactly as it does on real hardware.

Note this sequence is the *only* mechanism that works:
``TPM2_PCR_Reset`` cannot reset PCRs 17-22 even from locality 4 (swtpm
answers ``TPM_RC_LOCALITY``), because on HW those PCRs respond to the
signal rather than to a command.  The sequence travels on the TPM
backend's control channel, so it requires ``-tpmdev emulator``; the
passthrough backend cannot express it, and ``txt=on`` refuses a
backend that does not implement it.

The resulting PCR 17 is still only the *first component* of the
eventual composite; steps c/e extend the remainder (MLE and
launch-context digests), so it is neither final nor attestable and
will change when those land.  PCR 18 (the MLE hash) is not extended
yet.  Instead of steps b-i, SENTER records TXT.ERRORCODE =
0x80040001 (LAUNCH_INCOMPLETE) and returns normally;
STS.SENTER_DONE is not set, so a loader seeing ERRORCODE/STS observes
a failed launch — the staging state the master plan sanctions.  A
precondition failure records the matching precondition ERRORCODE and
issues no TPM commands at all.

MLE entry CPU state (BSP), per MLE Dev Guide:

- 32-bit protected mode, paging enabled with the MLE page tables
  (from ``os_sinit_data.mle_ptab``), EPT/``ecx_pgtbl`` variants
  honored,
- GDTR from the MLE_JOIN GDT (the loader-provided GDT), CS =
  seg_sel (32-bit code, RPL0), DS/ES/SS = seg_sel+8,
- EIP = MLE_JOIN entry_point, ESP = a value the MLE expects
  (tboot/GRUB pass it via os_mle_data; pinned in M3),
- interrupts/NMI/SMI masked as per the guide, EFLAGS fixed,
- EBX/ECX/EDX scrubbed; the environment is "monitored".

The exact register details are pinned in M3 against the MLE Dev
Guide §2.4 and the tboot/grub MLE entry assembly (the loaders are
tolerant of legitimate HW variance here).

Teardown (GETSEC[SEXIT])
========================

- Requires measured environment; otherwise #GP.
- Clears secrets (QEMU: clears ``E2STS.SECRET_STS``), releases DPR
  and PMR enforcement, resets the platform (full machine reset in
  QEMU, matching HW's TXT reset semantics), leaving
  ``ESTS.TXT_RESET_STS`` and ``STS.SEXIT_DONE`` readable until the
  next TXT reset.

Machine/device wiring
=====================

- New device ``intel-txt`` (``hw/i386/intel_txt.c``), sysbus,
  created by q35 when ``-machine txt=on``.
- MMIO regions: public (64 KiB @ 0xFED30000), private (64 KiB @
  0xFED20000). TPM decode region is the existing tpm-tis; the device
  holds a link to the TPM backend for locality-4 measurements.
- MCH (q35): DPR config register + TXT-capable DIDVID reporting.
- CPU: ``smx`` CPUID bit default-enabled on the TXT machine; GETSEC
  decode in ``target/i386/tcg``; a CPU-state "measured environment"
  flag gates SEXIT/WAKEUP/SMCTRL.
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
3. VT-d PMR/SMM-monitor (MSEG/STM) enforcement is functional only.
4. Private config space is largely a facade (see above).
5. Only one TXT generation is modeled; the register map is the
   intersection documented above (FSB-era offsets + modern
   additions), pinned per generation as loaders require.
6. DRTM PCR values reflect QEMU's semantic measurements, which can
   differ from what a real SINIT would extend (exact per-generation
   digest lists, e.g. for PCR17, are normalized to the MLE guide's
   documented sequence).
7. SENTER is staged ("semantic measured launch": preconditions +
   steps a and d over the SINIT region): it does not transfer
   control to the MLE, does not set STS.SENTER_DONE, and returns
   normally instead of performing the HW TXT reset.  Both the
   successful-measurement path and the precondition failures
   therefore surface as defined TXT.ERRORCODE values (table above)
   that a loader reading the registers would treat as a failed
   launch.  This is the master plan's M2/M3 staging state, to be
   replaced when the MLE entry/transfer slice lands.
8. The staged SENTER takes the SINIT base/size from the pre-
   programmed TXT.SINIT_BASE/SIZE registers; it does not latch the
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
