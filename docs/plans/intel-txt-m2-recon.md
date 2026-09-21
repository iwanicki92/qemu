# QEMU Intel TXT — M2/M3 Recon Handoff

Repo: `/home/michal/Development/qemu`, HEAD `059ce2ad26` (VERSION file says 11.1.50; upstream-staging merge base `c1c18d1e64`).
Read-only recon; no files modified. All line numbers verified in this tree.

## 1. GETSEC (0F 37) decode in TCG

The x86 TCG frontend is **split files**, not one big switch:
- `target/i386/tcg/translate.c` (3607 ln) — codegen: `gen_exception` (1505), `gen_illegal_opcode`→EXCP06 (1516), `gen_exception_gpf` (1521), `check_cpl0` (1528), `#include "emit.c.inc"` at 2138.
- `target/i386/tcg/decode-new.c.inc` (3201 ln) — opcode tables + dispatch.
- `target/i386/tcg/emit.c.inc` (4822 ln) — `gen_<OP>()` functions.

**Dispatch chain for 0F 37:**
1. `disas_insn` `decode-new.c.inc:2783` reads first byte, handles prefixes, then `decode_insn(..., decode_func=decode_root, ...)` at 2973.
2. `decode_insn` (2466) → `decode_root` (2006) → `opcodes_root[0x0F]` = `X86_OP_GROUP0(0F)` (**1848**) which has `.is_decode=true, .decode=decode_0F` (macros at 225; GROUP0 sets `.decode=glue(decode_,op)` at ~168-175).
3. `decode_0F` (1556-1561) reads 2nd byte → `*entry = opcodes_0F[*b]` (1560).
4. **`opcodes_0F[256]` starts at 1269 and has NO `[0x37]` entry** (gap between `[0x35] SYSEXIT` ~1299 and `[0x40] CMOVcc` ~1300). Zeroed entry → `if (!decode.e.gen) goto unknown_op` (2976) → `unknown_op:` (3193) → `gen_illegal_opcode(s)` + `dump_unknown_opcode` = **#UD today**. That is the current GETSEC path.

**Hook point:** add `[0x37] = X86_OP_ENTRY0(GETSEC)` to `opcodes_0F` (decode-new.c.inc, ~1299), plus `gen_GETSEC` in emit.c.inc and `helper_getsec` (decl in `target/i386/helper.h`, impl in `tcg/misc_helper.c` or `int_helper.c`). Entry macros: `X86_OP_ENTRY0` at decode-new.c.inc:225; `cpuid(feat)`, `chk(...)` helpers at 236-259.

**Gating patterns:**
- *Static* (checked in `disas_insn` after decode): `has_cpuid_feature` → `goto illegal_op` (2979); `decode.e.check` bits (2993+): `X86_CHECK_i64`, `X86_CHECK_i64_amd`, `cpl0`, `prot` (see entries `[0x05] SYSCALL`, `[0x07] SYSRET`, `[0x34] SYSENTER` in `opcodes_0F`).
- *Runtime* (in `gen_*` / helpers): `env->cr[4] & CR4_...` — e.g. `helper_rdtsc` (tcg/misc_helper.c:69, CR4_TSD), `helper_rdpmc` (:81, CR4_PCE), `helper_rdpkru` (:107, CR4_PKE) raising `raise_exception_ra(EXCP06/0D)`. `gen_AAA` (emit.c.inc:1136-1141) is the closest codegen template: `gen_update_cc_op → gen_helper_x(tcg_env) → assume_cc_op`.
- Helper invocation from translate/emit: `gen_helper_name(tcg_env, args...)` (macro translate.c:230); e.g. `gen_helper_aaa(tcg_env)` emit.c.inc:1139; `helper_aaa` impl tcg/int_helper.c:167.
- CPU-vendor gate: `IS_INTEL_CPU(env)` macro cpu.h:1293; used in disas_insn (2989).

**AAA/0F 37 conflict — verified quirk:** on real HW 0F 37 is AAA when SMX off, GETSEC when CR4.SMXE=1. In QEMU the 0F-table slot 0x37 is empty (both pre- and post decoder-migration: old `translate.c` had `case 0x137` absent; old root switch had `case 0x37: /* aaa */` — i.e. TCG never decoded two-byte 0F 37; it decodes *single-byte* 0x37 as AAA, still present as `opcodes_root[0x37] = X86_OP_ENTRY0(AAA, chk(i64))` decode-new.c.inc:1734). So M2's `gen_GETSEC` should branch at runtime: SMX on → GETSEC; else fall through to `helper_aaa` (restoring 0F 37 AAA, real-HW semantics). Verify with `tests/tcg/i386/test-i386.c:1099` (`TEST_BCD(aaa, ...)`, 32-bit only, under `#if !defined(__x86_64__)` at 1052) before/after.

## 2. CR4.SMXE, CPUID smx, `-cpu +smx`

- `CR4_SMXE_MASK (1U << 14)` — `target/i386/cpu.h:276` (only definition+no users yet; M2 adds the first consumer).
- `CPUID_EXT_SMX (1U << 6)` — `target/i386/cpu.h:790` (CPUID leaf 1, **ECX** bit 6); feature word enum `FEAT_1_ECX` cpu.h:690.
- Feature-name table: `[FEAT_1_ECX] .feat_names = {..., "ds-cpl", "vmx", "smx", "est", ...}` — cpu.c:1066-1069 (index 6 = "smx").
- `-cpu +smx` machinery: `x86_cpu_parse_featurestr` cpu.c:7874 (registered `cc->parse_features` cpu.c:10923) toggles `features[FEAT_1_ECX]`; `cpu_x86_cpuid` cpu.c:8611 reports the bit to guests.
- Default models: **none ship smx**. `TCG_EXT_FEATURES` (cpu.c:900-908) explicitly excludes it ("missing: ... CPUID_EXT_VMX, CPUID_EXT_SMX ..."); default model `qemu64` (cpu.c:3545) sets only `CPUID_EXT_SSE3|CPUID_EXT_CX16` for FEAT_1_ECX; newer models repeat the "missing SMX" comment (cpu.c:5645, 7087). Guests must opt in: `-cpu <model>+smx`.
- VMX precedent for a similar capability query: `x86_cpu_has_vmx` pattern at cpu.h:2935 (`env->features[FEAT_1_ECX] & CPUID_EXT_VMX`) — mirror it for smx if needed.

## 3. How TCG target code reaches a machine device

Existing pattern = **raw pointer stored on CPUX86State**:
- Field: `APICCommonState *apic_state;` — cpu.h:2526 (comment: "in order to simplify APIC support, we leave this pointer to the user").
- Setter (CPU-side): `x86_cpu_apic_create` — `target/i386/cpu-apic.c:45-62`: `cpu->apic_state = APIC_COMMON(object_new_with_class(...))`, `object_property_add_child(OBJECT(cpu), "lapic", ...)`, back-pointer `apic_state->cpu = cpu`. Cleanup cpu.c:10359-10361; usage cpu.c:9526, 9554.
- Device→CPU back-read: `hw/i386/vapic.c:388, 522, 738` (`cpu->apic_state`).

**Recommendation for GETSEC → intel-txt device:** add `IntelTxtState *txt_state;` next to `apic_state` (cpu.h ~2526). The intel-txt device is a machine-level singleton, so the *machine* (not the CPU) should set it: in `q35_machine_init`/`pc_machine_init`, after creating the device (gated by `-machine txt=on`), loop over the CPU array and assign `cpu->env.txt_state = txt;` (same loop the machine already uses for cpus). Helper then does `CPUX86State *env` → `env->txt_state` directly — no QOM lookup, matches the apic/vapic idiom and keeps target/ decoupled from hw/ (only a forward declaration of the state struct in cpu.h). Avoid a QOM link (the apic code itself carries `/* TODO: convert to link<> */` at cpu-apic.c:55); a pointer set by the machine is the established norm here.

## 4. Machine property pattern ('smm'), tpm-tis, TPM backend API

**'smm' is on X86MachineState, not PCMachineClass** (hw/i386/pc.c has no smm code):
- Field: `OnOffAuto smm;` — `include/hw/i386/x86.h:75`; name macro `X86_MACHINE_SMM "smm"` x86.h:98.
- Property registered in `x86_machine_class_init` — `hw/i386/x86.c:393-396`: `object_class_property_add(oc, X86_MACHINE_SMM, "OnOffAuto", x86_machine_get_smm, x86_machine_set_smm, NULL, NULL)`; getter/setter x86.c:191-205 (plain `visit_type_OnOffAuto`); default `ON_OFF_AUTO_AUTO` set in `x86_machine_initfn` x86.c:364.
- Consumer: `x86_machine_is_smm_enabled` x86.c:165-189 (tcg→always on; kvm→`kvm_has_smm()`; ON_OFF_AUTO_ON+unsupported→exit).
- q35 propagation: `hw/i386/pc_q35.c:228` (vmclock/SMRAM sizing via `x86_machine_is_smm_enabled`) and :241-242 `qdev_prop_set_bit(lpc_dev, "smm-enabled", ...)`; PIIX4 twin at hw/i386/pc_piix.c:250.

**M2/M3 analogue:** add `OnOffAuto txt` to X86MachineState + `object_class_property_add` in x86.c class init (copy the smm triple), then in `pc_q35.c` q35 init create the device + wire `cpu->env.txt_state`. Note q35's MCH child already carries an SMM-related property: `mch.has_smm_ranges` default true set in `hw/pci-host/q35.c:194` (props block ~672-683: `DEFINE_PROP_UINT16("extended-tseg-mbytes"...)`, `DEFINE_PROP_BOOL("smbase-smram"...)`), applied in realize via `object_initialize_child(OBJECT(s), "mch", ...)` q35.c:222.

**TPM: the PC machine does NOT instantiate tpm-tis** — the user passes `-device tpm-tis` (`TYPE_TPM_TIS_ISA "tpm-tis"` / `TYPE_TPM_TIS_SYSBUS "tpm-tis-device"`, `include/system/tpm.h:47-48`) plus a backend (`hw/tpm/tpm_ppi.c` etc.). Machines find it via singleton `TPMIf *tpm_find(void)` — tpm.h:66-72 (used by `hw/i386/acpi-build.c:875, 2346` for ACPI TCPA/PPI tables). `TPMIf` is an interface (`TPMIfClass` tpm.h:37-46: `model`, `request_completed`, `get_version`).

**Backend API = `include/system/tpm_backend.h`** (old `tpm_emulator_*` names are gone in this tree; everything is `tpm_backend_*`):
- `tpm_backend_init` :104, `tpm_backend_startup_tpm(s, buffersize)` :114, `tpm_backend_had_startup_error` :124,
- **`tpm_backend_deliver_request(s, TPMBackendCmd *cmd)` :134** — the programmatic command-submit path,
- `tpm_backend_reset` :143, `tpm_backend_cancel_cmd` :152, `tpm_backend_get_tpm_established_flag` :162, `tpm_backend_reset_tpm_established_flag(s, uint8_t locty)` :171 (locality-qualified), `tpm_backend_get_tpm_version` :181, `tpm_backend_get_buffer_size` :191, `tpm_backend_finish_sync` :200, `tpm_backend_query_tpm` :210, `tpm_backend_get_type` :91.

**TIS flow** (`hw/tpm/tpm_tis_common.c`; the device keeps `be_driver` = TPMBackend*):
- submit: `tpm_backend_deliver_request(s->be_driver, &s->cmd)` at :104 (old `tpm_tis_submit_command` equivalent);
- locality: `tpm_tis_locality_from_addr` :53, `tpm_tis_new_active_locality` :138, ctrl-register locality seize/grant logic in the write path :479-605, `tpm_backend_reset_tpm_established_flag(s->be_driver, locty)` :649;
- lifecycle: `tpm_backend_startup_tpm` :854, `tpm_backend_finish_sync` :874, `tpm_backend_cancel_cmd` :224/643.
For the TXT helper's programmatic PCR-extend: obtain `TPMIf *tpm = tpm_find()`, use its backend (`TPMState`/`be_driver` if it's TIS) and call `tpm_backend_deliver_request` with a `TPMBackendCmd`; locality-4 semantics live in the TIS ctrl path above (the swtpm locality-4 spike from the plan maps here).

## 5. q35 MCH PCI config dispatch (DPR mirror hook)

- `static void mch_write_config(PCIDevice *d, uint32_t address, uint32_t val, int len)` — `hw/pci-host/q35.c:471-506`:
  calls `pci_default_write_config` first, then per-register `ranges_overlap(address, len, MCH_HOST_BRIDGE_PAM0|PCIEXBAR|SMRAM|EXT_TSEG_MBYTES|F_SMBASE, size)` branches → `mch_update_pam` (:338), `mch_update_pciexbar` (:299), `mch_update_smram`/`mch_update_ext_tseg_mbytes`/`mch_update_smbase_smram` (all gated by `mch->has_smm_ranges`).
- Registration: `mch_class_init` q35.c:685-699 — `k->realize = mch_realize;` `k->config_write = mch_write_config;` (:691). **No `config_read` override** → reads fall through to `pci_default_read_config`.
- Register offsets: `include/hw/pci-host/q35.h:86-103` (`MCH_HOST_BRIDGE_EXT_TSEG_MBYTES 0x50`, `PCIEXBAR 0x60`, `F_SMBASE 0x9c`, plus `*_SIZE`/`*_ADMSK`/`*_QUERY`/`*_DEFAULT` per register).
- **DPR hook:** add `MCH_HOST_BRIDGE_DPR` offset (real hw: 0x330) + size/mask in q35.h; add one more `ranges_overlap` branch in `mch_write_config` that forwards to the intel-txt device (e.g. `txt_dpr_write(txt, val, len)`); if DPR needs readable mirror state, set `k->config_read` and call `pci_default_read_config` + override that offset. The `mch_update_*` post-write pattern (:338+ `mch_update_pam`) is the template for keeping MMIO regions in sync.

## Start Here
Open `target/i386/tcg/decode-new.c.inc` (table at 1269, dispatch at 2783) — M2 lives here: add the `[0x37]` entry + `gen_GETSEC` (emit.c.inc) + `helper_getsec` (helper.h/misc_helper.c), gating on `env->cr[4] & CR4_SMXE_MASK` (cpu.h:276) and `env->features[FEAT_1_ECX] & CPUID_EXT_SMX` (cpu.h:790), then reach the device via a new `txt_state` pointer on CPUX86State (cpu.h:2526) set by the q35 machine following the `smm` property pattern (x86.c:191-205, 393-396).

## Residual risks / open questions
- AAA 0F 37 behavior in TCG is a verified table-level quirk (0F slot empty; single-byte 0x37 = AAA) but was **not** empirically run (no build tree); confirm with `tests/tcg/i386` (32-bit) before M2 lands so the new entry doesn't regress guest AAA.
- `VERSION` file reads 11.1.50 — treat this fork's versioning as nonstandard; pin line numbers to HEAD `059ce2ad26`.
- TPM locality-4 programmatic submit has no existing caller in-tree (only TIS ctrl path); the M3 helper will be the first — the swtpm spike is the de-risking step.
- `opcodes_0F` is `static const` — runtime SMX gating must happen in `gen_GETSEC`, not in the table.
- KVM out of scope: `x86_machine_is_smm_enabled`-style hypervisor gating may be wanted for `-machine txt=on` (error out under KVM, like smm).
