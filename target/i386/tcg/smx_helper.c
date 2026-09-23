/*
 * QEMU Intel TXT (Trusted Execution Technology)
 *
 * GETSEC (SMX) instruction emulation: static leaves and single-vCPU
 * semantic SENTER (see hw/i386/intel_txt.c). Single-vCPU WAKEUP and
 * post-launch SMCTRL are accepted; SEXIT/ENTERACCS/EXITAC are deferred.
 *
 * Copyright (c) 2026 Michał Kopeć <michal@nozomi.space>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cpu-defs.h"
#include "exec/helper-proto.h"
#include "exec/translation-block.h"
#include "accel/tcg/cpu-loop.h"
#include "helper-tcg.h"
#include "hw/i386/intel_txt.h"
#include "qemu/bitops.h"
#include "trace.h"

/*
 * GETSEC leaf numbers (Intel SDM vol. 2, "GETSEC"; tboot smx.h).
 */
#define GETSEC_LEAF_CAPABILITIES    0
#define GETSEC_LEAF_SENTER          4
#define GETSEC_LEAF_PARAMETERS      6
#define GETSEC_LEAF_SMCTRL         7
#define GETSEC_LEAF_WAKEUP         8

/*
 * GETSEC[CAPABILITIES] leaf bitmap.  Bit 0 is raised only when the
 * emulated Intel TXT chipset device is present; bits 3-8 advertise
 * the leaves this target decodes.  ENTERACCS (bit 2) and the
 * extended leaves (bit 31) are not supported.
 */
#define GETSEC_CAPABILITIES_BASE \
    (BIT(3) | BIT(4) | BIT(5) | BIT(6) | BIT(7) | BIT(8))

/*
 * GETSEC[PARAMETERS]: one table entry per call, EBX indexes the
 * entries.  EAX holds the entry type in its low five bits, with the
 * entry value in the remaining EAX bits; EBX/ECX carry the value(s)
 * as well.  The table is terminated by an entry of type 0.
 *
 * The parameter values occupy EAX bits [31:5] (the low five bits
 * encode the type). The ACM maximum is a 32-byte-granularity field
 * at that bit position; masking EAX with ~0x1f gives its byte count.
 * Tboot's get_parameters() uses that mask, so 32 KiB is 0x8000, not
 * 0x400. An older TrenchBoot GRUB macro erroneously multiplies the
 * masked value by another 0x20; do not replicate that overestimate.
 *  - GRUB_SMX_GET_ACM_MEMORY_TYPES() keeps the high bits (UC -> 0x100);
 *  - GRUB_SMX_GET_SENTER_CONTROLS() extracts bits [15:8];
 *  - GRUB_SMX_GET_TXT_EXT_FEATURES() keeps bits [6:5]
 *    (processor-based SCRTM -> 0x20).
 */
#define GETSEC_PARAM_ACM_MEMORY_TYPE_UC       0x100
#define GETSEC_PARAM_TXT_EXT_PROCESSOR_SCRTM  BIT(5)
/* 32 KiB maximum ACM execution area, in bytes (EAX bits [31:5]). */
#define GETSEC_PARAM_MAX_ACM_SIZE             0x8000

#if !defined(CONFIG_USER_ONLY) && defined(CONFIG_TPM)
static void getsec_load_mle_seg(CPUX86State *env, int reg, uint32_t selector,
                                uint64_t desc)
{
    uint32_t e2 = desc >> 32;
    uint32_t limit = (desc & 0xffff) | (e2 & 0xf0000);
    uint32_t base = ((desc >> 16) & 0xffff) | ((e2 & 0xff) << 16) |
                    (e2 & 0xff000000);

    if (e2 & DESC_G_MASK) {
        limit = (limit << 12) | 0xfff;
    }
    cpu_x86_load_seg_cache(env, reg, selector, base, limit, e2);
}
#endif

void helper_getsec(CPUX86State *env)
{
    uint32_t leaf = (uint32_t)env->regs[R_EAX];

    /*
     * Per the SDM, GETSEC is only available with CR4.SMXE set; the #UD
     * from a disabled SMX takes precedence over the #GP(0) that a
     * non-zero CPL would raise.
     */
    if (!(env->cr[4] & CR4_SMXE_MASK)) {
        trace_getsec_smxe_off(leaf);
        raise_exception_err_ra(env, EXCP06_ILLOP, 0, GETPC());
    }

    if ((env->hflags & HF_CPL_MASK) != 0) {
        trace_getsec_cpl(leaf);
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }

    switch (leaf) {
    case GETSEC_LEAF_CAPABILITIES:
        env->regs[R_EAX] = GETSEC_CAPABILITIES_BASE |
                          (env_archcpu(env)->txt_state ? BIT(0) : 0);
        break;
    case GETSEC_LEAF_PARAMETERS: {
        /*
         * The parameter index is passed in EBX (SDM; matches the
         * calling convention of tboot and TrenchBoot GRUB, which
         * both use "b" for the index of this leaf).
         */
        uint32_t index = (uint32_t)env->regs[R_EBX];
        uint32_t type = 0;
        uint32_t eax_value = 0;
        uint32_t ebx = 0;
        uint32_t ecx = 0;

        switch (index) {
        case 0:
            type = 1;  /* ACM versions: EBX = version mask, ECX = version */
            ebx = 0xffffffff;
            break;
        case 1:
            type = 2;  /* max ACM execution area, bytes */
            eax_value = ebx = GETSEC_PARAM_MAX_ACM_SIZE;
            break;
        case 2:
            type = 3;  /* ACM memory types: UC */
            eax_value = ebx = GETSEC_PARAM_ACM_MEMORY_TYPE_UC;
            break;
        case 3:
            type = 4;  /* SENTER controls: none */
            break;
        case 4:
            type = 5;  /* TXT processor extensions: processor-based SCRTM */
            eax_value = ebx = GETSEC_PARAM_TXT_EXT_PROCESSOR_SCRTM;
            break;
        default:
            break;  /* type 0: end of the parameter table */
        }

        env->regs[R_EAX] = type | eax_value;
        env->regs[R_EBX] = ebx;
        env->regs[R_ECX] = ecx;
        break;
    }
#ifndef CONFIG_USER_ONLY
    /*
     * The chipset device this leaf drives (hw/i386/intel_txt.c) is
     * only linked into the system emulator, so the case is compiled
     * out for linux-user.  Nothing is lost: user mode always runs at
     * CPL 3, so the CPL check above has already raised #GP(0) and
     * this leaf is unreachable there.
     */
    case GETSEC_LEAF_SENTER:
        /* The chipset-present check is the CAPABILITIES bit-0 contract. */
        if (env_archcpu(env)->txt_state == NULL) {
            trace_getsec_senter_no_chipset();
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
            break;
        }
#ifdef CONFIG_TPM
        {
            IntelTxtMleEntry entry;

            trace_getsec_senter();
            if (!intel_txt_senter(env_archcpu(env)->txt_state,
                                  (uint32_t)env->regs[R_EBX],
                                  (uint32_t)env->regs[R_ECX], &entry)) {
                break;
            }
            /*
             * SINIT enters the MLE with paging off at the physical
             * address resolved from the measured MLE mapping. Tboot's
             * first instructions use absolute physical TXT MMIO and
             * expect EBX to contain that same physical entry address.
             */
            cpu_x86_update_cr0(env, env->cr[0] & ~CR0_PG_MASK);
            cpu_x86_update_cr4(env, env->cr[4] | CR4_PAE_MASK);
            cpu_x86_update_cr3(env, entry.ptab);
            env->gdt.base = entry.gdt_base;
            env->gdt.limit = entry.gdt_limit;
            getsec_load_mle_seg(env, R_CS, entry.seg_sel, entry.cs_desc);
            getsec_load_mle_seg(env, R_DS, entry.seg_sel + 8,
                                entry.ds_desc);
            getsec_load_mle_seg(env, R_ES, entry.seg_sel + 8,
                                entry.ds_desc);
            getsec_load_mle_seg(env, R_SS, entry.seg_sel + 8,
                                entry.ds_desc);
            cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0, 0);
            cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0, 0);
            env->regs[R_EBX] = entry.entry_phys;
            env->regs[R_ECX] = entry.ptab;
            env->regs[R_EDX] = 0;
            env->regs[R_ESP] = 0;
            cpu_load_eflags(env, 0x2, ~0u);
            env->eip = entry.entry_phys;
            cpu_x86_update_cr0(env, (env->cr[0] | CR0_PE_MASK) &
                                    ~CR0_PG_MASK);
            cpu_loop_exit(env_cpu(env));
        }
#endif
        break;
#ifdef CONFIG_TPM
    case GETSEC_LEAF_SMCTRL:
        if (!env_archcpu(env)->txt_state ||
            !intel_txt_smctrl(env_archcpu(env)->txt_state,
                              (uint32_t)env->regs[R_EBX])) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        break;
    case GETSEC_LEAF_WAKEUP:
        if (!env_archcpu(env)->txt_state ||
            !intel_txt_wakeup(env_archcpu(env)->txt_state)) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        break;
#endif
#endif /* !CONFIG_USER_ONLY */
    default:
        /*
         * ENTERACCS, EXITAC and SEXIT are not implemented yet;
         * report #UD so the missing leaf stays observable.
         */
        trace_getsec_unimpl(leaf);
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
        break;
    }
}
