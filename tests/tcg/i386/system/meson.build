tests = []

minilib_dir = meson.current_source_dir() / '..' / '..' / 'minilib'
minilib_printf = files(minilib_dir / 'printf.c')[0]
link_script = files('kernel.ld')[0]
boot = files('boot.S')[0]
cflags = ['-nostdlib',
          '-ffreestanding',
          '-Wa,--noexecstack',
          '-I', minilib_dir, minilib_printf, boot,
          '-Wl,-T', link_script,
          '-Wl,-melf_i386',
          '-Wl,--no-warn-rwx-segments',
          '-lgcc']
qemu_def_args = ['-display', 'none',
                 '-device', 'isa-debugcon,chardev=stdio',
                 '-chardev', 'stdio,id=stdio',
                 '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x4',
                 '-kernel']

# The images are 32-bit Multiboot kernels, which qemu-system-x86_64 loads
# too, so they run on it when qemu-system-i386 is not built
if 'qemu-system-i386' in emulators
  i386_system_qemu = emulators['qemu-system-i386']
elif 'qemu-system-x86_64' in emulators
  i386_system_qemu = emulators['qemu-system-x86_64']
endif

# Multi arch tests, on the i386 binary only: they already run under
# x86_64-softmmu, and their gdbstub tests expect an i386 target
if 'qemu-system-i386' in emulators
  multi_src = []
  foreach t: tcg_tests['multiarch-softmmu']['tests']
    foreach src, setup: t
      new_cflags = cflags
      if fs.stem(src) == 'memory'
        new_cflags += '-DCHECK_UNALIGNED=1'
      endif
      if src not in multi_src
        setup += {'cflags': [new_cflags]}
        multi_src += src
      endif
      tests += {src: setup + {'qemu_args': qemu_def_args}}
    endforeach
  endforeach
endif

if is_variable('i386_system_qemu')
  # GETSEC/SMX test; smx is not part of any default CPU model.
  # -fno-pie/-Wl,-no-pie: the #UD gate is naked and must keep its
  # entry point on hosts with default-PIE compilers; -fno-stack-protector
  # keeps the freestanding binary free of __stack_chk_fail.
  # -msse: the TXT register space only accepts 8-byte accesses, which
  # 32-bit code issues by staging the value through an XMM register
  # (see txt_read64/txt_write64); -msse enables XMM register
  # clobbers in the freestanding build.  The +sse CPU feature is the
  # matching guest side: without it the SSE staging instructions
  # raise #UD (qemu32's baseline PPRO feature set has no SSE).
  # The staged GETSEC[SENTER] coverage needs the intel-txt chipset
  # and a TPM, so the test runs on q35 with txt=on and a swtpm-backed
  # emulator backend; the wrapper starts swtpm and substitutes its
  # control socket path (SWTPM_SOCKET_PLACEHOLDER) before exec'ing
  # QEMU.
  run_swtpm_test = find_program('run-swtpm-test.sh')
  tests += {
    'test-smx-busy-ap.c': {
      'cflags': cflags + ['-fno-pie', '-Wl,-no-pie',
                          '-fno-stack-protector'],
      'qemu_args': ['-machine', 'q35,txt=on',
                    '-cpu', 'qemu32,smx,sse', '-smp', '2',
                    '-chardev',
                    'socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER',
                    '-tpmdev', 'emulator,id=tpm0,chardev=tpm0',
                    '-device', 'tpm-tis,tpmdev=tpm0'] + qemu_def_args,
      'wrapper': [run_swtpm_test],
    },
    'test-smx-getsec.c': {
      'cflags': cflags + ['-fno-pie', '-Wl,-no-pie',
                          '-fno-stack-protector', '-msse'],
      # intel-iommu makes the machine publish a DMAR ACPI table, which
      # SENTER must copy into sinit_mle_data for the MLE; the test
      # checks that copy, so the device is load-bearing here.
      # iommu-testdev provides the DMA engine the PMR denial checks
      # drive through the IOMMU address space.
      'qemu_args': ['-machine', 'q35,txt=on',
                    '-cpu', 'qemu32,smx,sse',
                    '-device', 'intel-iommu',
                    '-device', 'iommu-testdev',
                    '-chardev',
                    'socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER',
                    '-tpmdev', 'emulator,id=tpm0,chardev=tpm0',
                    '-device', 'tpm-tis,tpmdev=tpm0'] + qemu_def_args,
      'wrapper': [run_swtpm_test],
    },
  }

  # The platform txt-firmware=on leaves for the kernel SeaBIOS boots.
  # txt-vmx-compat=on gives the CPU VMX, so QEMU would otherwise hand
  # SeaBIOS a feature control value to write over the locked MSR.
  tests += {
    'test-txt-firmware.c': {
      'cflags': cflags + ['-fno-pie', '-Wl,-no-pie',
                          '-fno-stack-protector'],
      'qemu_args': ['-machine',
                    'q35,txt=on,txt-firmware=on,txt-vmx-compat=on',
                    '-cpu', 'qemu32,smx', '-m', '512M',
                    '-device', 'intel-iommu',
                    '-chardev',
                    'socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER',
                    '-tpmdev', 'emulator,id=tpm0,chardev=tpm0',
                    '-device', 'tpm-tis,tpmdev=tpm0'] + qemu_def_args,
      'wrapper': [run_swtpm_test],
    },
  }

  # Compile from the same source with a different define. A wrapper .c
  # that #includes the test is not reliably rebuilt by the TCG cross
  # compiler's depfile when the included file changes.
  tests += {'test-smx-getsec.c': {
    'exe_name': 'test-smx-getsec-smp',
    'cflags': cflags + ['-fno-pie', '-Wl,-no-pie',
                        '-fno-stack-protector', '-msse', '-DTEST_TXT_SMP=1'],
    'qemu_args': ['-machine', 'q35,txt=on',
                  '-cpu', 'qemu32,smx,sse', '-smp', '2',
                  '-device', 'intel-iommu',
                  '-device', 'iommu-testdev',
                  '-chardev',
                  'socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER',
                  '-tpmdev', 'emulator,id=tpm0,chardev=tpm0',
                  '-device', 'tpm-tis,tpmdev=tpm0'] + qemu_def_args,
    'wrapper': [run_swtpm_test],
  }}

  # Same source again, negotiating the MONITOR-based RLP wake instead
  # of GETSEC[WAKEUP] through os_sinit_data.capabilities.
  tests += {'test-smx-getsec.c': {
    'exe_name': 'test-smx-getsec-monitor',
    'cflags': cflags + ['-fno-pie', '-Wl,-no-pie',
                        '-fno-stack-protector', '-msse', '-DTEST_TXT_SMP=1',
                        '-DTEST_TXT_MONITOR_WAKE=1'],
    'qemu_args': ['-machine', 'q35,txt=on',
                  '-cpu', 'qemu32,smx,sse', '-smp', '2',
                  '-device', 'intel-iommu',
                  '-device', 'iommu-testdev',
                  '-chardev',
                  'socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER',
                  '-tpmdev', 'emulator,id=tpm0,chardev=tpm0',
                  '-device', 'tpm-tis,tpmdev=tpm0'] + qemu_def_args,
    'wrapper': [run_swtpm_test],
  }}

  # MLE Size not page aligned: the SDG's MLE Size is in bytes and the
  # final partial page is measured up to that size.
  tests += {'test-smx-getsec.c': {
    'exe_name': 'test-smx-getsec-mle-unaligned',
    'cflags': cflags + ['-fno-pie', '-Wl,-no-pie',
                        '-fno-stack-protector', '-msse',
                        '-DTEST_TXT_MLE_UNALIGNED=1'],
    'qemu_args': ['-machine', 'q35,txt=on',
                  '-cpu', 'qemu32,smx,sse',
                  '-device', 'intel-iommu',
                  '-device', 'iommu-testdev',
                  '-chardev',
                  'socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER',
                  '-tpmdev', 'emulator,id=tpm0,chardev=tpm0',
                  '-device', 'tpm-tis,tpmdev=tpm0'] + qemu_def_args,
    'wrapper': [run_swtpm_test],
  }}

  # Version-7 OS-to-SINIT data: verify bounded TPM2 Spec ID/log creation,
  # bank descriptions and PCR-unchanged rejection of a bad log pointer.
  tests += {'test-smx-getsec.c': {
    'exe_name': 'test-smx-getsec-tpm2-log',
    'cflags': cflags + ['-fno-pie', '-Wl,-no-pie',
                        '-fno-stack-protector', '-msse',
                        '-DTEST_TXT_TPM2_LOG=1'],
    'qemu_args': ['-machine', 'q35,txt=on',
                  '-cpu', 'qemu32,smx,sse',
                  '-device', 'intel-iommu',
                  '-device', 'iommu-testdev',
                  '-chardev',
                  'socket,id=tpm0,path=SWTPM_SOCKET_PLACEHOLDER',
                  '-tpmdev', 'emulator,id=tpm0,chardev=tpm0',
                  '-device', 'tpm-tis,tpmdev=tpm0'] + qemu_def_args,
    'wrapper': [run_swtpm_test],
  }}

  tcg_tests += {
    'i386-softmmu': {
      'cc': cc,
      'cc_dockerfile': cc_dockerfile,
      'cc_docker_host_arch': cc_docker_host_arch,
      'folder': 'i386/system',
      'gdb_arch': 'i386',
      'qemu': i386_system_qemu,
      'tests': tests,
    }
  }
endif
