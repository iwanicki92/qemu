tests = []

minilib_dir = meson.current_source_dir() / '..' / '..' / 'minilib'
minilib_printf = files(minilib_dir / 'printf.c')[0]
link_script = files('kernel.ld')[0]
boot = files('boot.S')[0]
# -fno-stack-protector: these are freestanding images with no libc, so a
# toolchain configured with --enable-default-ssp would emit calls to an
# undefined __stack_chk_fail.
cflags = ['-nostdlib',
          '-ffreestanding',
          '-fno-stack-protector',
          '-Wa,--noexecstack',
          '-I', minilib_dir, minilib_printf, boot,
          '-Wl,-T', link_script,
          '-Wl,-melf_x86_64',
          '-Wl,--no-warn-rwx-segments',
          '-Wl,--build-id=none',
          '-lgcc']
qemu_def_args = ['-display', 'none',
                 '-device', 'isa-debugcon,chardev=stdio',
                 '-chardev', 'stdio,id=stdio',
                 '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x4',
                 '-kernel']

# Multi arch tests
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

tests += {
  'patch-target.c': {
    'cflags': cflags,
    'qemu_args': qemu_def_args,
    'plugin_test': {
      'plugin': 'patch',
      'args': ['target=ffc0', 'patch=9090', 'use_hwaddr=true'],
    },
    'wrapper': [prog_check_plugin_output,
                find_program('./validate-patch.py')]
  }
}

tests += {
  # A launchable AMD machine: the skinit bit, the launch record, an AP to
  # park
  'skinit.c': {
    'cflags': cflags,
    'qemu_args': ['-machine', 'q35', '-cpu', 'max,+skinit', '-smp', '2',
                  '-device', 'amd-drtm-platform'] + qemu_def_args,
  },
  # The MSR maps MMCONFIG on the q35 host only
  'mmio-conf.c': {
    'cflags': cflags,
    'qemu_args': ['-machine', 'q35'] + qemu_def_args,
  },
  # SVM for the MSR to exist, and the value firmware that disables SVM leaves
  'vm-cr-preset.c': {
    'cflags': cflags,
    'qemu_args': ['-cpu', 'max,vm-cr=0x18'] + qemu_def_args,
  },
  # max is an AMD CPU under TCG, and no AMD CPU has SMX
  'cpuid-smx.c': {
    'cflags': cflags,
    'qemu_args': ['-cpu', 'max'] + qemu_def_args,
  },
}

# The same source where SMX belongs: an Intel max, and +smx asked for
tests += {'cpuid-smx.c': {
  'exe_name': 'cpuid-smx-intel',
  'cflags': cflags + ['-DEXPECT_SMX=1'],
  'qemu_args': ['-cpu', 'max,vendor=GenuineIntel'] + qemu_def_args,
}}
tests += {'cpuid-smx.c': {
  'exe_name': 'cpuid-smx-requested',
  'cflags': cflags + ['-DEXPECT_SMX=1'],
  'qemu_args': ['-cpu', 'max,+smx'] + qemu_def_args,
}}

if 'qemu-system-x86_64' in emulators
  tcg_tests += {
    'x86_64-softmmu': {
      'cc': cc,
      'cc_dockerfile': cc_dockerfile,
      'cc_docker_host_arch': cc_docker_host_arch,
      'folder': 'x86_64/system',
      'gdb_arch': 'x86_64',
      'qemu': emulators['qemu-system-x86_64'],
      'tests': tests,
    }
  }
endif
