#!/usr/bin/env python3
#
# Functional test that boots TrenchBoot's Xen through AMD SKINIT
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import shutil
import subprocess
import time

from qemu_test import QemuSystemTest, Asset
from qemu_test import exec_command_and_wait_for_pattern
from qemu_test import wait_for_console_pattern
from qemu_test import skipBigDataTest, skipIfMissingCommands


class TrenchBootXen(QemuSystemTest):
    """
    Boots the meta-trenchboot release image under Dasharo's coreboot+UEFI
    build with the AMD dynamic launch devices, picks the "Boot Xen with
    TrenchBoot (EFI)" GRUB entry and checks that the launch reached dom0
    with PCR 17 extended.
    """

    ASSET_FIRMWARE = Asset(
        ('https://github.com/Dasharo/coreboot/releases/download/'
         'qemu_q35_v0.2.1/qemu_q35_all_menus.rom'),
        'c6be232bc9884888b4b9dbe0fa85aa2a48042bdda456e3608c3f1d93e519d95d')

    ASSET_IMAGE = Asset(
        ('https://github.com/zarhus/meta-trenchboot/releases/download/'
         'v0.5.2/tb-full-image-genericx86-64.rootfs.wic.gz'),
        '702276d64f8aa9633a6aef1c88767716311d733a1dcbede2ed9e4d7a1cb380ca')

    # GRUB prints this under the finished menu and boots the first entry
    # five seconds later unless a key arrives.
    GRUB_MENU_READY = 'The highlighted entry will be executed automatically'
    GRUB_ENTRY = 'Boot Xen with TrenchBoot (EFI)'
    GRUB_ENTRY_INDEX = 5
    KEY_DOWN = b'\x1b[B'

    PROMPT = 'root@tb:~#'
    PCR_ZERO = '0' * 64

    def start_swtpm(self):
        '''
        Start a TPM 2.0 emulator under the socket directory, which lives
        in /tmp as swtpm may be confined to it, and return its socket.
        '''
        sockdir = self.socket_dir().name
        state = os.path.join(sockdir, 'tpmstate')
        os.mkdir(state)
        sock = os.path.join(sockdir, 'swtpm.sock')
        swtpm = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--terminate',
                                  '--tpmstate', f'dir={state}',
                                  '--ctrl', f'type=unixio,path={sock}'],
                                 stdout=subprocess.DEVNULL)
        self.addCleanup(swtpm.wait, 10)
        self.addCleanup(swtpm.terminate)
        for _ in range(50):
            if os.path.exists(sock):
                return sock
            time.sleep(0.1)
        self.fail('swtpm did not create its control socket')

    def read_pcr(self, index):
        out = exec_command_and_wait_for_pattern(
            self, f'tpm2_pcrread sha256:{index}', self.PROMPT)
        match = re.search(rb'%d\s*: 0x([0-9A-F]{64})' % index, out)
        self.assertIsNotNone(match, f'no PCR {index} in {out!r}')
        return match.group(1).decode()

    @skipIfMissingCommands('swtpm')
    @skipBigDataTest()
    def test_x86_64_trenchboot_xen_efi(self):
        self.set_machine('q35')
        self.require_accelerator('tcg')
        self.require_device('amd-drtm-platform')

        firmware = self.scratch_file('firmware.rom')
        shutil.copy(self.ASSET_FIRMWARE.fetch(), firmware)
        image = self.uncompress(self.ASSET_IMAGE, target='tb-full-image.wic')
        tpm_sock = self.start_swtpm()

        self.vm.set_console()
        self.vm.add_args('-accel', 'tcg', '-smp', '2', '-m', '4G',
                         '-cpu', 'EPYC-Genoa,+skinit,mmio-conf-base=0xb0000001',
                         '-global', 'q35-pcihost.mch-multifunction=on',
                         '-device', 'amd-drtm-platform',
                         '-device', 'amd-nb',
                         '-device', 'AMDVI-PCI,id=iommu0,addr=0.2',
                         '-device', 'amd-iommu,pci-id=iommu0,'
                                    'firmware-enabled=on',
                         '-chardev', f'socket,id=chrtpm,path={tpm_sock}',
                         '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm',
                         '-device', 'tpm-tis,tpmdev=tpm0',
                         '-drive', f'if=pflash,format=raw,file={firmware}',
                         '-drive', f'file={image},format=raw,if=none,id=hd,'
                                   'snapshot=on',
                         '-device', 'ide-hd,drive=hd', '-nic', 'none')
        self.vm.launch()

        wait_for_console_pattern(self, self.GRUB_ENTRY)
        wait_for_console_pattern(self, self.GRUB_MENU_READY)
        self.vm.console_socket.sendall(
            self.KEY_DOWN * self.GRUB_ENTRY_INDEX + b'\r')
        wait_for_console_pattern(self, 'Enabling slaunch')
        wait_for_console_pattern(self, '(XEN) Xen version', 'Panic on CPU')
        wait_for_console_pattern(self, 'tb login:', 'Panic on CPU')

        info = self.vm.cmd('query-amd-drtm')
        self.assertTrue(info['launched'])
        self.assertEqual(info['hash'], 'ok')
        self.assertGreater(info['slb-length'], 0)
        self.assertFalse(info['sl-dev'])
        self.assertEqual(info['dma-blocks'], [])

        exec_command_and_wait_for_pattern(self, 'root', self.PROMPT)
        self.assertEqual(self.read_pcr(16), self.PCR_ZERO)
        self.assertNotEqual(self.read_pcr(17), self.PCR_ZERO)


if __name__ == '__main__':
    QemuSystemTest.main()
