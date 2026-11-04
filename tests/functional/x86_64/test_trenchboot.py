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
    Boots a meta-trenchboot image under Dasharo's coreboot+UEFI build with
    the AMD dynamic launch devices, picks the "Boot Xen with TrenchBoot
    (EFI)" GRUB entry and checks that the launch reached dom0 with PCR 17
    extended. A second case boots the same image through the emulated PSP
    DRTM service: the image ships the classic and the AMDSL SKL and its
    GRUB picks by probing for the PSP.
    """

    ASSET_FIRMWARE = Asset(
        ('https://github.com/Dasharo/coreboot/releases/download/'
         'qemu_q35_v0.2.1/qemu_q35_all_menus.rom'),
        'c6be232bc9884888b4b9dbe0fa85aa2a48042bdda456e3608c3f1d93e519d95d')

    # A build of the meta-trenchboot fork's amd-drtm branch. The upstream
    # releases lack the AMDSL SKL and the PSP drivers, and their GRUB
    # enters the kernel wrongly on the EFI Linux launch.
    ASSET_IMAGE = Asset(
        ('https://github.com/iwanicki92/meta-trenchboot/releases/download/'
         'amd-drtm-test-image/tb-full-image-genericx86-64.rootfs.wic.gz'),
        '1440fa6548b419ba99dde5de4b262f2e3e3ebb0f6addbea62f0e68b96bca7a13')

    # GRUB prints this under the finished menu and boots the first entry
    # five seconds later unless a key arrives.
    GRUB_MENU_READY = 'The highlighted entry will be executed automatically'
    GRUB_ENTRY = 'Boot Xen with TrenchBoot (EFI)'
    # An entry as GRUB draws it over serial: the cursor put at the third
    # column of the entry's row, the highlight marker or a space, the
    # title, then the padding to the box's edge. The firmware's boot
    # manager prints a "Boot ..." line of its own before GRUB, without
    # the cursor move.
    GRUB_TITLE = re.compile(rb'\x1b\[\d+;0?3H[ *](Boot [A-Za-z0-9 ()]+?)\s{2,}')
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

    def boot_xen_efi(self, image, *devices):
        '''
        Boot the image, pick the Xen EFI launch entry and wait for the
        login prompt, with any extra device arguments on the machine.
        '''
        self.set_machine('q35')
        self.require_accelerator('tcg')
        self.require_device('amd-drtm-platform')
        self.require_device('amd-iommu')

        firmware = self.scratch_file('firmware.rom')
        shutil.copy(self.ASSET_FIRMWARE.fetch(), firmware)
        tpm_sock = self.start_swtpm()

        self.vm.set_console()
        # Strict, so a broken launch rule stops the VM instead of leaving
        # a line in the log, and paused rather than exited so the log
        # names the rule under a stopped VM. The rule is logged as a
        # guest error.
        self.vm.add_args('-accel', 'tcg', '-smp', '2', '-m', '4G',
                         '-machine', 'amd-drtm=on',
                         '-global', 'amd-drtm-platform.strict=on',
                         '-action', 'panic=pause',
                         '-d', 'guest_errors',
                         '-cpu', 'EPYC-Genoa',
                         '-chardev', f'socket,id=chrtpm,path={tpm_sock}',
                         '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm',
                         '-device', 'tpm-tis,tpmdev=tpm0',
                         '-drive', f'if=pflash,format=raw,file={firmware}',
                         '-drive', f'file={image},format=raw,if=none,id=hd,'
                                   'snapshot=on',
                         '-device', 'ide-hd,drive=hd', '-nic', 'none')
        for device in devices:
            self.vm.add_args('-device', device)
        self.vm.launch()

        # The entry's place comes from the menu GRUB draws, so an image
        # with more entries moves nothing here.
        menu = wait_for_console_pattern(self, self.GRUB_MENU_READY)
        titles = []
        for title in self.GRUB_TITLE.findall(menu):
            if title not in titles:
                titles.append(title)
        self.assertIn(self.GRUB_ENTRY.encode(), titles, f'GRUB menu {titles}')
        index = titles.index(self.GRUB_ENTRY.encode())
        self.log.info('GRUB menu %s, entry %d', titles, index)
        # One key at a time, each answered by GRUB highlighting the next
        # entry, so the selection is known before Enter.
        for i in range(index):
            self.vm.console_socket.sendall(self.KEY_DOWN)
            wait_for_console_pattern(self, '*' + titles[i + 1].decode())
        self.vm.console_socket.sendall(b'\r')
        wait_for_console_pattern(self, 'Enabling slaunch')
        wait_for_console_pattern(self, '(XEN) Xen version', 'Panic on CPU')

    def assert_launched(self):
        '''
        The platform's record of a launch that reached dom0 with the SLB
        released, then PCR 17 extended and 16 untouched, read from dom0.
        '''
        info = self.vm.cmd('query-amd-drtm')
        self.assertTrue(info['launched'])
        self.assertEqual(info['hash'], 'ok')
        self.assertGreater(info['slb-length'], 0)
        self.assertFalse(info['sl-dev'])
        self.assertEqual(info['dma-blocks'], [])

        exec_command_and_wait_for_pattern(self, 'root', self.PROMPT)
        self.assertEqual(self.read_pcr(16), self.PCR_ZERO)
        self.assertNotEqual(self.read_pcr(17), self.PCR_ZERO)
        return info

    @skipIfMissingCommands('swtpm')
    @skipBigDataTest()
    def test_x86_64_trenchboot_xen_efi(self):
        image = self.uncompress(self.ASSET_IMAGE, target='tb-full-image.wic')
        self.boot_xen_efi(image)
        wait_for_console_pattern(self, 'tb login:', 'Panic on CPU')
        self.assert_launched()

    @skipIfMissingCommands('swtpm')
    @skipBigDataTest()
    def test_x86_64_trenchboot_xen_efi_psp(self):
        '''
        The PSP path: GRUB sets a TMR up and SKL has the service launch,
        the signature verified, then Xen releases the TMR once its IOMMU
        is up. PCR 18 carries the key token, so it is extended too.
        '''
        self.require_device('amd-psp')
        image = self.uncompress(self.ASSET_IMAGE, target='tb-full-image.wic')
        self.boot_xen_efi(image, 'amd-psp,drtm-service=on')
        wait_for_console_pattern(self, 'SLAUNCH: PSP-assisted launch',
                                 'Panic on CPU')
        wait_for_console_pattern(self, 'SLAUNCH: released TMR 0',
                                 'Panic on CPU')
        wait_for_console_pattern(self, 'tb login:', 'Panic on CPU')

        info = self.assert_launched()
        self.assertEqual(info['psp'], {'kicked': True, 'launch': 'ok',
                                       'signature': 'verified',
                                       'command': 3, 'status': 0})
        self.assertNotEqual(self.read_pcr(18), self.PCR_ZERO)


if __name__ == '__main__':
    QemuSystemTest.main()
