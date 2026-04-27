// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::platform_signatures::HYPERVISOR_SIGNATURES;
use super::platform_types::Platform;

fn detect_qemu_fw_cfg() -> bool {
    const FW_CFG_CTL: u16 = 0x510;
    const FW_CFG_DATA: u16 = 0x511;
    const QEMU_SIGNATURE: u32 = 0x51454D55;
    unsafe {
        x86_64::instructions::port::Port::<u16>::new(FW_CFG_CTL).write(0x0000);
        let mut sig: u32 = 0;
        let mut data_port = x86_64::instructions::port::Port::<u8>::new(FW_CFG_DATA);
        for i in 0..4 {
            sig |= (data_port.read() as u32) << (i * 8);
        }
        sig == QEMU_SIGNATURE
    }
}

pub fn detect_platform() -> Platform {
    let cpuid1 = core::arch::x86_64::__cpuid(1);
    let hypervisor_present = (cpuid1.ecx >> 31) & 1 != 0;
    if !hypervisor_present {
        return Platform::BareMetal;
    }
    let cpuid_hv = core::arch::x86_64::__cpuid(0x40000000);
    if cpuid_hv.eax < 0x40000000 {
        return Platform::UnknownVm;
    }
    for sig in HYPERVISOR_SIGNATURES {
        if cpuid_hv.ebx == sig.ebx && cpuid_hv.ecx == sig.ecx && cpuid_hv.edx == sig.edx {
            if sig.platform == Platform::Kvm {
                return if detect_qemu_fw_cfg() { Platform::QemuKvm } else { Platform::Kvm };
            }
            return sig.platform;
        }
    }
    let sig_bytes = [
        (cpuid_hv.ebx & 0xFF) as u8,
        ((cpuid_hv.ebx >> 8) & 0xFF) as u8,
        ((cpuid_hv.ebx >> 16) & 0xFF) as u8,
        ((cpuid_hv.ebx >> 24) & 0xFF) as u8,
        (cpuid_hv.ecx & 0xFF) as u8,
        ((cpuid_hv.ecx >> 8) & 0xFF) as u8,
        ((cpuid_hv.ecx >> 16) & 0xFF) as u8,
        ((cpuid_hv.ecx >> 24) & 0xFF) as u8,
        (cpuid_hv.edx & 0xFF) as u8,
        ((cpuid_hv.edx >> 8) & 0xFF) as u8,
        ((cpuid_hv.edx >> 16) & 0xFF) as u8,
        ((cpuid_hv.edx >> 24) & 0xFF) as u8,
    ];
    if &sig_bytes[0..4] == b"VBox" {
        return Platform::VirtualBox;
    }
    if sig_bytes.contains(&b'p') && sig_bytes.contains(&b'r') && sig_bytes.contains(&b'l') {
        return Platform::Parallels;
    }
    if detect_qemu_fw_cfg() {
        return Platform::QemuTcg;
    }
    Platform::UnknownVm
}
