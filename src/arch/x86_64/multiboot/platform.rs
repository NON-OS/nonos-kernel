// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    QemuTcg,
    QemuKvm,
    Kvm,
    Vmware,
    HyperV,
    Xen,
    VirtualBox,
    Bhyve,
    Acrn,
    Parallels,
    AppleHv,
    UnknownVm,
    BareMetal,
}

impl Platform {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::QemuTcg => "QEMU (TCG)",
            Self::QemuKvm => "QEMU (KVM)",
            Self::Kvm => "Linux KVM",
            Self::Vmware => "VMware",
            Self::HyperV => "Microsoft Hyper-V",
            Self::Xen => "Xen Hypervisor",
            Self::VirtualBox => "Oracle VirtualBox",
            Self::Bhyve => "FreeBSD bhyve",
            Self::Acrn => "ACRN Hypervisor",
            Self::Parallels => "Parallels Desktop",
            Self::AppleHv => "Apple Hypervisor",
            Self::UnknownVm => "Unknown Hypervisor",
            Self::BareMetal => "Bare Metal",
        }
    }

    pub const fn is_virtual(&self) -> bool {
        !matches!(self, Self::BareMetal)
    }

    pub const fn is_qemu(&self) -> bool {
        matches!(self, Self::QemuTcg | Self::QemuKvm)
    }

    pub const fn has_hw_virtualization(&self) -> bool {
        matches!(
            self,
            Self::QemuKvm | Self::Kvm | Self::HyperV | Self::Vmware | Self::Xen
        )
    }

    pub const fn supports_virtio(&self) -> bool {
        matches!(self, Self::QemuTcg | Self::QemuKvm | Self::Kvm)
    }

    pub const fn timer_frequency(&self) -> u32 {
        match self {
            Self::QemuTcg => 100,
            Self::QemuKvm | Self::Kvm => 1000,
            Self::Vmware | Self::VirtualBox => 100,
            Self::HyperV => 1000,
            Self::Xen => 100,
            Self::BareMetal => 1000,
            _ => 100,
        }
    }

    pub const fn console_type(&self) -> ConsoleType {
        match self {
            Self::QemuTcg | Self::QemuKvm => ConsoleType::Serial,
            Self::Vmware | Self::VirtualBox => ConsoleType::Vga,
            Self::HyperV => ConsoleType::EfiConsole,
            _ => ConsoleType::Serial,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleType {
    Vga,
    Serial,
    Framebuffer,
    EfiConsole,
}

struct HypervisorSignature {
    ebx: u32,
    ecx: u32,
    edx: u32,
    platform: Platform,
}

const HYPERVISOR_SIGNATURES: &[HypervisorSignature] = &[
    HypervisorSignature {
        ebx: 0x4B4D564B,
        ecx: 0x564B4D56,
        edx: 0x0000004D,
        platform: Platform::Kvm,
    },
    HypervisorSignature {
        ebx: 0x7263694D,
        ecx: 0x666F736F,
        edx: 0x76482074,
        platform: Platform::HyperV,
    },
    HypervisorSignature {
        ebx: 0x61774D56,
        ecx: 0x4D566572,
        edx: 0x65726177,
        platform: Platform::Vmware,
    },
    HypervisorSignature {
        ebx: 0x566E6558,
        ecx: 0x65584D4D,
        edx: 0x4D4D566E,
        platform: Platform::Xen,
    },
    HypervisorSignature {
        ebx: 0x54474354,
        ecx: 0x54474354,
        edx: 0x47544347,
        platform: Platform::QemuTcg,
    },
    HypervisorSignature {
        ebx: 0x786F4256,
        ecx: 0x786F4256,
        edx: 0x786F4256,
        platform: Platform::VirtualBox,
    },
    HypervisorSignature {
        ebx: 0x76796862,
        ecx: 0x68622065,
        edx: 0x20657679,
        platform: Platform::Bhyve,
    },
    HypervisorSignature {
        ebx: 0x4E524341,
        ecx: 0x4E524341,
        edx: 0x4E524341,
        platform: Platform::Acrn,
    },
];

fn detect_qemu_fw_cfg() -> bool {
    const FW_CFG_CTL: u16 = 0x510;
    const FW_CFG_DATA: u16 = 0x511;
    const FW_CFG_SIGNATURE: u16 = 0x0000;
    const QEMU_SIGNATURE: u32 = 0x51454D55;

    // SAFETY: Reading from QEMU fw_cfg ports to detect QEMU presence
    unsafe {
        x86_64::instructions::port::Port::<u16>::new(FW_CFG_CTL).write(FW_CFG_SIGNATURE);

        let mut sig: u32 = 0;
        let mut data_port = x86_64::instructions::port::Port::<u8>::new(FW_CFG_DATA);
        for i in 0..4 {
            let byte = data_port.read();
            sig |= (byte as u32) << (i * 8);
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
                if detect_qemu_fw_cfg() {
                    return Platform::QemuKvm;
                }
                return Platform::Kvm;
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
