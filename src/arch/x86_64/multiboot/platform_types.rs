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
        matches!(self, Self::QemuKvm | Self::Kvm | Self::HyperV | Self::Vmware | Self::Xen)
    }
    pub const fn supports_virtio(&self) -> bool {
        matches!(self, Self::QemuTcg | Self::QemuKvm | Self::Kvm)
    }
    pub const fn timer_frequency(&self) -> u32 {
        match self {
            Self::QemuTcg => 100,
            Self::QemuKvm | Self::Kvm | Self::HyperV | Self::BareMetal => 1000,
            Self::Vmware | Self::VirtualBox | Self::Xen => 100,
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
