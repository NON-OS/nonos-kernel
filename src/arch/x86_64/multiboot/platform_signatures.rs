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

use super::platform_types::Platform;

pub struct HypervisorSignature {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub platform: Platform,
}

pub const HYPERVISOR_SIGNATURES: &[HypervisorSignature] = &[
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
