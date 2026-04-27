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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratGiccAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain: u32,
    pub acpi_processor_uid: u32,
    pub flags: u32,
    pub clock_domain: u32,
}

impl SratGiccAffinity {
    pub const ENABLED: u32 = 1 << 0;
    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratGenericInitiatorAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub reserved1: u8,
    pub device_handle_type: u8,
    pub proximity_domain: u32,
    pub device_handle: [u8; 16],
    pub flags: u32,
    pub reserved2: u32,
}

impl SratGenericInitiatorAffinity {
    pub const ENABLED: u32 = 1 << 0;
    pub const HANDLE_TYPE_ACPI: u8 = 0;
    pub const HANDLE_TYPE_PCI: u8 = 1;

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }
    pub fn is_acpi_device(&self) -> bool {
        self.device_handle_type == Self::HANDLE_TYPE_ACPI
    }
    pub fn is_pci_device(&self) -> bool {
        self.device_handle_type == Self::HANDLE_TYPE_PCI
    }
}
