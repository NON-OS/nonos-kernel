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

use super::sdt::SdtHeader;
use core::mem;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Srat {
    pub header: SdtHeader,
    pub table_revision: u32,
    pub reserved: u64,
}

impl Srat {
    pub fn entries_offset(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub fn entries_length(&self) -> u32 {
        self.header.length.saturating_sub(mem::size_of::<Self>() as u32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SratEntryType {
    ProcessorAffinity = 0,
    MemoryAffinity = 1,
    ProcessorX2ApicAffinity = 2,
    GiccAffinity = 3,
    GicItsAffinity = 4,
    GenericInitiatorAffinity = 5,
}

impl SratEntryType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ProcessorAffinity),
            1 => Some(Self::MemoryAffinity),
            2 => Some(Self::ProcessorX2ApicAffinity),
            3 => Some(Self::GiccAffinity),
            4 => Some(Self::GicItsAffinity),
            5 => Some(Self::GenericInitiatorAffinity),
            _ => None,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratEntryHeader {
    pub entry_type: u8,
    pub length: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratProcessorAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain_low: u8,
    pub apic_id: u8,
    pub flags: u32,
    pub sapic_eid: u8,
    pub proximity_domain_high: [u8; 3],
    pub clock_domain: u32,
}

impl SratProcessorAffinity {
    pub const ENABLED: u32 = 1 << 0;

    pub fn proximity_domain(&self) -> u32 {
        self.proximity_domain_low as u32
            | ((self.proximity_domain_high[0] as u32) << 8)
            | ((self.proximity_domain_high[1] as u32) << 16)
            | ((self.proximity_domain_high[2] as u32) << 24)
    }

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratMemoryAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain: u32,
    pub reserved1: u16,
    pub base_address: u64,
    pub length_bytes: u64,
    pub reserved2: u32,
    pub flags: u32,
    pub reserved3: u64,
}

impl SratMemoryAffinity {
    pub const ENABLED: u32 = 1 << 0;
    pub const HOT_PLUGGABLE: u32 = 1 << 1;
    pub const NON_VOLATILE: u32 = 1 << 2;

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }

    pub fn is_hot_pluggable(&self) -> bool {
        self.flags & Self::HOT_PLUGGABLE != 0
    }

    pub fn is_non_volatile(&self) -> bool {
        self.flags & Self::NON_VOLATILE != 0
    }

    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.length_bytes)
    }

    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.base_address && addr < self.end_address()
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratX2ApicAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub reserved1: u16,
    pub proximity_domain: u32,
    pub x2apic_id: u32,
    pub flags: u32,
    pub clock_domain: u32,
    pub reserved2: u32,
}

impl SratX2ApicAffinity {
    pub const ENABLED: u32 = 1 << 0;

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }
}

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
