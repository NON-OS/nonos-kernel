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

pub mod madt_flags {
    pub const PCAT_COMPAT: u32 = 1 << 0;
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Madt {
    pub header: SdtHeader,
    pub local_apic_address: u32,
    pub flags: u32,
}

impl Madt {
    pub fn has_legacy_pics(&self) -> bool {
        self.flags & madt_flags::PCAT_COMPAT != 0
    }

    pub fn entries_start(&self) -> usize {
        core::mem::size_of::<Self>()
    }

    pub fn entries_length(&self) -> u32 {
        self.header.length.saturating_sub(core::mem::size_of::<Self>() as u32)
    }

    pub fn local_apic_addr(&self) -> u64 {
        self.local_apic_address as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MadtEntryType {
    LocalApic = 0,
    IoApic = 1,
    InterruptSourceOverride = 2,
    NmiSource = 3,
    LocalApicNmi = 4,
    LocalApicAddressOverride = 5,
    IoSapic = 6,
    LocalSapic = 7,
    PlatformInterruptSources = 8,
    LocalX2Apic = 9,
    LocalX2ApicNmi = 10,
    GicCpuInterface = 11,
    GicDistributor = 12,
    GicMsiFrame = 13,
    GicRedistributor = 14,
    GicIts = 15,
    MultiprocessorWakeup = 16,
}

impl MadtEntryType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::LocalApic),
            1 => Some(Self::IoApic),
            2 => Some(Self::InterruptSourceOverride),
            3 => Some(Self::NmiSource),
            4 => Some(Self::LocalApicNmi),
            5 => Some(Self::LocalApicAddressOverride),
            6 => Some(Self::IoSapic),
            7 => Some(Self::LocalSapic),
            8 => Some(Self::PlatformInterruptSources),
            9 => Some(Self::LocalX2Apic),
            10 => Some(Self::LocalX2ApicNmi),
            11 => Some(Self::GicCpuInterface),
            12 => Some(Self::GicDistributor),
            13 => Some(Self::GicMsiFrame),
            14 => Some(Self::GicRedistributor),
            15 => Some(Self::GicIts),
            16 => Some(Self::MultiprocessorWakeup),
            _ => None,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtEntryHeader {
    pub entry_type: u8,
    pub length: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApic {
    pub header: MadtEntryHeader,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

impl MadtLocalApic {
    pub const ENABLED: u32 = 1 << 0;
    pub const ONLINE_CAPABLE: u32 = 1 << 1;

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }

    pub fn is_online_capable(&self) -> bool {
        self.flags & Self::ONLINE_CAPABLE != 0
    }

    pub fn is_usable(&self) -> bool {
        self.is_enabled() || self.is_online_capable()
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtIoApic {
    pub header: MadtEntryHeader,
    pub ioapic_id: u8,
    pub reserved: u8,
    pub address: u32,
    pub gsi_base: u32,
}

impl MadtIoApic {
    pub fn address(&self) -> u64 {
        self.address as u64
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtInterruptOverride {
    pub header: MadtEntryHeader,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

impl MadtInterruptOverride {
    pub const POLARITY_MASK: u16 = 0x03;
    pub const TRIGGER_MASK: u16 = 0x0C;
    pub const TRIGGER_SHIFT: u16 = 2;

    pub fn polarity(&self) -> u8 {
        (self.flags & Self::POLARITY_MASK) as u8
    }

    pub fn trigger_mode(&self) -> u8 {
        ((self.flags & Self::TRIGGER_MASK) >> Self::TRIGGER_SHIFT) as u8
    }

    pub fn is_active_low(&self) -> bool {
        self.polarity() == 3
    }

    pub fn is_level_triggered(&self) -> bool {
        self.trigger_mode() == 3
    }

    pub fn is_edge_triggered(&self) -> bool {
        self.trigger_mode() == 1
    }

    pub fn is_active_high(&self) -> bool {
        self.polarity() == 1
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtNmiSource {
    pub header: MadtEntryHeader,
    pub flags: u16,
    pub gsi: u32,
}

impl MadtNmiSource {
    pub fn polarity(&self) -> u8 {
        (self.flags & 0x03) as u8
    }

    pub fn trigger_mode(&self) -> u8 {
        ((self.flags >> 2) & 0x03) as u8
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApicNmi {
    pub header: MadtEntryHeader,
    pub processor_id: u8,
    pub flags: u16,
    pub lint: u8,
}

impl MadtLocalApicNmi {
    pub const ALL_PROCESSORS: u8 = 0xFF;

    pub fn applies_to_all(&self) -> bool {
        self.processor_id == Self::ALL_PROCESSORS
    }

    pub fn polarity(&self) -> u8 {
        (self.flags & 0x03) as u8
    }

    pub fn trigger_mode(&self) -> u8 {
        ((self.flags >> 2) & 0x03) as u8
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApicOverride {
    pub header: MadtEntryHeader,
    pub reserved: u16,
    pub address: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtIoSapic {
    pub header: MadtEntryHeader,
    pub ioapic_id: u8,
    pub reserved: u8,
    pub gsi_base: u32,
    pub address: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalX2Apic {
    pub header: MadtEntryHeader,
    pub reserved: u16,
    pub x2apic_id: u32,
    pub flags: u32,
    pub processor_uid: u32,
}

impl MadtLocalX2Apic {
    pub const ENABLED: u32 = 1 << 0;
    pub const ONLINE_CAPABLE: u32 = 1 << 1;

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }

    pub fn is_online_capable(&self) -> bool {
        self.flags & Self::ONLINE_CAPABLE != 0
    }

    pub fn is_usable(&self) -> bool {
        self.is_enabled() || self.is_online_capable()
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalX2ApicNmi {
    pub header: MadtEntryHeader,
    pub flags: u16,
    pub processor_uid: u32,
    pub lint: u8,
    pub reserved: [u8; 3],
}

impl MadtLocalX2ApicNmi {
    pub const ALL_PROCESSORS: u32 = 0xFFFFFFFF;

    pub fn applies_to_all(&self) -> bool {
        self.processor_uid == Self::ALL_PROCESSORS
    }

    pub fn polarity(&self) -> u8 {
        (self.flags & 0x03) as u8
    }

    pub fn trigger_mode(&self) -> u8 {
        ((self.flags >> 2) & 0x03) as u8
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtMultiprocessorWakeup {
    pub header: MadtEntryHeader,
    pub mailbox_version: u16,
    pub reserved: u32,
    pub mailbox_address: u64,
}

pub mod polarity {
    pub const CONFORMS: u8 = 0;
    pub const ACTIVE_HIGH: u8 = 1;
    pub const RESERVED: u8 = 2;
    pub const ACTIVE_LOW: u8 = 3;
}

pub mod trigger {
    pub const CONFORMS: u8 = 0;
    pub const EDGE: u8 = 1;
    pub const RESERVED: u8 = 2;
    pub const LEVEL: u8 = 3;
}
