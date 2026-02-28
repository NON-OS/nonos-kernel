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

use super::header::MadtEntryHeader;

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
