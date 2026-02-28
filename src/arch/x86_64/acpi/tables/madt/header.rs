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

use crate::arch::x86_64::acpi::tables::sdt::SdtHeader;

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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtEntryHeader {
    pub entry_type: u8,
    pub length: u8,
}
