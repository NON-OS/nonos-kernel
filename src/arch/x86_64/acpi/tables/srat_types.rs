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
    pub fn entries_offset(&self) -> usize { mem::size_of::<Self>() }
    pub fn entries_length(&self) -> u32 { self.header.length.saturating_sub(mem::size_of::<Self>() as u32) }
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
            0 => Some(Self::ProcessorAffinity), 1 => Some(Self::MemoryAffinity),
            2 => Some(Self::ProcessorX2ApicAffinity), 3 => Some(Self::GiccAffinity),
            4 => Some(Self::GicItsAffinity), 5 => Some(Self::GenericInitiatorAffinity),
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
