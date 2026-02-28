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
pub struct MadtIoSapic {
    pub header: MadtEntryHeader,
    pub ioapic_id: u8,
    pub reserved: u8,
    pub gsi_base: u32,
    pub address: u64,
}
