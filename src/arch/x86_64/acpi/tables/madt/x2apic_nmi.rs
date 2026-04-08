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
