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
