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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LbaFormat {
    pub metadata_size: u16,
    pub lba_data_size_shift: u8,
    pub relative_performance: u8,
}

impl LbaFormat {
    pub fn from_dword(dw: u32) -> Self {
        Self {
            metadata_size: (dw & 0xFFFF) as u16,
            lba_data_size_shift: ((dw >> 16) & 0xFF) as u8,
            relative_performance: ((dw >> 24) & 0x3) as u8,
        }
    }

    pub const fn lba_size(&self) -> u32 {
        if self.lba_data_size_shift == 0 {
            0
        } else {
            1 << self.lba_data_size_shift
        }
    }

    pub const fn performance_string(&self) -> &'static str {
        match self.relative_performance {
            0 => "Best",
            1 => "Better",
            2 => "Good",
            3 => "Degraded",
            _ => "Unknown",
        }
    }
}
