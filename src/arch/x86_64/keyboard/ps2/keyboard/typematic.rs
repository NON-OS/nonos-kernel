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
pub enum ScanCodeSet {
    Set1 = 1,
    Set2 = 2,
    Set3 = 3,
}

#[derive(Debug, Clone, Copy)]
pub struct TypematicConfig {
    pub delay_ms: u16,
    pub rate_hz: u8,
}

impl TypematicConfig {
    pub const fn default_config() -> Self {
        Self {
            delay_ms: 500,
            rate_hz: 10,
        }
    }

    pub fn to_byte(self) -> u8 {
        let delay = match self.delay_ms {
            0..=312 => 0,
            313..=562 => 1,
            563..=812 => 2,
            _ => 3,
        };

        let rate = match self.rate_hz {
            0..=2 => 0x1F,
            3..=4 => 0x14,
            5..=6 => 0x10,
            7..=9 => 0x0C,
            10..=12 => 0x0A,
            13..=16 => 0x08,
            17..=20 => 0x06,
            21..=24 => 0x04,
            25..=27 => 0x02,
            28..=30 => 0x01,
            _ => 0x00,
        };

        (delay << 5) | rate
    }
}

impl Default for TypematicConfig {
    fn default() -> Self {
        Self::default_config()
    }
}
