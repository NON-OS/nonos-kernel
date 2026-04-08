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
#[repr(u8)]
pub enum SleepState {
    S0 = 0,
    S1 = 1,
    S2 = 2,
    S3 = 3,
    S4 = 4,
    S5 = 5,
}

impl SleepState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::S0 => "Working (S0)",
            Self::S1 => "Power On Suspend (S1)",
            Self::S2 => "CPU Off (S2)",
            Self::S3 => "Suspend to RAM (S3)",
            Self::S4 => "Suspend to Disk (S4)",
            Self::S5 => "Soft Off (S5)",
        }
    }
}

pub mod pm1_bits {
    pub const SLP_TYP_SHIFT: u16 = 10;
    pub const SLP_EN: u16 = 1 << 13;
}
