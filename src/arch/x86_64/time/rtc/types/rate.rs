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
pub enum PeriodicRate {
    Disabled = 0,
    Hz256 = 1,
    Hz128 = 2,
    Hz8192 = 3,
    Hz4096 = 4,
    Hz2048 = 5,
    Hz1024 = 6,
    Hz512 = 7,
    Hz256_2 = 8,
    Hz128_2 = 9,
    Hz64 = 10,
    Hz32 = 11,
    Hz16 = 12,
    Hz8 = 13,
    Hz4 = 14,
    Hz2 = 15,
}

impl PeriodicRate {
    pub const fn value(&self) -> u8 {
        *self as u8
    }

    pub const fn frequency_hz(&self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Hz256 | Self::Hz256_2 => 256,
            Self::Hz128 | Self::Hz128_2 => 128,
            Self::Hz8192 => 8192,
            Self::Hz4096 => 4096,
            Self::Hz2048 => 2048,
            Self::Hz1024 => 1024,
            Self::Hz512 => 512,
            Self::Hz64 => 64,
            Self::Hz32 => 32,
            Self::Hz16 => 16,
            Self::Hz8 => 8,
            Self::Hz4 => 4,
            Self::Hz2 => 2,
        }
    }

    pub const fn period_us(&self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Hz256 | Self::Hz256_2 => 3906,
            Self::Hz128 | Self::Hz128_2 => 7812,
            Self::Hz8192 => 122,
            Self::Hz4096 => 244,
            Self::Hz2048 => 488,
            Self::Hz1024 => 976,
            Self::Hz512 => 1953,
            Self::Hz64 => 15625,
            Self::Hz32 => 31250,
            Self::Hz16 => 62500,
            Self::Hz8 => 125000,
            Self::Hz4 => 250000,
            Self::Hz2 => 500000,
        }
    }
}
