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
pub enum MadtEntryType {
    LocalApic = 0,
    IoApic = 1,
    InterruptSourceOverride = 2,
    NmiSource = 3,
    LocalApicNmi = 4,
    LocalApicAddressOverride = 5,
    IoSapic = 6,
    LocalSapic = 7,
    PlatformInterruptSources = 8,
    LocalX2Apic = 9,
    LocalX2ApicNmi = 10,
    GicCpuInterface = 11,
    GicDistributor = 12,
    GicMsiFrame = 13,
    GicRedistributor = 14,
    GicIts = 15,
    MultiprocessorWakeup = 16,
}

impl MadtEntryType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::LocalApic),
            1 => Some(Self::IoApic),
            2 => Some(Self::InterruptSourceOverride),
            3 => Some(Self::NmiSource),
            4 => Some(Self::LocalApicNmi),
            5 => Some(Self::LocalApicAddressOverride),
            6 => Some(Self::IoSapic),
            7 => Some(Self::LocalSapic),
            8 => Some(Self::PlatformInterruptSources),
            9 => Some(Self::LocalX2Apic),
            10 => Some(Self::LocalX2ApicNmi),
            11 => Some(Self::GicCpuInterface),
            12 => Some(Self::GicDistributor),
            13 => Some(Self::GicMsiFrame),
            14 => Some(Self::GicRedistributor),
            15 => Some(Self::GicIts),
            16 => Some(Self::MultiprocessorWakeup),
            _ => None,
        }
    }
}

pub mod polarity {
    pub const CONFORMS: u8 = 0;
    pub const ACTIVE_HIGH: u8 = 1;
    pub const RESERVED: u8 = 2;
    pub const ACTIVE_LOW: u8 = 3;
}

pub mod trigger {
    pub const CONFORMS: u8 = 0;
    pub const EDGE: u8 = 1;
    pub const RESERVED: u8 = 2;
    pub const LEVEL: u8 = 3;
}
