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

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmiSource {
    Software,
    Timer,
    IoTrap,
    Thermal,
    PowerButton,
    Tco,
    UsbLegacy,
    Gpio,
    Smbus,
    GlobalEnable,
    Unknown,
}

impl SmiSource {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Software => "Software",
            Self::Timer => "Timer",
            Self::IoTrap => "I/O Trap",
            Self::Thermal => "Thermal",
            Self::PowerButton => "Power Button",
            Self::Tco => "TCO Timer",
            Self::UsbLegacy => "USB Legacy",
            Self::Gpio => "GPIO",
            Self::Smbus => "SMBus",
            Self::GlobalEnable => "Global Enable",
            Self::Unknown => "Unknown",
        }
    }

    pub fn from_smi_sts(sts: u32) -> Self {
        if sts & (1 << 0) != 0 { Self::Software }
        else if sts & (1 << 4) != 0 { Self::Timer }
        else if sts & (1 << 5) != 0 { Self::IoTrap }
        else if sts & (1 << 6) != 0 { Self::Thermal }
        else if sts & (1 << 16) != 0 { Self::PowerButton }
        else if sts & (1 << 13) != 0 { Self::Tco }
        else if sts & (1 << 3) != 0 { Self::UsbLegacy }
        else if sts & (1 << 18) != 0 { Self::Gpio }
        else { Self::Unknown }
    }
}

#[derive(Debug, Clone)]
pub struct SmiInfo {
    pub smi_count: u64,
    pub last_source: SmiSource,
    pub smi_en: u32,
    pub smi_sts: u32,
    pub active_handlers: Vec<u64>,
}
