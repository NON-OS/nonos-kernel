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
pub enum AddressSpace {
    SystemMemory = 0x00,
    SystemIo = 0x01,
    PciConfig = 0x02,
    EmbeddedController = 0x03,
    SmBus = 0x04,
    Cmos = 0x05,
    PciBarTarget = 0x06,
    Ipmi = 0x07,
    Gpio = 0x08,
    GenericSerialBus = 0x09,
    Pcc = 0x0A,
    FunctionalFixedHw = 0x7F,
}

impl AddressSpace {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::SystemMemory),
            0x01 => Some(Self::SystemIo),
            0x02 => Some(Self::PciConfig),
            0x03 => Some(Self::EmbeddedController),
            0x04 => Some(Self::SmBus),
            0x05 => Some(Self::Cmos),
            0x06 => Some(Self::PciBarTarget),
            0x07 => Some(Self::Ipmi),
            0x08 => Some(Self::Gpio),
            0x09 => Some(Self::GenericSerialBus),
            0x0A => Some(Self::Pcc),
            0x7F => Some(Self::FunctionalFixedHw),
            _ => None,
        }
    }
}
