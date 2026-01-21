// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::mem;
use core::slice;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SdtHeader {
    pub signature: u32,
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl SdtHeader {
    pub fn signature_bytes(&self) -> [u8; 4] {
        self.signature.to_le_bytes()
    }

    pub fn validate_checksum(&self, table_ptr: *const u8) -> bool {
        if self.length < mem::size_of::<Self>() as u32 {
            return false;
        }
        // SAFETY: Caller ensures table_ptr is valid for self.length bytes
        unsafe {
            let bytes = slice::from_raw_parts(table_ptr, self.length as usize);
            bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
        }
    }

    pub fn data_length(&self) -> u32 {
        self.length.saturating_sub(mem::size_of::<Self>() as u32)
    }
}

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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GenericAddress {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

impl GenericAddress {
    pub const fn empty() -> Self {
        Self { address_space: 0, bit_width: 0, bit_offset: 0, access_size: 0, address: 0 }
    }

    pub fn is_valid(&self) -> bool {
        self.address != 0
    }

    pub fn space(&self) -> Option<AddressSpace> {
        AddressSpace::from_u8(self.address_space)
    }

    pub fn is_memory(&self) -> bool {
        self.address_space == AddressSpace::SystemMemory as u8
    }

    pub fn is_io(&self) -> bool {
        self.address_space == AddressSpace::SystemIo as u8
    }

    pub fn access_bytes(&self) -> usize {
        match self.access_size {
            1 => 1,
            2 => 2,
            3 => 4,
            4 => 8,
            _ => (self.bit_width / 8) as usize,
        }
    }
}

impl Default for GenericAddress {
    fn default() -> Self {
        Self::empty()
    }
}
