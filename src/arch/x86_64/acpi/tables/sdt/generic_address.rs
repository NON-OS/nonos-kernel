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

use super::AddressSpace;

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
