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

use crate::drivers::pci::constants::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiInfo {
    pub offset: u8,
    pub is_64bit: bool,
    pub per_vector_mask: bool,
    pub multi_message_capable: u8,
    pub multi_message_enabled: u8,
    pub enabled: bool,
}

impl MsiInfo {
    pub fn max_vectors(&self) -> u8 {
        1 << self.multi_message_capable
    }

    pub fn allocated_vectors(&self) -> u8 {
        1 << self.multi_message_enabled
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsixInfo {
    pub offset: u8,
    pub table_size: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
    pub enabled: bool,
    pub function_mask: bool,
}

impl MsixInfo {
    pub fn vector_count(&self) -> u16 {
        self.table_size + 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiMessage {
    pub address: u64,
    pub data: u32,
}

impl MsiMessage {
    pub fn new(vector: u8, dest_id: u8, edge_trigger: bool, level_assert: bool) -> Self {
        let address = (MSI_ADDRESS_BASE as u64) | ((dest_id as u64) << MSI_ADDRESS_DEST_ID_SHIFT);
        let mut data = (vector as u32) & MSI_DATA_VECTOR_MASK;
        data |= MSI_DATA_DELIVERY_FIXED;
        if !edge_trigger {
            data |= MSI_DATA_TRIGGER_LEVEL;
            if level_assert {
                data |= MSI_DATA_LEVEL_ASSERT;
            }
        }
        Self { address, data }
    }

    pub fn for_local_apic(vector: u8) -> Self {
        Self::new(vector, 0, true, false)
    }
}
