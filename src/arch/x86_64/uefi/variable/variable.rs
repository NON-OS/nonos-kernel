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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::x86_64::uefi::types::{Guid, VariableAttributes};

#[derive(Debug, Clone)]
pub struct UefiVariable {
    pub name: String,
    pub guid: Guid,
    pub attributes: VariableAttributes,
    pub data: Vec<u8>,
}

impl UefiVariable {
    pub fn new(name: String, guid: Guid, attributes: VariableAttributes, data: Vec<u8>) -> Self {
        Self {
            name,
            guid,
            attributes,
            data,
        }
    }

    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_non_volatile(&self) -> bool {
        self.attributes.is_non_volatile()
    }

    pub fn is_runtime_accessible(&self) -> bool {
        self.attributes.is_runtime_access()
    }

    pub fn as_u8(&self) -> Option<u8> {
        if self.data.len() == 1 {
            Some(self.data[0])
        } else {
            None
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        if self.data.len() >= 2 {
            Some(u16::from_le_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() >= 8 {
            Some(u64::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
                self.data[4],
                self.data[5],
                self.data[6],
                self.data[7],
            ]))
        } else {
            None
        }
    }

    pub fn as_bool(&self) -> bool {
        !self.data.is_empty() && self.data[0] != 0
    }

    pub fn as_string(&self) -> Option<String> {
        if self.data.is_empty() {
            return Some(String::new());
        }

        if self.data.len() % 2 == 0 {
            let chars: Vec<u16> = self
                .data
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();

            String::from_utf16(&chars).ok()
        } else {
            let end = self.data.iter().position(|&b| b == 0).unwrap_or(self.data.len());
            String::from_utf8(self.data[..end].to_vec()).ok()
        }
    }
}
