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
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DuidType {
    Llt = 1,
    En = 2,
    Ll = 3,
    Uuid = 4,
}

#[derive(Debug, Clone)]
pub struct Duid {
    pub duid_type: DuidType,
    pub data: Vec<u8>,
}

const HW_TYPE_ETHERNET: u16 = 1;
const EPOCH_OFFSET: u32 = 946684800;

impl Duid {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let dtype = u16::from_be_bytes([data[0], data[1]]);
        let duid_type = match dtype {
            1 => DuidType::Llt,
            2 => DuidType::En,
            3 => DuidType::Ll,
            4 => DuidType::Uuid,
            _ => return None,
        };
        Some(Self { duid_type, data: data[2..].to_vec() })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.extend_from_slice(&(self.duid_type as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn hw_type(&self) -> Option<u16> {
        match self.duid_type {
            DuidType::Llt | DuidType::Ll if self.data.len() >= 2 => {
                Some(u16::from_be_bytes([self.data[0], self.data[1]]))
            }
            _ => None,
        }
    }

    pub fn link_layer_address(&self) -> Option<&[u8]> {
        match self.duid_type {
            DuidType::Llt if self.data.len() >= 8 => Some(&self.data[6..]),
            DuidType::Ll if self.data.len() >= 4 => Some(&self.data[2..]),
            _ => None,
        }
    }

    pub fn timestamp(&self) -> Option<u32> {
        match self.duid_type {
            DuidType::Llt if self.data.len() >= 6 => {
                Some(u32::from_be_bytes([self.data[2], self.data[3], self.data[4], self.data[5]]))
            }
            _ => None,
        }
    }
}

pub fn generate_duid_llt(mac: &[u8; 6]) -> Duid {
    let timestamp = (crate::sys::clock::unix_timestamp() as u32).saturating_sub(EPOCH_OFFSET);
    let mut data = Vec::with_capacity(10);
    data.extend_from_slice(&HW_TYPE_ETHERNET.to_be_bytes());
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(mac);
    Duid { duid_type: DuidType::Llt, data }
}

pub fn generate_duid_ll(mac: &[u8; 6]) -> Duid {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&HW_TYPE_ETHERNET.to_be_bytes());
    data.extend_from_slice(mac);
    Duid { duid_type: DuidType::Ll, data }
}

pub fn generate_duid_uuid(uuid: &[u8; 16]) -> Duid {
    Duid { duid_type: DuidType::Uuid, data: uuid.to_vec() }
}

pub fn get_mac_from_duid(duid: &Duid) -> Option<[u8; 6]> {
    let addr = duid.link_layer_address()?;
    if addr.len() >= 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&addr[..6]);
        Some(mac)
    } else {
        None
    }
}
