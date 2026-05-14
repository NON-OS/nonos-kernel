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

#[derive(Clone, Copy)]
pub struct ControllerIdentity {
    pub vendor_id: u16,
    pub subsystem_vendor_id: u16,
    pub serial: [u8; 20],
    pub model: [u8; 40],
    pub firmware: [u8; 8],
    pub version: u32,
    pub optional_admin: u16,
    pub namespace_count: u32,
    pub mdts: u8,
    pub sq_entry_size: u8,
    pub cq_entry_size: u8,
    pub optional_nvm: u16,
    pub volatile_write_cache: u8,
}

impl ControllerIdentity {
    pub fn parse(data: &[u8]) -> Self {
        let mut serial = [0u8; 20];
        let mut model = [0u8; 40];
        let mut firmware = [0u8; 8];
        serial.copy_from_slice(&data[0x04..0x18]);
        model.copy_from_slice(&data[0x18..0x40]);
        firmware.copy_from_slice(&data[0x40..0x48]);
        Self {
            vendor_id: le16(data, 0x00),
            subsystem_vendor_id: le16(data, 0x02),
            serial,
            model,
            firmware,
            version: le32(data, 0x50),
            optional_admin: le16(data, 0x100),
            namespace_count: le32(data, 0x204),
            mdts: data[0x4d],
            sq_entry_size: data[0x200],
            cq_entry_size: data[0x201],
            optional_nvm: le16(data, 0x208),
            volatile_write_cache: data[0x20d],
        }
    }
}

fn le16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn le32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}
