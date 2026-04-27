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

#[derive(Debug, Clone)]
pub struct HidDescriptor {
    pub hid_descriptor_length: u16,
    pub bcd_version: u16,
    pub report_descriptor_length: u16,
    pub report_descriptor_register: u16,
    pub input_register: u16,
    pub max_input_length: u16,
    pub output_register: u16,
    pub max_output_length: u16,
    pub command_register: u16,
    pub data_register: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub version_id: u16,
}

impl HidDescriptor {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 30 {
            return None;
        }
        let hid_descriptor_length = u16::from_le_bytes([data[0], data[1]]);
        if hid_descriptor_length < 30 {
            return None;
        }
        let bcd_version = u16::from_le_bytes([data[2], data[3]]);
        if bcd_version != 0x0100 {
            return None;
        }
        Some(Self {
            hid_descriptor_length,
            bcd_version,
            report_descriptor_length: u16::from_le_bytes([data[4], data[5]]),
            report_descriptor_register: u16::from_le_bytes([data[6], data[7]]),
            input_register: u16::from_le_bytes([data[8], data[9]]),
            max_input_length: u16::from_le_bytes([data[10], data[11]]),
            output_register: u16::from_le_bytes([data[12], data[13]]),
            max_output_length: u16::from_le_bytes([data[14], data[15]]),
            command_register: u16::from_le_bytes([data[16], data[17]]),
            data_register: u16::from_le_bytes([data[18], data[19]]),
            vendor_id: u16::from_le_bytes([data[20], data[21]]),
            product_id: u16::from_le_bytes([data[22], data[23]]),
            version_id: u16::from_le_bytes([data[24], data[25]]),
        })
    }
}

impl Default for HidDescriptor {
    fn default() -> Self {
        Self {
            hid_descriptor_length: 30,
            bcd_version: 0x0100,
            report_descriptor_length: 0,
            report_descriptor_register: 0x0002,
            input_register: 0x0003,
            max_input_length: 64,
            output_register: 0x0004,
            max_output_length: 64,
            command_register: 0x0005,
            data_register: 0x0006,
            vendor_id: 0,
            product_id: 0,
            version_id: 0,
        }
    }
}
