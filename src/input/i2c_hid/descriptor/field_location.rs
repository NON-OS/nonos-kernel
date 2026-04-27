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

#[derive(Debug, Clone, Copy, Default)]
pub struct FieldLocation {
    pub bit_offset: u16,
    pub bit_size: u16,
}

impl FieldLocation {
    pub fn is_valid(&self) -> bool {
        self.bit_size > 0
    }

    pub fn extract(&self, data: &[u8]) -> i32 {
        if !self.is_valid() || data.is_empty() {
            return 0;
        }
        let byte_offset = (self.bit_offset / 8) as usize;
        let bit_in_byte = (self.bit_offset % 8) as u32;
        if byte_offset >= data.len() {
            return 0;
        }
        match self.bit_size {
            1 => ((data[byte_offset] >> bit_in_byte) & 1) as i32,
            8 if bit_in_byte == 0 => data[byte_offset] as i32,
            16 if bit_in_byte == 0 && byte_offset + 1 < data.len() => {
                u16::from_le_bytes([data[byte_offset], data[byte_offset + 1]]) as i32
            }
            _ => self.extract_general(data, byte_offset),
        }
    }

    fn extract_general(&self, data: &[u8], _byte_offset: usize) -> i32 {
        let mut value: u32 = 0;
        let mut bits_remaining = self.bit_size as u32;
        let mut current_bit = self.bit_offset as u32;
        while bits_remaining > 0 {
            let byte_idx = (current_bit / 8) as usize;
            if byte_idx >= data.len() {
                break;
            }
            let bit_idx = current_bit % 8;
            let bits_in_byte = (8 - bit_idx).min(bits_remaining);
            let mask = ((1u32 << bits_in_byte) - 1) as u8;
            let byte_val = (data[byte_idx] >> bit_idx) & mask;
            let shift = self.bit_size as u32 - bits_remaining;
            value |= (byte_val as u32) << shift;
            bits_remaining -= bits_in_byte;
            current_bit += bits_in_byte;
        }
        value as i32
    }
}
