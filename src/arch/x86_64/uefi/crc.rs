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

const CRC32_POLYNOMIAL: u32 = 0xEDB88320;
const CRC32_TABLE: [u32; 256] = generate_table();
const fn generate_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

#[inline]
pub fn compute(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

#[inline]
pub fn compute_with_zero_field(data: &[u8], zero_offset: usize, zero_len: usize) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for (i, &byte) in data.iter().enumerate() {
        let byte = if i >= zero_offset && i < zero_offset + zero_len {
            0
        } else {
            byte
        };
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

#[inline]
pub fn compute_table_crc(data: &[u8], crc_offset: usize) -> u32 {
    compute_with_zero_field(data, crc_offset, 4)
}

pub fn verify_table(data: &[u8], crc_offset: usize, expected_crc: u32) -> bool {
    compute_table_crc(data, crc_offset) == expected_crc
}

pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    #[inline]
    pub const fn new() -> Self {
        Self { state: 0xFFFFFFFF }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.state ^ byte as u32) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ CRC32_TABLE[index];
        }
    }

    #[inline]
    pub fn update_byte(&mut self, byte: u8) {
        let index = ((self.state ^ byte as u32) & 0xFF) as usize;
        self.state = (self.state >> 8) ^ CRC32_TABLE[index];
    }

    #[inline]
    pub const fn finalize(self) -> u32 {
        !self.state
    }

    #[inline]
    pub fn reset(&mut self) {
        self.state = 0xFFFFFFFF;
    }

    #[inline]
    pub const fn current(&self) -> u32 {
        !self.state
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_standard() {
        let data = b"123456789";
        assert_eq!(compute(data), 0xCBF43926);
    }

    #[test]
    fn test_compute_empty() {
        assert_eq!(compute(&[]), 0x00000000);
    }

    #[test]
    fn test_compute_single_byte() {
        assert_eq!(compute(&[0x00]), 0xD202EF8D);
        assert_eq!(compute(&[0xFF]), 0xFF000000);
    }

    #[test]
    fn test_streaming() {
        let mut crc = Crc32::new();
        crc.update(b"1234");
        crc.update(b"56789");
        assert_eq!(crc.finalize(), 0xCBF43926);
    }

    #[test]
    fn test_streaming_byte_by_byte() {
        let mut crc = Crc32::new();
        for &b in b"123456789" {
            crc.update_byte(b);
        }
        assert_eq!(crc.finalize(), 0xCBF43926);
    }

    #[test]
    fn test_with_zero_field() {
        let data = [0x01, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x03, 0x04];
        let zeroed = [0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04];
        assert_eq!(compute_with_zero_field(&data, 2, 4), compute(&zeroed));
    }

    #[test]
    fn test_reset() {
        let mut crc = Crc32::new();
        crc.update(b"test");
        crc.reset();
        crc.update(b"123456789");
        assert_eq!(crc.finalize(), 0xCBF43926);
    }

    #[test]
    fn test_verify_table() {
        let mut data = [0u8; 24];
        data[16..20].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let computed = compute_table_crc(&data, 16);
        data[16..20].copy_from_slice(&computed.to_le_bytes());
        assert!(verify_table(&data, 16, computed));
    }
}
