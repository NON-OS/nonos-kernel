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

use super::markers::HuffmanTableData;
use alloc::vec::Vec;

/// Maximum Huffman code length in JPEG (16 bits).
const MAX_CODE_LEN: usize = 16;

/// A built Huffman lookup table for fast decoding.
/// Uses a flat array: for each (code_length, code_value) pair, store the symbol.
/// We use the standard JPEG Huffman table generation algorithm.
#[derive(Debug, Clone)]
pub(super) struct HuffmanTable {
    /// min_code[i] = minimum code value at code length (i+1)
    min_code: [i32; MAX_CODE_LEN],
    /// max_code[i] = maximum code value at code length (i+1), or -1 if no codes
    max_code: [i32; MAX_CODE_LEN],
    /// val_ptr[i] = index into `symbols` where codes of length (i+1) start
    val_ptr: [usize; MAX_CODE_LEN],
    /// Symbol values in order of increasing code length then code value
    symbols: Vec<u8>,
}

impl HuffmanTable {
    /// Build a Huffman table from DHT marker data.
    pub(super) fn from_dht(dht: &HuffmanTableData) -> Option<Self> {
        let mut symbols = Vec::with_capacity(dht.symbols.len());
        symbols.extend_from_slice(&dht.symbols);

        let mut min_code = [0i32; MAX_CODE_LEN];
        let mut max_code = [-1i32; MAX_CODE_LEN];
        let mut val_ptr = [0usize; MAX_CODE_LEN];

        // Generate code values per JPEG spec (Annex C, Figure C.1)
        let mut code: i32 = 0;
        let mut si = 0usize; // symbol index

        for i in 0..MAX_CODE_LEN {
            let count = dht.counts[i] as usize;
            if count > 0 {
                val_ptr[i] = si;
                min_code[i] = code;
                max_code[i] = code + count as i32 - 1;
                si += count;
                code += count as i32;
            }
            code <<= 1;
        }

        Some(HuffmanTable { min_code, max_code, val_ptr, symbols })
    }
}

/// Bit-stream reader for entropy-coded JPEG data.
/// Handles byte-stuffing (0xFF 0x00 → 0xFF) and restart markers.
pub(super) struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buffer: u32,
    bits_left: u8,
}

impl<'a> BitReader<'a> {
    pub(super) fn new(data: &'a [u8], start: usize) -> Self {
        BitReader { data, pos: start, bit_buffer: 0, bits_left: 0 }
    }

    /// Read the next byte from the entropy stream, handling byte-stuffing.
    /// Returns `None` if we hit EOI or end of data.
    fn next_byte(&mut self) -> Option<u8> {
        if self.pos >= self.data.len() {
            return None;
        }
        let byte = self.data[self.pos];
        self.pos += 1;

        if byte == 0xFF {
            if self.pos >= self.data.len() {
                return None;
            }
            let next = self.data[self.pos];
            match next {
                0x00 => {
                    // Byte-stuffed 0xFF
                    self.pos += 1;
                    Some(0xFF)
                }
                0xD0..=0xD7 => {
                    // Restart marker — skip it and reset
                    self.pos += 1;
                    self.bit_buffer = 0;
                    self.bits_left = 0;
                    self.next_byte()
                }
                0xD9 => {
                    // EOI marker
                    None
                }
                _ => {
                    // Other marker — unexpected in entropy data
                    None
                }
            }
        } else {
            Some(byte)
        }
    }

    /// Ensure at least `n` bits are available in the buffer.
    fn fill_bits(&mut self, n: u8) -> Option<()> {
        while self.bits_left < n {
            let byte = self.next_byte()?;
            self.bit_buffer = (self.bit_buffer << 8) | (byte as u32);
            self.bits_left += 8;
        }
        Some(())
    }

    /// Read exactly `n` bits (1-16) from the stream as an unsigned value.
    fn read_bits(&mut self, n: u8) -> Option<u16> {
        if n == 0 {
            return Some(0);
        }
        if n > 16 {
            return None;
        }
        self.fill_bits(n)?;
        self.bits_left -= n;
        let val = (self.bit_buffer >> self.bits_left) & ((1u32 << n) - 1);
        Some(val as u16)
    }

    /// Decode one Huffman-coded symbol using the given table.
    fn decode_huffman(&mut self, table: &HuffmanTable) -> Option<u8> {
        let mut code: i32 = 0;
        for i in 0..MAX_CODE_LEN {
            let bit = self.read_bits(1)? as i32;
            code = (code << 1) | bit;
            if code <= table.max_code[i] {
                let idx = table.val_ptr[i] + (code - table.min_code[i]) as usize;
                return table.symbols.get(idx).copied();
            }
        }
        None // No valid code found in 16 bits
    }

    /// Decode a DC coefficient value.
    /// `category` is the Huffman-decoded symbol (number of additional bits).
    fn decode_dc_value(&mut self, category: u8) -> Option<i32> {
        if category == 0 {
            return Some(0);
        }
        if category > 15 {
            return None;
        }
        let bits = self.read_bits(category)? as i32;
        // Sign-extend: if the first bit is 0, the value is negative
        let threshold = 1i32 << (category - 1);
        if bits < threshold {
            Some(bits - (1i32 << category) + 1)
        } else {
            Some(bits)
        }
    }

    /// Decode one 8×8 block's worth of DCT coefficients.
    /// Returns 64 coefficients in zigzag order.
    /// `prev_dc` is updated with the new DC value (differential coding).
    pub(super) fn decode_block(
        &mut self,
        dc_table: &HuffmanTable,
        ac_table: &HuffmanTable,
        prev_dc: &mut i32,
    ) -> Option<[i32; 64]> {
        let mut coeffs = [0i32; 64];

        // DC coefficient
        let category = self.decode_huffman(dc_table)?;
        let dc_diff = self.decode_dc_value(category)?;
        *prev_dc += dc_diff;
        coeffs[0] = *prev_dc;

        // AC coefficients (positions 1-63 in zigzag order)
        let mut k = 1usize;
        while k < 64 {
            let symbol = self.decode_huffman(ac_table)?;
            if symbol == 0x00 {
                // EOB — remaining coefficients are zero
                break;
            }
            let run = (symbol >> 4) as usize; // number of zero coefficients to skip
            let size = (symbol & 0x0F) as u8; // number of bits for the value

            if symbol == 0xF0 {
                // ZRL — skip 16 zeros
                k += 16;
                continue;
            }

            k += run;
            if k >= 64 {
                break;
            }

            if size > 0 {
                let value = self.decode_dc_value(size)?; // same sign-extension as DC
                coeffs[k] = value;
            }
            k += 1;
        }

        Some(coeffs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_huffman_table() {
        // Simple table: one code of length 1 (symbol 0x00)
        let dht = HuffmanTableData {
            class: 0,
            id: 0,
            counts: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            symbols: alloc::vec![0x00],
        };
        let table = HuffmanTable::from_dht(&dht).unwrap();
        assert_eq!(table.min_code[0], 0);
        assert_eq!(table.max_code[0], 0);
        assert_eq!(table.symbols.len(), 1);
    }

    #[test]
    fn test_build_two_symbol_table() {
        // Two codes of length 1: symbols 0x00 and 0x01
        let dht = HuffmanTableData {
            class: 0,
            id: 0,
            counts: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            symbols: alloc::vec![0x00, 0x01],
        };
        let table = HuffmanTable::from_dht(&dht).unwrap();
        assert_eq!(table.min_code[0], 0);
        assert_eq!(table.max_code[0], 1);
    }

    #[test]
    fn test_bitreader_basic() {
        // Data: 0b10110000 = 0xB0
        let data = [0xB0u8, 0x00];
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.read_bits(1), Some(1));
        assert_eq!(reader.read_bits(1), Some(0));
        assert_eq!(reader.read_bits(2), Some(0b11));
    }

    #[test]
    fn test_bitreader_byte_stuffing() {
        // 0xFF followed by 0x00 should yield 0xFF
        let data = [0xFF, 0x00, 0x80];
        let mut reader = BitReader::new(&data, 0);
        let val = reader.read_bits(8);
        assert_eq!(val, Some(0xFF));
        let val2 = reader.read_bits(1);
        assert_eq!(val2, Some(1)); // first bit of 0x80
    }

    #[test]
    fn test_dc_value_decode() {
        // Category 3, bits 0b110 = 6 → positive 6
        let data = [0b11000000];
        let mut reader = BitReader::new(&data, 0);
        let val = reader.decode_dc_value(3);
        // Read 3 bits from 0b110_00000 = 6, category 3, threshold 4, 6 >= 4 → +6
        assert_eq!(val, Some(6));
    }

    #[test]
    fn test_dc_value_negative() {
        // Category 3, bits 0b001 = 1 → 1 - 8 + 1 = -6
        let data = [0b00100000];
        let mut reader = BitReader::new(&data, 0);
        let val = reader.decode_dc_value(3);
        assert_eq!(val, Some(-6));
    }

    #[test]
    fn test_decode_huffman_single_symbol() {
        let dht = HuffmanTableData {
            class: 0,
            id: 0,
            counts: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            symbols: alloc::vec![0x05],
        };
        let table = HuffmanTable::from_dht(&dht).unwrap();
        // Code '0' maps to symbol 0x05
        let data = [0x00]; // bit stream starts with 0
        let mut reader = BitReader::new(&data, 0);
        assert_eq!(reader.decode_huffman(&table), Some(0x05));
    }
}
