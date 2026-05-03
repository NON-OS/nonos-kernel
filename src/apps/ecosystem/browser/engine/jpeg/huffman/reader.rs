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

pub(super) struct BitReader<'a> {
    pub(super) data: &'a [u8],
    pub(super) pos: usize,
    pub(super) bit_buffer: u32,
    pub(super) bits_left: u8,
}

impl<'a> BitReader<'a> {
    pub(super) fn new(data: &'a [u8], start: usize) -> Self {
        BitReader { data, pos: start, bit_buffer: 0, bits_left: 0 }
    }

    pub(super) fn next_byte(&mut self) -> Option<u8> {
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
                    self.pos += 1;
                    Some(0xFF)
                }
                0xD0..=0xD7 => {
                    self.pos += 1;
                    self.bit_buffer = 0;
                    self.bits_left = 0;
                    self.next_byte()
                }
                0xD9 => None,
                _ => None,
            }
        } else {
            Some(byte)
        }
    }

    pub(super) fn fill_bits(&mut self, n: u8) -> Option<()> {
        while self.bits_left < n {
            let byte = self.next_byte()?;
            self.bit_buffer = (self.bit_buffer << 8) | (byte as u32);
            self.bits_left += 8;
        }
        Some(())
    }

    pub(super) fn read_bits(&mut self, n: u8) -> Option<u16> {
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
}
