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

use crate::image::types::DecodeError;

pub struct BitReader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    pub bit_buf: u64,
    pub bit_count: u32,
    pub marker_hit: Option<u8>,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            pos: start,
            bit_buf: 0,
            bit_count: 0,
            marker_hit: None,
        }
    }

    fn fill_byte(&mut self) -> Result<(), DecodeError> {
        if self.marker_hit.is_some() {
            self.bit_buf <<= 8;
            self.bit_count += 8;
            return Ok(());
        }
        if self.pos >= self.data.len() {
            return Err(DecodeError::Truncated);
        }
        let mut b = self.data[self.pos];
        self.pos += 1;
        if b == 0xFF {
            if self.pos >= self.data.len() {
                return Err(DecodeError::Truncated);
            }
            let next = self.data[self.pos];
            self.pos += 1;
            if next == 0x00 {
                b = 0xFF;
            } else {
                self.marker_hit = Some(next);
                self.bit_buf <<= 8;
                self.bit_count += 8;
                return Ok(());
            }
        }
        self.bit_buf = (self.bit_buf << 8) | (b as u64);
        self.bit_count += 8;
        Ok(())
    }

    pub fn ensure(&mut self, n: u32) -> Result<(), DecodeError> {
        while self.bit_count < n {
            self.fill_byte()?;
        }
        Ok(())
    }

    pub fn peek(&mut self, n: u32) -> Result<u32, DecodeError> {
        self.ensure(n)?;
        let shift = self.bit_count - n;
        let mask: u64 = if n == 0 { 0 } else { (1u64 << n) - 1 };
        Ok(((self.bit_buf >> shift) & mask) as u32)
    }

    pub fn consume(&mut self, n: u32) {
        self.bit_count -= n;
        let mask: u64 = if self.bit_count == 0 { 0 } else { (1u64 << self.bit_count) - 1 };
        self.bit_buf &= mask;
    }

    pub fn read_bits(&mut self, n: u32) -> Result<u32, DecodeError> {
        if n == 0 {
            return Ok(0);
        }
        let v = self.peek(n)?;
        self.consume(n);
        Ok(v)
    }

    pub fn align_to_byte(&mut self) {
        let drop = self.bit_count & 7;
        if drop != 0 {
            self.consume(drop);
        }
    }

    pub fn flush(&mut self) {
        self.bit_buf = 0;
        self.bit_count = 0;
    }
}

pub fn extend(v: u32, t: u32) -> i32 {
    if t == 0 {
        return 0;
    }
    let vt: i32 = 1i32 << (t - 1);
    if (v as i32) < vt {
        let bias: i32 = (-1i32 << t) + 1;
        (v as i32) + bias
    } else {
        v as i32
    }
}
