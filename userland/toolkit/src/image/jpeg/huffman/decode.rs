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

use crate::image::jpeg::bits::BitReader;
use crate::image::jpeg::dht::HuffmanTable;
use crate::image::types::DecodeError;

pub fn decode_symbol(br: &mut BitReader, t: &HuffmanTable) -> Result<u8, DecodeError> {
    if !t.present {
        return Err(DecodeError::Unsupported);
    }
    let mut code: i32 = br.read_bits(1)? as i32;
    let mut l: usize = 1;
    while l <= 16 {
        if code <= t.maxcode[l] {
            let idx = (t.valptr[l] + (code - t.mincode[l])) as usize;
            if idx >= t.total {
                return Err(DecodeError::Unsupported);
            }
            return Ok(t.huffval[idx]);
        }
        code = (code << 1) | (br.read_bits(1)? as i32);
        l += 1;
    }
    Err(DecodeError::Unsupported)
}
