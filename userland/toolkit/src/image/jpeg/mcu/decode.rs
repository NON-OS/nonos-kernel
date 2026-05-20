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

use crate::image::jpeg::bits::{extend, BitReader};
use crate::image::jpeg::dht::HuffmanTable;
use crate::image::jpeg::dqt::QuantTable;
use crate::image::jpeg::huffman::decode_symbol;
use crate::image::jpeg::idct::idct_8x8;
use crate::image::jpeg::zigzag::ZIGZAG;
use crate::image::types::DecodeError;

pub fn decode_block(
    br: &mut BitReader,
    dc_table: &HuffmanTable,
    ac_table: &HuffmanTable,
    qt: &QuantTable,
    pred: &mut i32,
    samples: &mut [u8; 64],
) -> Result<(), DecodeError> {
    let mut coeffs: [i32; 64] = [0; 64];
    let t = decode_symbol(br, dc_table)? as u32;
    if t > 11 {
        return Err(DecodeError::Unsupported);
    }
    let raw = br.read_bits(t)?;
    let diff = extend(raw, t);
    *pred += diff;
    coeffs[0] = (*pred) * (qt.values[0] as i32);
    let mut k = 1usize;
    while k < 64 {
        let rs = decode_symbol(br, ac_table)?;
        let s = (rs & 0x0F) as u32;
        let r = ((rs >> 4) & 0x0F) as usize;
        if s == 0 {
            if r == 15 {
                k += 16;
                continue;
            }
            break;
        }
        k += r;
        if k >= 64 {
            return Err(DecodeError::Unsupported);
        }
        let raw_ac = br.read_bits(s)?;
        let val = extend(raw_ac, s);
        let zi = ZIGZAG[k];
        coeffs[zi] = val * (qt.values[zi] as i32);
        k += 1;
    }
    idct_8x8(&coeffs, samples);
    Ok(())
}
