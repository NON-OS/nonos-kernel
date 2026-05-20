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

pub const MAX_HT: usize = 4;

#[derive(Clone)]
pub struct HuffmanTable {
    pub present: bool,
    pub bits: [u8; 17],
    pub huffval: [u8; 256],
    pub mincode: [i32; 17],
    pub maxcode: [i32; 18],
    pub valptr: [i32; 17],
    pub total: usize,
}

impl HuffmanTable {
    pub const fn new() -> Self {
        Self {
            present: false,
            bits: [0; 17],
            huffval: [0; 256],
            mincode: [0; 17],
            maxcode: [-1; 18],
            valptr: [0; 17],
            total: 0,
        }
    }
}

fn build_decode_tables(t: &mut HuffmanTable) {
    let mut huffsize = [0u8; 257];
    let mut huffcode = [0u32; 257];
    let mut k = 0usize;
    let mut i = 1usize;
    while i <= 16 {
        let mut j = 1u8;
        while j <= t.bits[i] {
            huffsize[k] = i as u8;
            k += 1;
            j += 1;
        }
        i += 1;
    }
    huffsize[k] = 0;
    let mut code: u32 = 0;
    let mut si: u8 = huffsize[0];
    let mut k2 = 0usize;
    while huffsize[k2] != 0 {
        while huffsize[k2] == si {
            huffcode[k2] = code;
            code += 1;
            k2 += 1;
        }
        if huffsize[k2] == 0 {
            break;
        }
        while huffsize[k2] != si {
            code <<= 1;
            si += 1;
        }
    }
    let mut j = 0usize;
    let mut l = 1usize;
    while l <= 16 {
        if t.bits[l] == 0 {
            t.maxcode[l] = -1;
        } else {
            t.valptr[l] = j as i32;
            t.mincode[l] = huffcode[j] as i32;
            j += t.bits[l] as usize;
            t.maxcode[l] = huffcode[j - 1] as i32;
        }
        l += 1;
    }
    t.maxcode[17] = 0xFFFFF;
    t.total = k;
}

pub fn parse_dht(
    seg: &[u8],
    dc_tables: &mut [HuffmanTable; MAX_HT],
    ac_tables: &mut [HuffmanTable; MAX_HT],
) -> Result<(), DecodeError> {
    let mut p = 0usize;
    while p < seg.len() {
        let tc_th = seg[p];
        p += 1;
        let tc = (tc_th >> 4) & 0x0F;
        let th = (tc_th & 0x0F) as usize;
        if th >= MAX_HT || tc > 1 {
            return Err(DecodeError::Unsupported);
        }
        if p + 16 > seg.len() {
            return Err(DecodeError::Truncated);
        }
        let mut t = HuffmanTable::new();
        let mut count = 0usize;
        let mut i = 1usize;
        while i <= 16 {
            t.bits[i] = seg[p + i - 1];
            count += t.bits[i] as usize;
            i += 1;
        }
        p += 16;
        if count > 256 || p + count > seg.len() {
            return Err(DecodeError::Truncated);
        }
        let mut i = 0usize;
        while i < count {
            t.huffval[i] = seg[p + i];
            i += 1;
        }
        p += count;
        t.present = true;
        build_decode_tables(&mut t);
        if tc == 0 {
            dc_tables[th] = t;
        } else {
            ac_tables[th] = t;
        }
    }
    Ok(())
}
