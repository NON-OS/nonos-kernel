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

const GEN_POLY: [u8; 7] = [0x01, 0x7F, 0x7A, 0x9A, 0xA4, 0x0B, 0x44];

pub fn compute_ecc(data: &[u8; 19]) -> [u8; 7] {
    let mut ecc = [0u8; 7];
    for i in 0..19 {
        let coef = data[i] ^ ecc[0];
        for j in 0..6 {
            ecc[j] = ecc[j + 1];
        }
        ecc[6] = 0;
        for j in 0..7 {
            ecc[j] ^= gf_mul(GEN_POLY[j], coef);
        }
    }
    ecc
}

fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u16;
    let mut aa = a as u16;
    let mut bb = b;
    while bb != 0 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        bb >>= 1;
        aa <<= 1;
        if aa & 0x100 != 0 {
            aa ^= 0x11D;
        }
    }
    result as u8
}
