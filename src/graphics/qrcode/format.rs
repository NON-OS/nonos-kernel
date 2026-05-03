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

use super::encode::{QrCode, SIZE};

const FORMAT_BITS: [u16; 8] = [0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976];

pub fn draw_format_info(qr: &mut QrCode, mask: u8) {
    let bits = FORMAT_BITS[mask as usize & 7];
    for i in 0..6 {
        qr.modules[8][i] = get_bit(bits, i);
    }
    qr.modules[8][7] = get_bit(bits, 6);
    qr.modules[8][8] = get_bit(bits, 7);
    qr.modules[7][8] = get_bit(bits, 8);
    for i in 0..6 {
        qr.modules[5 - i][8] = get_bit(bits, 9 + i);
    }
    for i in 0..7 {
        qr.modules[SIZE - 1 - i][8] = get_bit(bits, i);
    }
    for i in 0..8 {
        qr.modules[8][SIZE - 8 + i] = get_bit(bits, 7 + i);
    }
}

fn get_bit(val: u16, pos: usize) -> bool {
    (val >> pos) & 1 == 1
}
