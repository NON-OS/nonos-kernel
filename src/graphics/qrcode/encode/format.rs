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

use super::types::{QrCode, QR_SIZE};

pub(super) fn place_format_info(qr: &mut QrCode) {
    let format_bits: u16 = 0b111110110101010;
    for i in 0..6 {
        qr.modules[8][i] = (format_bits >> i) & 1 == 1;
    }
    qr.modules[8][7] = (format_bits >> 6) & 1 == 1;
    qr.modules[8][8] = (format_bits >> 7) & 1 == 1;
    qr.modules[7][8] = (format_bits >> 8) & 1 == 1;
    for i in 0..6 {
        qr.modules[5 - i][8] = (format_bits >> (9 + i)) & 1 == 1;
    }
    for i in 0..7 {
        qr.modules[QR_SIZE - 1 - i][8] = (format_bits >> i) & 1 == 1;
    }
    qr.modules[QR_SIZE - 8][8] = true;
    for i in 0..8 {
        qr.modules[8][QR_SIZE - 8 + i] = (format_bits >> (7 + i)) & 1 == 1;
    }
}
