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

use super::data::is_reserved;
use super::types::{QrCode, QR_SIZE};

pub(super) fn apply_mask(qr: &mut QrCode, pattern: u8) {
    for y in 0..QR_SIZE {
        for x in 0..QR_SIZE {
            if is_reserved(x, y) {
                continue;
            }
            let should_flip = match pattern {
                0 => (y + x) % 2 == 0,
                1 => y % 2 == 0,
                2 => x % 3 == 0,
                3 => (y + x) % 3 == 0,
                4 => (y / 2 + x / 3) % 2 == 0,
                5 => (y * x) % 2 + (y * x) % 3 == 0,
                6 => ((y * x) % 2 + (y * x) % 3) % 2 == 0,
                _ => ((y + x) % 2 + (y * x) % 3) % 2 == 0,
            };
            if should_flip {
                qr.modules[y][x] = !qr.modules[y][x];
            }
        }
    }
}
