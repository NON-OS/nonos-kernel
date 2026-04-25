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

pub(super) fn place_finder_patterns(qr: &mut QrCode) {
    for (cx, cy) in [(0, 0), (18, 0), (0, 18)] {
        for dy in 0..7 {
            for dx in 0..7 {
                let x = cx + dx;
                let y = cy + dy;
                if x < QR_SIZE && y < QR_SIZE {
                    let is_border = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                    let is_center = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
                    qr.modules[y][x] = is_border || is_center;
                }
            }
        }
    }
    for i in 0..8 {
        if 7 < QR_SIZE {
            qr.modules[7][i] = false;
        }
        if i < QR_SIZE {
            qr.modules[i][7] = false;
        }
        if 7 < QR_SIZE && 17 + i < QR_SIZE {
            qr.modules[7][17 + i] = false;
        }
        if 17 + i < QR_SIZE {
            qr.modules[17 + i][7] = false;
        }
        if 17 < QR_SIZE && i < QR_SIZE {
            qr.modules[17][i] = false;
        }
        if i < QR_SIZE && 17 < QR_SIZE {
            qr.modules[i][17] = false;
        }
    }
}

pub(super) fn place_timing_patterns(qr: &mut QrCode) {
    for i in 8..17 {
        qr.modules[6][i] = i % 2 == 0;
        qr.modules[i][6] = i % 2 == 0;
    }
}

pub(super) fn place_alignment_pattern(qr: &mut QrCode) {
    let (cx, cy) = (18, 18);
    for dy in 0..5 {
        for dx in 0..5 {
            let x = cx - 2 + dx;
            let y = cy - 2 + dy;
            let is_border = dx == 0 || dx == 4 || dy == 0 || dy == 4;
            let is_center = dx == 2 && dy == 2;
            qr.modules[y][x] = is_border || is_center;
        }
    }
}
