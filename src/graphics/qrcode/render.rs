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

/*
QR code framebuffer rendering. Scales modules to specified pixel size with
quiet zone margin. Dark modules rendered in foreground color, light in
background color for maximum contrast on any display.
*/

use crate::graphics::framebuffer::fill_rect;
use super::encode::QrCode;

const QUIET_ZONE: u32 = 4;

pub fn draw_qr(qr: &QrCode, x: u32, y: u32, module_size: u32, fg_color: u32, bg_color: u32) {
    let total_size = (qr.size as u32 + QUIET_ZONE * 2) * module_size;
    fill_rect(x, y, total_size, total_size, bg_color);

    let offset = QUIET_ZONE * module_size;
    for row in 0..qr.size {
        for col in 0..qr.size {
            if qr.modules[row][col] {
                let px = x + offset + (col as u32) * module_size;
                let py = y + offset + (row as u32) * module_size;
                fill_rect(px, py, module_size, module_size, fg_color);
            }
        }
    }
}
