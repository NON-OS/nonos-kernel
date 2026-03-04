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

use alloc::vec::Vec;
use super::DecodedImage;

pub fn decode_bmp(data: &[u8]) -> Option<DecodedImage> {
    if data.len() < 54 {
        return None;
    }

    if data[0] != b'B' || data[1] != b'M' {
        return None;
    }

    let data_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
    let width = i32::from_le_bytes([data[18], data[19], data[20], data[21]]);
    let height = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
    let bits_per_pixel = u16::from_le_bytes([data[28], data[29]]);

    if width <= 0 || height == 0 {
        return None;
    }

    let width = width as u32;
    let height_abs = height.unsigned_abs();
    let top_down = height < 0;

    let row_size = ((bits_per_pixel as u32 * width + 31) / 32) * 4;

    let mut pixels = Vec::with_capacity((width * height_abs) as usize);

    for row in 0..height_abs {
        let src_row = if top_down { row } else { height_abs - 1 - row };
        let row_start = data_offset + (src_row * row_size) as usize;

        for col in 0..width {
            let pixel = match bits_per_pixel {
                24 => {
                    let idx = row_start + (col * 3) as usize;
                    if idx + 2 >= data.len() {
                        return None;
                    }
                    let b = data[idx] as u32;
                    let g = data[idx + 1] as u32;
                    let r = data[idx + 2] as u32;
                    0xFF000000 | (r << 16) | (g << 8) | b
                }
                32 => {
                    let idx = row_start + (col * 4) as usize;
                    if idx + 3 >= data.len() {
                        return None;
                    }
                    let b = data[idx] as u32;
                    let g = data[idx + 1] as u32;
                    let r = data[idx + 2] as u32;
                    let a = data[idx + 3] as u32;
                    (a << 24) | (r << 16) | (g << 8) | b
                }
                _ => return None,
            };
            pixels.push(pixel);
        }
    }

    Some(DecodedImage::new(width, height_abs, pixels))
}
