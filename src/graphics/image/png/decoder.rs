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
use crate::graphics::image::DecodedImage;
use super::deflate::zlib_decompress;

const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

pub fn decode_png(data: &[u8]) -> Option<DecodedImage> {
    if data.len() < 8 || data[..8] != PNG_MAGIC {
        return None;
    }

    let mut pos = 8;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut color_type = 0u8;
    let mut idat_chunks: Vec<&[u8]> = Vec::new();

    while pos + 12 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        let chunk_type = &data[pos+4..pos+8];

        if pos + 12 + len > data.len() {
            break;
        }

        match chunk_type {
            b"IHDR" if len >= 13 => {
                let chunk_data = &data[pos+8..pos+8+len];
                width = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]]);
                height = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
                let bit_depth = chunk_data[8];
                color_type = chunk_data[9];

                if bit_depth != 8 || (color_type != 2 && color_type != 6) {
                    return None;
                }
            }
            b"IDAT" => {
                idat_chunks.push(&data[pos+8..pos+8+len]);
            }
            b"IEND" => break,
            _ => {}
        }

        pos += 12 + len;
    }

    if width == 0 || height == 0 || idat_chunks.is_empty() {
        return None;
    }

    let total_idat_len: usize = idat_chunks.iter().map(|c| c.len()).sum();
    let mut idat_data = Vec::with_capacity(total_idat_len);
    for chunk in idat_chunks {
        idat_data.extend_from_slice(chunk);
    }

    let bytes_per_pixel = if color_type == 6 { 4 } else { 3 };
    let row_bytes = width as usize * bytes_per_pixel;
    let expected_size = (row_bytes + 1) * height as usize;

    let raw_data = zlib_decompress(&idat_data, expected_size)?;

    if raw_data.len() < expected_size {
        return None;
    }

    let mut pixels = Vec::with_capacity((width * height) as usize);
    let mut prev_row = alloc::vec![0u8; row_bytes];
    let mut curr_row = alloc::vec![0u8; row_bytes];

    for y in 0..height as usize {
        let row_start = y * (row_bytes + 1);
        let filter = raw_data[row_start];
        let scanline = &raw_data[row_start + 1..row_start + 1 + row_bytes];

        for i in 0..row_bytes {
            let x = scanline[i];
            let a = if i >= bytes_per_pixel { curr_row[i - bytes_per_pixel] } else { 0 };
            let b = prev_row[i];
            let c = if i >= bytes_per_pixel { prev_row[i - bytes_per_pixel] } else { 0 };

            curr_row[i] = match filter {
                0 => x,
                1 => x.wrapping_add(a),
                2 => x.wrapping_add(b),
                3 => x.wrapping_add(((a as u16 + b as u16) >> 1) as u8),
                4 => x.wrapping_add(paeth_predictor(a, b, c)),
                _ => x,
            };
        }

        for x in 0..width as usize {
            let i = x * bytes_per_pixel;
            let r = curr_row[i] as u32;
            let g = curr_row[i + 1] as u32;
            let b = curr_row[i + 2] as u32;
            let a = if bytes_per_pixel == 4 { curr_row[i + 3] as u32 } else { 255 };
            pixels.push((a << 24) | (r << 16) | (g << 8) | b);
        }

        core::mem::swap(&mut prev_row, &mut curr_row);
    }

    Some(DecodedImage::new(width, height, pixels))
}

#[inline]
fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i32 + b as i32 - c as i32;
    let pa = (p - a as i32).abs();
    let pb = (p - b as i32).abs();
    let pc = (p - c as i32).abs();
    if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c }
}
