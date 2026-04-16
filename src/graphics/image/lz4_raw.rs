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

const MAGIC: [u8; 4] = *b"NLZ4";

pub fn decode_lz4_raw(data: &[u8]) -> Option<DecodedImage> {
    if data.len() < 16 || data[0..4] != MAGIC {
        return None;
    }
    let width = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let height = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let uncompressed_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        return None;
    }
    let expected = (width * height * 4) as usize;
    if uncompressed_size != expected {
        return None;
    }
    let compressed = &data[16..];
    let raw = match lz4_flex::decompress(compressed, uncompressed_size) {
        Ok(data) => data,
        Err(_) => return None,
    };
    if raw.len() != expected {
        return None;
    }
    let mut pixels = Vec::with_capacity((width * height) as usize);
    for chunk in raw.chunks_exact(4) {
        let r = chunk[0] as u32;
        let g = chunk[1] as u32;
        let b = chunk[2] as u32;
        let a = chunk[3] as u32;
        pixels.push((a << 24) | (r << 16) | (g << 8) | b);
    }
    Some(DecodedImage::new(width, height, pixels))
}
