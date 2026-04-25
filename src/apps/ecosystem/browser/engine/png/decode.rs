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

extern crate alloc;

use super::chunks::{parse_ihdr, read_chunk, PngHeader};
use super::filter::unfilter_row;
use crate::apps::ecosystem::browser::engine::types::ImageData;
use alloc::vec::Vec;

const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

pub fn decode_png(data: &[u8]) -> Option<ImageData> {
    if data.len() < 8 || data[..8] != PNG_SIGNATURE {
        return None;
    }
    let mut pos = 8;
    let mut header: Option<PngHeader> = None;
    let mut idat_data: Vec<u8> = Vec::new();
    while let Some((next_pos, chunk_type, chunk_data)) = read_chunk(data, pos) {
        match chunk_type {
            b"IHDR" => {
                header = parse_ihdr(chunk_data);
            }
            b"IDAT" => {
                idat_data.extend_from_slice(chunk_data);
            }
            b"IEND" => break,
            _ => {}
        }
        pos = next_pos;
    }
    let hdr = header?;
    if idat_data.is_empty() {
        return None;
    }
    let decompressed = miniz_oxide::inflate::decompress_to_vec_zlib(&idat_data).ok()?;
    decode_pixels(&hdr, &decompressed)
}

fn decode_pixels(hdr: &PngHeader, decompressed: &[u8]) -> Option<ImageData> {
    let channels: usize = if hdr.color_type == 6 { 4 } else { 3 };
    let stride = hdr.width as usize * channels + 1;
    if decompressed.len() < stride * hdr.height as usize {
        return None;
    }
    let mut unfiltered = Vec::with_capacity(hdr.width as usize * channels * hdr.height as usize);
    let mut prev_row: Vec<u8> = alloc::vec![0u8; hdr.width as usize * channels];
    for row in 0..hdr.height as usize {
        let row_start = row * stride;
        let filter_type = decompressed[row_start];
        let raw = &decompressed[row_start + 1..row_start + stride];
        let current_row = unfilter_row(filter_type, raw, &prev_row, channels)?;
        unfiltered.extend_from_slice(&current_row);
        prev_row = current_row;
    }
    let pixel_count = (hdr.width * hdr.height) as usize;
    let mut pixels = Vec::with_capacity(pixel_count);
    for i in 0..pixel_count {
        let offset = i * channels;
        if offset + channels > unfiltered.len() {
            break;
        }
        let (r, g, b) = (
            unfiltered[offset] as u32,
            unfiltered[offset + 1] as u32,
            unfiltered[offset + 2] as u32,
        );
        let a = if channels == 4 { unfiltered[offset + 3] as u32 } else { 0xFF };
        pixels.push((a << 24) | (r << 16) | (g << 8) | b);
    }
    Some(ImageData { width: hdr.width, height: hdr.height, pixels })
}
