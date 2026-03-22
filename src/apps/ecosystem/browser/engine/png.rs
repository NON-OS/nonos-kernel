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

//! Minimal PNG decoder for the NONOS browser engine.
//!
//! Supports:
//! - 8-bit RGB and RGBA color types (color type 2 and 6)
//! - DEFLATE decompression via `miniz_oxide`
//! - PNG row filters (None, Sub, Up, Average, Paeth)
//!
//! Does NOT support:
//! - Indexed color (palette), grayscale, 16-bit depth
//! - Interlaced images (Adam7)
//! - Ancillary chunks (tEXt, gAMA, cHRM, etc.)

extern crate alloc;

use alloc::vec::Vec;
use super::types::ImageData;

const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

/// Decode a PNG file from raw bytes into ARGB8888 pixel data.
///
/// Returns `None` if the data is not valid PNG or uses an unsupported format.
pub fn decode_png(data: &[u8]) -> Option<ImageData> {
    if data.len() < 8 || data[..8] != PNG_SIGNATURE {
        return None;
    }

    let mut pos = 8;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let mut color_type: u8 = 0;
    let mut idat_data: Vec<u8> = Vec::new();

    while pos + 8 <= data.len() {
        let chunk_len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let chunk_type = &data[pos + 4..pos + 8];
        let chunk_data_start = pos + 8;
        let chunk_data_end = chunk_data_start + chunk_len;

        if chunk_data_end > data.len() {
            return None;
        }

        match chunk_type {
            b"IHDR" => {
                if chunk_len < 13 {
                    return None;
                }
                let d = &data[chunk_data_start..chunk_data_end];
                width = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
                height = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
                let bit_depth = d[8];
                color_type = d[9];
                let _compression = d[10];
                let _filter = d[11];
                let interlace = d[12];

                // Only support 8-bit RGB (2) and RGBA (6), non-interlaced
                if bit_depth != 8 || (color_type != 2 && color_type != 6) || interlace != 0 {
                    return None;
                }
                // Sanity limit: reject images larger than 4096x4096 to avoid OOM
                if width > 4096 || height > 4096 || width == 0 || height == 0 {
                    return None;
                }
            }
            b"IDAT" => {
                idat_data.extend_from_slice(&data[chunk_data_start..chunk_data_end]);
            }
            b"IEND" => break,
            _ => {} // Skip ancillary chunks
        }

        // Advance past chunk data + 4-byte CRC
        pos = chunk_data_end + 4;
    }

    if width == 0 || height == 0 || idat_data.is_empty() {
        return None;
    }

    // Decompress the IDAT stream (zlib-wrapped DEFLATE)
    let decompressed = miniz_oxide::inflate::decompress_to_vec_zlib(&idat_data).ok()?;

    let channels: usize = if color_type == 6 { 4 } else { 3 };
    let stride = width as usize * channels + 1; // +1 for filter byte per row
    if decompressed.len() < stride * height as usize {
        return None;
    }

    // Unfilter rows
    let mut unfiltered = Vec::with_capacity(width as usize * channels * height as usize);
    let mut prev_row: Vec<u8> = alloc::vec![0u8; width as usize * channels];

    for row in 0..height as usize {
        let row_start = row * stride;
        let filter_type = decompressed[row_start];
        let raw = &decompressed[row_start + 1..row_start + stride];

        let mut current_row = Vec::with_capacity(width as usize * channels);

        for i in 0..raw.len() {
            let a = if i >= channels { current_row[i - channels] } else { 0u8 };
            let b = prev_row[i];
            let c = if i >= channels { prev_row[i - channels] } else { 0u8 };

            let val = match filter_type {
                0 => raw[i],                                          // None
                1 => raw[i].wrapping_add(a),                         // Sub
                2 => raw[i].wrapping_add(b),                         // Up
                3 => raw[i].wrapping_add(((a as u16 + b as u16) / 2) as u8), // Average
                4 => raw[i].wrapping_add(paeth_predictor(a, b, c)),  // Paeth
                _ => return None, // Unknown filter
            };

            current_row.push(val);
        }

        unfiltered.extend_from_slice(&current_row);
        prev_row = current_row;
    }

    // Convert to ARGB8888
    let pixel_count = (width * height) as usize;
    let mut pixels = Vec::with_capacity(pixel_count);

    for i in 0..pixel_count {
        let offset = i * channels;
        if offset + channels > unfiltered.len() {
            break;
        }
        let r = unfiltered[offset] as u32;
        let g = unfiltered[offset + 1] as u32;
        let b = unfiltered[offset + 2] as u32;
        let a = if channels == 4 { unfiltered[offset + 3] as u32 } else { 0xFF };
        pixels.push((a << 24) | (r << 16) | (g << 8) | b);
    }

    Some(ImageData { width, height, pixels })
}

/// Paeth predictor function per PNG specification.
fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i32 + b as i32 - c as i32;
    let pa = (p - a as i32).abs();
    let pb = (p - b as i32).abs();
    let pc = (p - c as i32).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_png_invalid_signature() {
        assert!(decode_png(b"not a png").is_none());
        assert!(decode_png(&[]).is_none());
    }

    #[test]
    fn test_decode_png_truncated() {
        let mut data = PNG_SIGNATURE.to_vec();
        data.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
        // Truncated — no chunk type or data
        assert!(decode_png(&data).is_none());
    }

    #[test]
    fn test_paeth_predictor() {
        assert_eq!(paeth_predictor(0, 0, 0), 0);
        assert_eq!(paeth_predictor(100, 100, 100), 100);
        assert_eq!(paeth_predictor(50, 100, 50), 100);
    }

    #[test]
    fn test_decode_png_minimal_1x1_rgb() {
        // Construct a minimal valid 1x1 red pixel PNG (RGB, color type 2)
        let mut png = Vec::new();
        png.extend_from_slice(&PNG_SIGNATURE);

        // IHDR chunk: width=1, height=1, bit_depth=8, color_type=2 (RGB), compression=0, filter=0, interlace=0
        let ihdr_data: [u8; 13] = [
            0, 0, 0, 1, // width
            0, 0, 0, 1, // height
            8,           // bit depth
            2,           // color type (RGB)
            0,           // compression
            0,           // filter
            0,           // interlace
        ];
        append_chunk(&mut png, b"IHDR", &ihdr_data);

        // IDAT: zlib-compressed row: filter_byte=0, R=255, G=0, B=0
        let raw_row: [u8; 4] = [0, 255, 0, 0]; // filter=None, R, G, B
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&raw_row, 6);
        append_chunk(&mut png, b"IDAT", &compressed);

        // IEND
        append_chunk(&mut png, b"IEND", &[]);

        let result = decode_png(&png);
        assert!(result.is_some());
        let img = result.unwrap();
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 1);
        assert_eq!(img.pixels.len(), 1);
        // Expected: 0xFFFF0000 (alpha=FF, R=FF, G=00, B=00)
        assert_eq!(img.pixels[0], 0xFFFF0000);
    }

    #[test]
    fn test_decode_png_1x1_rgba() {
        let mut png = Vec::new();
        png.extend_from_slice(&PNG_SIGNATURE);

        // IHDR: 1x1, 8-bit RGBA (color type 6)
        let ihdr_data: [u8; 13] = [
            0, 0, 0, 1,
            0, 0, 0, 1,
            8, 6, 0, 0, 0,
        ];
        append_chunk(&mut png, b"IHDR", &ihdr_data);

        // IDAT: filter=0, R=0, G=255, B=0, A=128
        let raw_row: [u8; 5] = [0, 0, 255, 0, 128];
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&raw_row, 6);
        append_chunk(&mut png, b"IDAT", &compressed);

        append_chunk(&mut png, b"IEND", &[]);

        let img = decode_png(&png).unwrap();
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 1);
        // Expected: A=0x80, R=0x00, G=0xFF, B=0x00 → 0x8000FF00
        assert_eq!(img.pixels[0], 0x8000FF00);
    }

    #[test]
    fn test_decode_png_2x2_with_sub_filter() {
        let mut png = Vec::new();
        png.extend_from_slice(&PNG_SIGNATURE);

        let ihdr_data: [u8; 13] = [
            0, 0, 0, 2, // width=2
            0, 0, 0, 2, // height=2
            8, 2, 0, 0, 0, // 8-bit RGB
        ];
        append_chunk(&mut png, b"IHDR", &ihdr_data);

        // Row 0: filter=1 (Sub), pixel0=(100,150,200), pixel1 = delta(50,50,50)
        // Decoded pixel1 = (150,200,250)
        // Row 1: filter=0 (None), pixel0=(10,20,30), pixel1=(40,50,60)
        let raw: [u8; 14] = [
            1, 100, 150, 200, 50, 50, 50,  // row 0: Sub filter
            0, 10, 20, 30, 40, 50, 60,      // row 1: None filter
        ];
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6);
        append_chunk(&mut png, b"IDAT", &compressed);

        append_chunk(&mut png, b"IEND", &[]);

        let img = decode_png(&png).unwrap();
        assert_eq!(img.width, 2);
        assert_eq!(img.height, 2);
        assert_eq!(img.pixels.len(), 4);

        // Row 0: (100,150,200), (150,200,250)
        assert_eq!(img.pixels[0], 0xFF6496C8); // ARGB
        assert_eq!(img.pixels[1], 0xFF96C8FA);
        // Row 1: (10,20,30), (40,50,60)
        assert_eq!(img.pixels[2], 0xFF0A141E);
        assert_eq!(img.pixels[3], 0xFF28323C);
    }

    #[test]
    fn test_decode_png_oversized_rejected() {
        let mut png = Vec::new();
        png.extend_from_slice(&PNG_SIGNATURE);

        // 8192x8192 — exceeds 4096 limit
        let ihdr_data: [u8; 13] = [
            0, 0, 32, 0, // width=8192
            0, 0, 32, 0, // height=8192
            8, 2, 0, 0, 0,
        ];
        append_chunk(&mut png, b"IHDR", &ihdr_data);
        append_chunk(&mut png, b"IEND", &[]);

        assert!(decode_png(&png).is_none());
    }

    /// Helper to append a PNG chunk (length + type + data + CRC placeholder).
    fn append_chunk(buf: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(chunk_type);
        buf.extend_from_slice(data);
        // CRC (not validated by our decoder — write zeros)
        buf.extend_from_slice(&[0, 0, 0, 0]);
    }
}
