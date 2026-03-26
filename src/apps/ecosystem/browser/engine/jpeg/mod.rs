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

mod markers;
mod huffman;
mod dct;
mod color;

use alloc::vec::Vec;
use crate::apps::ecosystem::browser::engine::ImageData;
use markers::{JpegMarkers, parse_markers};
use huffman::{HuffmanTable, BitReader};
use dct::{dequantize_and_dezigzag, idct_8x8};
use color::{ycbcr_to_argb, gray_to_argb};

/// Decode a baseline JPEG (SOF0) from raw bytes.
/// Returns `None` for progressive JPEG, corrupt data, or unsupported formats.
pub fn decode_jpeg(data: &[u8]) -> Option<ImageData> {
    let markers = parse_markers(data)?;

    // Only support baseline DCT (SOF0)
    if !markers.sof.is_baseline {
        return None;
    }

    let width = markers.sof.width;
    let height = markers.sof.height;
    let num_components = markers.sof.components.len();

    if num_components == 1 {
        decode_grayscale(data, &markers, width, height)
    } else if num_components == 3 {
        decode_ycbcr(data, &markers, width, height)
    } else {
        None // Unsupported component count (e.g., CMYK=4)
    }
}

/// Decode a single-component (grayscale) JPEG.
fn decode_grayscale(
    data: &[u8],
    markers: &JpegMarkers,
    width: u32,
    height: u32,
) -> Option<ImageData> {
    let comp = &markers.sof.components[0];
    let scan_comp = &markers.sos.components[0];

    let dc_table = find_huffman_table(&markers.huffman_tables, 0, scan_comp.dc_table_id)?;
    let ac_table = find_huffman_table(&markers.huffman_tables, 1, scan_comp.ac_table_id)?;
    let quant = find_quant_table(&markers.quant_tables, comp.quant_table_id)?;

    let mcu_w = ((width + 7) / 8) as usize;
    let mcu_h = ((height + 7) / 8) as usize;

    let mut reader = BitReader::new(data, markers.sos.entropy_data_offset);
    let mut prev_dc: i32 = 0;

    // Allocate full plane (MCU-aligned)
    let plane_w = mcu_w * 8;
    let plane_h = mcu_h * 8;
    let mut y_plane = alloc::vec![128u8; plane_w * plane_h];

    for mcu_row in 0..mcu_h {
        for mcu_col in 0..mcu_w {
            let coeffs = reader.decode_block(&dc_table, &ac_table, &mut prev_dc)?;
            let mut block = dequantize_and_dezigzag(&coeffs, &quant);
            idct_8x8(&mut block);

            // Write 8×8 block to plane
            let base_x = mcu_col * 8;
            let base_y = mcu_row * 8;
            for by in 0..8 {
                for bx in 0..8 {
                    let px = base_x + bx;
                    let py = base_y + by;
                    if px < plane_w && py < plane_h {
                        y_plane[py * plane_w + px] = block[by * 8 + bx] as u8;
                    }
                }
            }
        }
    }

    // Crop plane to actual dimensions and convert to ARGB
    let cropped = crop_plane(&y_plane, plane_w, width as usize, height as usize);
    let pixels = gray_to_argb(&cropped, width, height);
    Some(ImageData { width, height, pixels })
}

/// Decode a 3-component YCbCr JPEG.
fn decode_ycbcr(
    data: &[u8],
    markers: &JpegMarkers,
    width: u32,
    height: u32,
) -> Option<ImageData> {
    let comps = &markers.sof.components;
    let scan_comps = &markers.sos.components;

    // Find max sampling factors
    let h_max = comps.iter().map(|c| c.h_sampling).max().unwrap_or(1);
    let v_max = comps.iter().map(|c| c.v_sampling).max().unwrap_or(1);

    // MCU dimensions in pixels
    let mcu_px_w = (h_max as u32) * 8;
    let mcu_px_h = (v_max as u32) * 8;
    let mcu_cols = ((width + mcu_px_w - 1) / mcu_px_w) as usize;
    let mcu_rows = ((height + mcu_px_h - 1) / mcu_px_h) as usize;

    // Build lookup: component_id → scan component
    let mut scan_lookup = [None; 4];
    for sc in scan_comps {
        for (ci, comp) in comps.iter().enumerate() {
            if comp.id == sc.component_id {
                scan_lookup[ci] = Some(sc);
            }
        }
    }

    // Prepare Huffman tables and quant tables per component
    let mut dc_tables: Vec<HuffmanTable> = Vec::new();
    let mut ac_tables: Vec<HuffmanTable> = Vec::new();
    let mut quant_tables: Vec<[u16; 64]> = Vec::new();

    for (ci, comp) in comps.iter().enumerate() {
        let sc = scan_lookup[ci]?;
        dc_tables.push(find_huffman_table(&markers.huffman_tables, 0, sc.dc_table_id)?);
        ac_tables.push(find_huffman_table(&markers.huffman_tables, 1, sc.ac_table_id)?);
        quant_tables.push(find_quant_table(&markers.quant_tables, comp.quant_table_id)?);
    }

    // Allocate component planes (each at their own resolution)
    let mut planes: Vec<Vec<u8>> = Vec::new();
    let mut plane_widths: Vec<usize> = Vec::new();

    for comp in comps {
        let pw = mcu_cols * (comp.h_sampling as usize) * 8;
        let ph = mcu_rows * (comp.v_sampling as usize) * 8;
        planes.push(alloc::vec![128u8; pw * ph]);
        plane_widths.push(pw);
    }

    let mut reader = BitReader::new(data, markers.sos.entropy_data_offset);
    let mut prev_dc = [0i32; 4];

    // Decode MCUs
    for mcu_row in 0..mcu_rows {
        for mcu_col in 0..mcu_cols {
            // Each MCU contains blocks for each component
            for ci in 0..comps.len() {
                let comp = &comps[ci];
                let blocks_h = comp.h_sampling as usize;
                let blocks_v = comp.v_sampling as usize;

                for bv in 0..blocks_v {
                    for bh in 0..blocks_h {
                        let coeffs = reader.decode_block(
                            &dc_tables[ci],
                            &ac_tables[ci],
                            &mut prev_dc[ci],
                        )?;
                        let mut block = dequantize_and_dezigzag(&coeffs, &quant_tables[ci]);
                        idct_8x8(&mut block);

                        // Write block to component plane
                        let base_x = (mcu_col * blocks_h + bh) * 8;
                        let base_y = (mcu_row * blocks_v + bv) * 8;
                        let pw = plane_widths[ci];

                        for by in 0..8 {
                            for bx in 0..8 {
                                let px = base_x + bx;
                                let py = base_y + by;
                                let idx = py * pw + px;
                                if idx < planes[ci].len() {
                                    planes[ci][idx] = block[by * 8 + bx] as u8;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Crop planes to actual dimensions and convert to ARGB
    let y_w = plane_widths[0];
    let cb_w = plane_widths[1];

    let y_plane = crop_plane(&planes[0], y_w, width as usize, height as usize);
    // Chroma planes are at their native (subsampled) resolution
    // ycbcr_to_argb handles upsampling via sampling factor ratios
    let cb_h_pixels = (width as usize + (comps[0].h_sampling as usize) - 1) / (comps[0].h_sampling as usize) * (comps[1].h_sampling as usize);
    let cb_v_pixels = (height as usize + (comps[0].v_sampling as usize) - 1) / (comps[0].v_sampling as usize) * (comps[1].v_sampling as usize);
    let cb_plane = crop_plane(&planes[1], cb_w, cb_h_pixels, cb_v_pixels);
    let cr_plane = crop_plane(&planes[2], plane_widths[2], cb_h_pixels, cb_v_pixels);

    let pixels = ycbcr_to_argb(
        &y_plane, &cb_plane, &cr_plane,
        width, height,
        comps[0].h_sampling, comps[0].v_sampling,
        comps[1].h_sampling, comps[1].v_sampling,
    );

    Some(ImageData { width, height, pixels })
}

/// Find a Huffman table by class (0=DC, 1=AC) and id.
fn find_huffman_table(
    tables: &[markers::HuffmanTableData],
    class: u8,
    id: u8,
) -> Option<HuffmanTable> {
    tables.iter()
        .find(|t| t.class == class && t.id == id)
        .and_then(|t| HuffmanTable::from_dht(t))
}

/// Find a quantization table by id.
fn find_quant_table(tables: &[markers::QuantTable], id: u8) -> Option<[u16; 64]> {
    tables.iter()
        .find(|t| t.id == id)
        .map(|t| t.values)
}

/// Crop a padded plane to the target dimensions.
fn crop_plane(plane: &[u8], plane_width: usize, target_w: usize, target_h: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(target_w * target_h);
    for row in 0..target_h {
        let start = row * plane_width;
        let end = start + target_w;
        if end <= plane.len() {
            out.extend_from_slice(&plane[start..end]);
        } else if start < plane.len() {
            out.extend_from_slice(&plane[start..]);
            // Pad remaining with 128
            for _ in 0..(end - plane.len()) {
                out.push(128);
            }
        } else {
            for _ in 0..target_w {
                out.push(128);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Build a minimal valid 8×8 grayscale baseline JPEG.
    /// DC=0 → all pixels will be 128 (mid-gray) after IDCT level shift.
    fn build_gray_jpeg(width: u16, height: u16) -> Vec<u8> {
        let mut data = Vec::new();
        // SOI
        data.extend_from_slice(&[0xFF, 0xD8]);

        // DQT — all-ones quantization table (id=0)
        data.extend_from_slice(&[0xFF, 0xDB]);
        data.extend_from_slice(&67u16.to_be_bytes());
        data.push(0x00);
        for _ in 0..64 { data.push(1); }

        // SOF0 — baseline, grayscale
        data.extend_from_slice(&[0xFF, 0xC0]);
        data.extend_from_slice(&11u16.to_be_bytes());
        data.push(8);
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&width.to_be_bytes());
        data.push(1); // 1 component
        data.push(1); data.push(0x11); data.push(0);

        // DHT — DC table: symbol 0 with code '0'
        data.extend_from_slice(&[0xFF, 0xC4]);
        data.extend_from_slice(&20u16.to_be_bytes());
        data.push(0x00);
        data.push(1); for _ in 1..16 { data.push(0); }
        data.push(0x00);

        // DHT — AC table: symbol 0x00 (EOB) with code '0'
        data.extend_from_slice(&[0xFF, 0xC4]);
        data.extend_from_slice(&20u16.to_be_bytes());
        data.push(0x10);
        data.push(1); for _ in 1..16 { data.push(0); }
        data.push(0x00);

        // SOS
        data.extend_from_slice(&[0xFF, 0xDA]);
        data.extend_from_slice(&8u16.to_be_bytes());
        data.push(1);
        data.push(1); data.push(0x00);
        data.push(0); data.push(63); data.push(0);

        // Entropy: DC category=0 (code '0'), AC EOB (code '0')
        // For each MCU, we need 2 bits (DC=0, AC=EOB)
        let mcu_w = ((width as usize) + 7) / 8;
        let mcu_h = ((height as usize) + 7) / 8;
        let total_mcus = mcu_w * mcu_h;
        let total_bits = total_mcus * 2;
        let total_bytes = (total_bits + 7) / 8;
        for _ in 0..total_bytes { data.push(0x00); }

        // EOI
        data.extend_from_slice(&[0xFF, 0xD9]);
        data
    }

    #[test]
    fn test_decode_8x8_grayscale() {
        let jpeg = build_gray_jpeg(8, 8);
        let result = decode_jpeg(&jpeg);
        assert!(result.is_some(), "decode_jpeg returned None");
        let img = result.unwrap();
        assert_eq!(img.width, 8);
        assert_eq!(img.height, 8);
        assert_eq!(img.pixels.len(), 64);
        // All pixels should be mid-gray (128) → ARGB = 0xFF808080
        for (i, &pixel) in img.pixels.iter().enumerate() {
            assert_eq!(pixel, 0xFF808080, "pixel {} = 0x{:08X}", i, pixel);
        }
    }

    #[test]
    fn test_decode_16x16_grayscale() {
        let jpeg = build_gray_jpeg(16, 16);
        let result = decode_jpeg(&jpeg);
        assert!(result.is_some());
        let img = result.unwrap();
        assert_eq!(img.width, 16);
        assert_eq!(img.height, 16);
        assert_eq!(img.pixels.len(), 256);
    }

    #[test]
    fn test_reject_progressive() {
        let mut jpeg = build_gray_jpeg(8, 8);
        // Change SOF0 (0xC0) to SOF2 (0xC2) to make it progressive
        for i in 0..jpeg.len() - 1 {
            if jpeg[i] == 0xFF && jpeg[i + 1] == 0xC0 {
                jpeg[i + 1] = 0xC2;
                break;
            }
        }
        assert!(decode_jpeg(&jpeg).is_none());
    }

    #[test]
    fn test_reject_truncated() {
        let jpeg = build_gray_jpeg(8, 8);
        // Truncate before EOI
        let truncated = &jpeg[..jpeg.len() / 2];
        // Should handle gracefully (return None, not panic)
        let _ = decode_jpeg(truncated);
    }

    #[test]
    fn test_reject_not_jpeg() {
        assert!(decode_jpeg(&[]).is_none());
        assert!(decode_jpeg(&[0x89, 0x50, 0x4E, 0x47]).is_none()); // PNG magic
        assert!(decode_jpeg(&[0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_reject_oversized() {
        // Build a JPEG header with 8192×8192 — should be rejected by marker parser
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xD8]);
        data.extend_from_slice(&[0xFF, 0xC0]);
        data.extend_from_slice(&11u16.to_be_bytes());
        data.push(8);
        data.extend_from_slice(&8192u16.to_be_bytes());
        data.extend_from_slice(&8192u16.to_be_bytes());
        data.push(1);
        data.push(1); data.push(0x11); data.push(0);
        data.extend_from_slice(&[0xFF, 0xD9]);
        assert!(decode_jpeg(&data).is_none());
    }
}
