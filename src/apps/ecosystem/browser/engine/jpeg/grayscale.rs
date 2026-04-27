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

use super::color::gray_to_argb;
use super::crop::crop_plane;
use super::dct::{dequantize_and_dezigzag, idct_8x8};
use super::huffman::BitReader;
use super::lookup::{find_huffman_table, find_quant_table};
use super::markers::JpegMarkers;
use crate::apps::ecosystem::browser::engine::ImageData;

pub(super) fn decode_grayscale(
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
    let plane_w = mcu_w * 8;
    let plane_h = mcu_h * 8;
    let mut y_plane = alloc::vec![128u8; plane_w * plane_h];
    for mcu_row in 0..mcu_h {
        for mcu_col in 0..mcu_w {
            let coeffs = reader.decode_block(&dc_table, &ac_table, &mut prev_dc)?;
            let mut block = dequantize_and_dezigzag(&coeffs, &quant);
            idct_8x8(&mut block);
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
    let cropped = crop_plane(&y_plane, plane_w, width as usize, height as usize);
    let pixels = gray_to_argb(&cropped, width, height);
    Some(ImageData { width, height, pixels })
}
