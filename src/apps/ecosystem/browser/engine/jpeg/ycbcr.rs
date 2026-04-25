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

use super::color::ycbcr_to_argb;
use super::crop::crop_plane;
use super::dct::{dequantize_and_dezigzag, idct_8x8};
use super::huffman::{BitReader, HuffmanTable};
use super::lookup::{find_huffman_table, find_quant_table};
use super::markers::JpegMarkers;
use crate::apps::ecosystem::browser::engine::ImageData;
use alloc::vec::Vec;

pub(super) fn decode_ycbcr(
    data: &[u8],
    markers: &JpegMarkers,
    width: u32,
    height: u32,
) -> Option<ImageData> {
    let comps = &markers.sof.components;
    let scan_comps = &markers.sos.components;
    let h_max = comps.iter().map(|c| c.h_sampling).max().unwrap_or(1);
    let v_max = comps.iter().map(|c| c.v_sampling).max().unwrap_or(1);
    let mcu_px_w = (h_max as u32) * 8;
    let mcu_px_h = (v_max as u32) * 8;
    let mcu_cols = ((width + mcu_px_w - 1) / mcu_px_w) as usize;
    let mcu_rows = ((height + mcu_px_h - 1) / mcu_px_h) as usize;
    let mut scan_lookup = [None; 4];
    for sc in scan_comps {
        for (ci, comp) in comps.iter().enumerate() {
            if comp.id == sc.component_id {
                scan_lookup[ci] = Some(sc);
            }
        }
    }
    let mut dc_tables: Vec<HuffmanTable> = Vec::new();
    let mut ac_tables: Vec<HuffmanTable> = Vec::new();
    let mut quant_tables: Vec<[u16; 64]> = Vec::new();
    for (ci, comp) in comps.iter().enumerate() {
        let sc = scan_lookup[ci]?;
        dc_tables.push(find_huffman_table(&markers.huffman_tables, 0, sc.dc_table_id)?);
        ac_tables.push(find_huffman_table(&markers.huffman_tables, 1, sc.ac_table_id)?);
        quant_tables.push(find_quant_table(&markers.quant_tables, comp.quant_table_id)?);
    }
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
    for mcu_row in 0..mcu_rows {
        for mcu_col in 0..mcu_cols {
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
                        let base_x = (mcu_col * blocks_h + bh) * 8;
                        let base_y = (mcu_row * blocks_v + bv) * 8;
                        let pw = plane_widths[ci];
                        for by in 0..8 {
                            for bx in 0..8 {
                                let idx = (base_y + by) * pw + base_x + bx;
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
    convert_planes_to_argb(&planes, &plane_widths, comps, width, height)
}

fn convert_planes_to_argb(
    planes: &[Vec<u8>],
    plane_widths: &[usize],
    comps: &[super::markers::ComponentInfo],
    width: u32,
    height: u32,
) -> Option<ImageData> {
    let y_w = plane_widths[0];
    let cb_w = plane_widths[1];
    let y_plane = crop_plane(&planes[0], y_w, width as usize, height as usize);
    let cb_h_pixels = (width as usize + (comps[0].h_sampling as usize) - 1)
        / (comps[0].h_sampling as usize)
        * (comps[1].h_sampling as usize);
    let cb_v_pixels = (height as usize + (comps[0].v_sampling as usize) - 1)
        / (comps[0].v_sampling as usize)
        * (comps[1].v_sampling as usize);
    let cb_plane = crop_plane(&planes[1], cb_w, cb_h_pixels, cb_v_pixels);
    let cr_plane = crop_plane(&planes[2], plane_widths[2], cb_h_pixels, cb_v_pixels);
    let pixels = ycbcr_to_argb(
        &y_plane,
        &cb_plane,
        &cr_plane,
        width,
        height,
        comps[0].h_sampling,
        comps[0].v_sampling,
        comps[1].h_sampling,
        comps[1].v_sampling,
    );
    Some(ImageData { width, height, pixels })
}
