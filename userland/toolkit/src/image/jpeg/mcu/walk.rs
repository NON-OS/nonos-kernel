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

use crate::image::jpeg::bits::BitReader;
use crate::image::jpeg::dht::{HuffmanTable, MAX_HT};
use crate::image::jpeg::dqt::{QuantTable, MAX_QT};
use crate::image::jpeg::mcu::decode::decode_block;
use crate::image::jpeg::sof0::FrameHeader;
use crate::image::jpeg::sos::ScanHeader;
use crate::image::jpeg::ycbcr::{gray_to_argb8888, ycbcr_to_argb8888};
use crate::image::types::DecodeError;

pub struct ScanContext<'a> {
    pub frame: &'a FrameHeader,
    pub scan: &'a ScanHeader,
    pub dc_tables: &'a [HuffmanTable; MAX_HT],
    pub ac_tables: &'a [HuffmanTable; MAX_HT],
    pub qt: &'a [QuantTable; MAX_QT],
    pub restart_interval: u32,
}

fn next_rst_marker(prev: u8) -> u8 {
    let n = (prev + 1) & 7;
    0xD0 | n
}

fn handle_restart(
    br: &mut BitReader,
    expected: u8,
    pred: &mut [i32; 3],
) -> Result<u8, DecodeError> {
    br.align_to_byte();
    br.flush();
    let mut m = br.marker_hit.take();
    if m.is_none() {
        while br.pos < br.data.len() && br.data[br.pos] != 0xFF {
            br.pos += 1;
        }
        while br.pos < br.data.len() && br.data[br.pos] == 0xFF {
            br.pos += 1;
        }
        if br.pos >= br.data.len() {
            return Err(DecodeError::Truncated);
        }
        let mk = br.data[br.pos];
        br.pos += 1;
        m = Some(mk);
    }
    let marker = m.ok_or(DecodeError::Truncated)?;
    if marker != expected {
        return Err(DecodeError::Unsupported);
    }
    pred[0] = 0;
    pred[1] = 0;
    pred[2] = 0;
    Ok(next_rst_marker(expected))
}

fn emit_grayscale(
    out: &mut [u32],
    width: usize,
    height: usize,
    y_blk: &[u8; 64],
    mcu_x: usize,
    mcu_y: usize,
) {
    let base_x = mcu_x * 8;
    let base_y = mcu_y * 8;
    let mut yy = 0usize;
    while yy < 8 {
        let py = base_y + yy;
        if py >= height {
            break;
        }
        let mut xx = 0usize;
        while xx < 8 {
            let px = base_x + xx;
            if px < width {
                let v = y_blk[yy * 8 + xx];
                out[py * width + px] = gray_to_argb8888(v);
            }
            xx += 1;
        }
        yy += 1;
    }
}

fn emit_color(
    out: &mut [u32],
    width: usize,
    height: usize,
    h_max: usize,
    v_max: usize,
    y_blocks: &[[u8; 64]],
    cb_blk: &[u8; 64],
    cr_blk: &[u8; 64],
    mcu_x: usize,
    mcu_y: usize,
) {
    let mcu_w = h_max * 8;
    let mcu_h = v_max * 8;
    let base_x = mcu_x * mcu_w;
    let base_y = mcu_y * mcu_h;
    let mut yy = 0usize;
    while yy < mcu_h {
        let py = base_y + yy;
        if py >= height {
            break;
        }
        let mut xx = 0usize;
        while xx < mcu_w {
            let px = base_x + xx;
            if px < width {
                let by = yy / 8;
                let bx = xx / 8;
                let iy = yy % 8;
                let ix = xx % 8;
                let yi = by * h_max + bx;
                let y_val = y_blocks[yi][iy * 8 + ix];
                let cx = xx / h_max;
                let cy = yy / v_max;
                let cb_val = cb_blk[cy * 8 + cx];
                let cr_val = cr_blk[cy * 8 + cx];
                out[py * width + px] = ycbcr_to_argb8888(y_val, cb_val, cr_val);
            }
            xx += 1;
        }
        yy += 1;
    }
}

pub fn walk_scan(
    ctx: &ScanContext,
    entropy: &[u8],
    entropy_start: usize,
    out: &mut [u32],
) -> Result<usize, DecodeError> {
    let width = ctx.frame.width as usize;
    let height = ctx.frame.height as usize;
    let h_max = ctx.frame.h_max as usize;
    let v_max = ctx.frame.v_max as usize;
    let mcu_pixel_w = h_max * 8;
    let mcu_pixel_h = v_max * 8;
    let mcus_x = (width + mcu_pixel_w - 1) / mcu_pixel_w;
    let mcus_y = (height + mcu_pixel_h - 1) / mcu_pixel_h;
    let mut br = BitReader::new(entropy, entropy_start);
    let mut pred: [i32; 3] = [0; 3];
    let mut y_blocks: [[u8; 64]; 4] = [[0; 64]; 4];
    let mut cb_blk: [u8; 64] = [0; 64];
    let mut cr_blk: [u8; 64] = [0; 64];
    let mut next_rst: u8 = 0xD0;
    let mut mcus_since_rst: u32 = 0;
    let is_color = ctx.frame.num_comps == 3;
    let mut my = 0usize;
    while my < mcus_y {
        let mut mx = 0usize;
        while mx < mcus_x {
            if is_color {
                let y_comp_index = ctx.scan.comps[0].frame_index;
                let cb_index = ctx.scan.comps[1].frame_index;
                let cr_index = ctx.scan.comps[2].frame_index;
                let y_blocks_count = h_max * v_max;
                let mut bi = 0usize;
                while bi < y_blocks_count {
                    decode_block(
                        &mut br,
                        &ctx.dc_tables[ctx.scan.comps[0].td as usize],
                        &ctx.ac_tables[ctx.scan.comps[0].ta as usize],
                        &ctx.qt[ctx.frame.comps[y_comp_index].tq as usize],
                        &mut pred[0],
                        &mut y_blocks[bi],
                    )?;
                    bi += 1;
                }
                decode_block(
                    &mut br,
                    &ctx.dc_tables[ctx.scan.comps[1].td as usize],
                    &ctx.ac_tables[ctx.scan.comps[1].ta as usize],
                    &ctx.qt[ctx.frame.comps[cb_index].tq as usize],
                    &mut pred[1],
                    &mut cb_blk,
                )?;
                decode_block(
                    &mut br,
                    &ctx.dc_tables[ctx.scan.comps[2].td as usize],
                    &ctx.ac_tables[ctx.scan.comps[2].ta as usize],
                    &ctx.qt[ctx.frame.comps[cr_index].tq as usize],
                    &mut pred[2],
                    &mut cr_blk,
                )?;
                emit_color(
                    out, width, height, h_max, v_max,
                    &y_blocks[..y_blocks_count],
                    &cb_blk, &cr_blk, mx, my,
                );
            } else {
                let comp_index = ctx.scan.comps[0].frame_index;
                decode_block(
                    &mut br,
                    &ctx.dc_tables[ctx.scan.comps[0].td as usize],
                    &ctx.ac_tables[ctx.scan.comps[0].ta as usize],
                    &ctx.qt[ctx.frame.comps[comp_index].tq as usize],
                    &mut pred[0],
                    &mut y_blocks[0],
                )?;
                emit_grayscale(out, width, height, &y_blocks[0], mx, my);
            }
            mcus_since_rst += 1;
            if ctx.restart_interval != 0
                && mcus_since_rst == ctx.restart_interval
                && !(mx + 1 == mcus_x && my + 1 == mcus_y)
            {
                next_rst = handle_restart(&mut br, next_rst, &mut pred)?;
                mcus_since_rst = 0;
            }
            mx += 1;
        }
        my += 1;
    }
    br.align_to_byte();
    Ok(br.pos)
}
