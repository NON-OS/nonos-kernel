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

use alloc::vec;
use nonos_toolkit::image::{bmp, jpeg, lz4_raw, png::decoder, types::DecodeError};

use crate::protocol::{DECODE_LZ4_PREFIX_LEN, DECODE_RESP_LEN, E_BAD_LEN, E_INVAL, E_UNSUPPORTED, HDR_LEN, OP_DECODE_BMP, OP_DECODE_JPEG, OP_DECODE_LZ4_RAW, OP_DECODE_PNG, Request, STATUS_LEN};
use crate::server::{handlers::surface::register_argb_surface, respond};

const MAX_PIXELS: usize = 16384;

pub fn handle(sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let mut pixels = vec![0u32; MAX_PIXELS];
    let decoded = match req.op {
        OP_DECODE_PNG => decoder::decode_png_argb8888(body, &mut pixels),
        OP_DECODE_BMP => bmp::decode_bmp_argb8888(body, &mut pixels),
        OP_DECODE_JPEG => jpeg::decode_jpeg_argb8888(body, &mut pixels),
        OP_DECODE_LZ4_RAW => decode_lz4(body, &mut pixels),
        _ => return,
    };
    let size = match decoded { Ok(v) => v, Err(e) => return fail(sender_pid, req, map_decode_error(e), tx) };
    let count = size.pixel_count() as usize;
    let (handle, stride, byte_len) = match register_argb_surface(&pixels[..count], size) { Ok(v) => v, Err(e) => return fail(sender_pid, req, e, tx) };
    let o = HDR_LEN + STATUS_LEN;
    tx[o..o + 8].copy_from_slice(&handle.to_le_bytes());
    tx[o + 8..o + 12].copy_from_slice(&size.width.to_le_bytes());
    tx[o + 12..o + 16].copy_from_slice(&size.height.to_le_bytes());
    tx[o + 16..o + 20].copy_from_slice(&stride.to_le_bytes());
    tx[o + 20..o + 24].copy_from_slice(&1u32.to_le_bytes());
    tx[o + 24..o + 32].copy_from_slice(&byte_len.to_le_bytes());
    let _ = respond::payload(sender_pid, req, DECODE_RESP_LEN, tx);
}

fn fail(sender_pid: u32, req: &Request, errno: i32, tx: &mut [u8]) { let _ = respond::status(sender_pid, req, errno, tx); }

fn decode_lz4(body: &[u8], out: &mut [u32]) -> Result<nonos_toolkit::types::ImageSize, DecodeError> {
    if body.len() < DECODE_LZ4_PREFIX_LEN { return Err(DecodeError::Truncated); }
    let width = u32::from_le_bytes(body[0..4].try_into().map_err(|_| DecodeError::Truncated)?);
    let height = u32::from_le_bytes(body[4..8].try_into().map_err(|_| DecodeError::Truncated)?);
    lz4_raw::decode_lz4_raw_argb8888(width, height, &body[8..], out)
}

fn map_decode_error(err: DecodeError) -> i32 {
    match err { DecodeError::BadMagic => E_INVAL, DecodeError::Unsupported => E_UNSUPPORTED, DecodeError::BadDimensions => E_BAD_LEN, DecodeError::OutputTooSmall => E_BAD_LEN, DecodeError::Truncated => E_BAD_LEN }
}
