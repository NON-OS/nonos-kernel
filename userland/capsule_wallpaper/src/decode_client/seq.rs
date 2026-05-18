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

use super::{header::parse_decode_req, wire::decode_argb};
use crate::{protocol::E_INVAL, state::Context};

pub fn decode_and_paint(ctx: &Context, body: &[u8]) -> Result<(), i32> {
    let req = parse_decode_req(body)?;
    let cap = (ctx.width as usize).saturating_mul(ctx.height as usize);
    let mut decoded = vec![0u32; cap];
    let size = decode_argb(&req, &mut decoded).map_err(|_| E_INVAL)?;
    paint_stretch(
        ctx.backing_va,
        ctx.stride as usize,
        ctx.width as usize,
        ctx.height as usize,
        &decoded,
        size.width as usize,
        size.height as usize,
    );
    Ok(())
}

fn paint_stretch(
    base_va: u64,
    stride: usize,
    dst_w: usize,
    dst_h: usize,
    src: &[u32],
    src_w: usize,
    src_h: usize,
) {
    if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
        return;
    }
    for y in 0..dst_h {
        let sy = (y * src_h) / dst_h;
        for x in 0..dst_w {
            let sx = (x * src_w) / dst_w;
            let px = src[sy * src_w + sx];
            let addr = (base_va as usize + y * stride + x * 4) as *mut u32;
            unsafe { core::ptr::write_volatile(addr, px) };
        }
    }
}
