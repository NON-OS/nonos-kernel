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

use crate::gfx_client;
use crate::state::{scene::SceneTable, Context};
use crate::sw_blitter;

// Picks the topmost (highest z) layer's surface handle for tracing.
// Real multi-layer compositing arrives once toolkit hooks in; the
// read here keeps the scene-layer surface/z fields observable.
fn top_owner_handle(ctx: &Context) -> Option<u64> {
    pick_top_handle(&ctx.scene)
}

fn pick_top_handle(scene: &SceneTable) -> Option<u64> {
    let mut top: Option<(u64, u32)> = None;
    for layer in scene.layers() {
        if let Some(read) = scene.read(layer.owner_pid) {
            top = Some(match top {
                None => read,
                Some(cur) if read.1 > cur.1 => read,
                Some(cur) => cur,
            });
        }
    }
    top.map(|(handle, _z)| handle)
}

// One frame: drain damage, paint the bottom layer into the
// driver-shared backing, tell the GPU to pull and scan out. SET_SCANOUT
// only runs once after bring-up; subsequent frames just FLUSH.
const BACKGROUND_ARGB: u32 = 0xFF10_1620;

pub fn tick(ctx: &mut Context) -> Result<(), &'static str> {
    let Some(rect) = ctx.damage.drain() else {
        return Ok(());
    };
    let _top = top_owner_handle(ctx);
    sw_blitter::fill_rect(
        ctx.backing_va,
        ctx.stride,
        rect.x,
        rect.y,
        rect.width,
        rect.height,
        BACKGROUND_ARGB,
    );
    let req_a = ctx.issue_request_id();
    let pixel_offset = (rect.y as u64) * (ctx.stride as u64) + (rect.x as u64) * 4;
    gfx_client::transfer_to_host(
        ctx.gfx_port,
        req_a,
        ctx.resource_id,
        rect.x,
        rect.y,
        rect.width,
        rect.height,
        pixel_offset,
    )?;
    if !ctx.first_scanout_done {
        let req_b = ctx.issue_request_id();
        gfx_client::set_scanout(
            ctx.gfx_port,
            req_b,
            0,
            ctx.resource_id,
            0,
            0,
            ctx.width,
            ctx.height,
        )?;
        ctx.first_scanout_done = true;
    }
    let req_c = ctx.issue_request_id();
    gfx_client::resource_flush(
        ctx.gfx_port,
        req_c,
        ctx.resource_id,
        rect.x,
        rect.y,
        rect.width,
        rect.height,
    )?;
    Ok(())
}
