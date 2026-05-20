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

use crate::frame_pacer::composite;
use nonos_libc::nonos_surface_present_rect;

use crate::gfx_client;
use crate::state::{Context, PresentMode};

pub fn tick(ctx: &mut Context) -> Result<(), &'static str> {
    let Some(rect) = ctx.damage.drain() else {
        return Ok(());
    };
    composite::paint(ctx, rect);
    if ctx.present_mode == PresentMode::BootFramebuffer {
        let rc =
            nonos_surface_present_rect(0, ctx.surface_id, rect.x, rect.y, rect.width, rect.height);
        if rc < 0 {
            return Err("boot framebuffer present failed");
        }
        return Ok(());
    }
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
