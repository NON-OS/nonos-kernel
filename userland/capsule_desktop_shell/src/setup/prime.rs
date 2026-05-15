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

use nonos_libc::{
    mk_mmap, mk_surface_register, mk_surface_share, nonos_display_dimensions, SurfaceDescriptor,
    SURFACE_FORMAT_ARGB8888,
};

use super::discover;
use crate::compositor_client::push_scene_submit;
use crate::render::paint_chrome;
use crate::state::{Context, SpotlightState, TrayTable};

const PROT_READ_WRITE: i32 = 0x3;
const MAP_PRIVATE_ANON: i32 = 0x22;
const OVERLAY_Z: u32 = 1;

pub fn run() -> Result<Context, &'static str> {
    let compositor_port = discover::require_compositor()?;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let rc = nonos_display_dimensions(0, &mut width as *mut u32, &mut height as *mut u32);
    if rc != 0 || width == 0 || height == 0 {
        return Err("display dimensions unavailable");
    }
    let stride = width.checked_mul(4).ok_or("stride overflow")?;
    let byte_len = (stride as u64)
        .checked_mul(height as u64)
        .ok_or("overlay size overflow")?;
    let base = mk_mmap(
        core::ptr::null_mut(),
        byte_len as usize,
        PROT_READ_WRITE,
        MAP_PRIVATE_ANON,
        -1,
        0,
    );
    if base.is_null() {
        return Err("overlay mmap failed");
    }
    let backing_va = base as u64;
    let mut ctx = Context {
        compositor_port,
        width,
        height,
        stride,
        backing_va,
        tray: TrayTable::new(),
        spotlight: SpotlightState::new(),
        last_notify_level: None,
        next_request_id: 1,
    };
    paint_chrome(&ctx);
    let desc = SurfaceDescriptor {
        width,
        height,
        stride,
        format: SURFACE_FORMAT_ARGB8888,
        byte_len,
        base_va: backing_va,
        flags: 0,
    };
    let sid = mk_surface_register(&desc);
    if sid < 0 {
        return Err("overlay surface register rejected");
    }
    let handle = mk_surface_share(sid as u64);
    if handle <= 0 {
        return Err("overlay surface share rejected");
    }
    let rid = ctx.issue_request_id();
    push_scene_submit(compositor_port, rid, handle as u64, 0, 0, width, height, OVERLAY_Z)?;
    Ok(ctx)
}
