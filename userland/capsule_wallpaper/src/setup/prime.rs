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
    mk_mmap, mk_surface_register, mk_surface_release, mk_surface_share, nonos_display_dimensions,
    SurfaceDescriptor, SURFACE_FORMAT_ARGB8888,
};

use super::discover;
use crate::compositor_client::{healthcheck, push_scene_submit};
use crate::paint::fill_argb;
use crate::state::{Context, FadeTimeline, Policy};

const DEFAULT_ARGB: u32 = 0xFF10_1620;
const PROT_READ_WRITE: i32 = 0x3;
const MAP_PRIVATE_ANON: i32 = 0x22;
const BOTTOM_Z: u32 = 0;

pub fn run() -> Result<Context, &'static str> {
    let compositor_port = discover::lookup_compositor_port()?;
    healthcheck(compositor_port, 1)?;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let rc = nonos_display_dimensions(0, &mut width as *mut u32, &mut height as *mut u32);
    if rc != 0 || width == 0 || height == 0 {
        return Err("display dimensions unavailable");
    }
    let stride = width.checked_mul(4).ok_or("stride overflow")?;
    let byte_len = (stride as u64).checked_mul(height as u64).ok_or("surface size overflow")?;
    let base =
        mk_mmap(core::ptr::null_mut(), byte_len as usize, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0);
    if base.is_null() {
        return Err("backing mmap failed");
    }
    let backing_va = base as u64;
    fill_argb(backing_va, stride, width, height, DEFAULT_ARGB);
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
        return Err("surface register rejected");
    }
    let handle = mk_surface_share(sid as u64);
    if handle <= 0 {
        return Err("surface share rejected");
    }
    let mut ctx = Context {
        compositor_port,
        width,
        height,
        stride,
        backing_va,
        argb: DEFAULT_ARGB,
        alpha: 0xFF,
        policy: Policy::Fill,
        fade: FadeTimeline::new(),
        next_request_id: 1,
    };
    ctx.set_argb(DEFAULT_ARGB);
    let rid = ctx.issue_request_id();
    if let Err(e) =
        push_scene_submit(compositor_port, rid, handle as u64, 0, 0, width, height, BOTTOM_Z)
    {
        let _ = mk_surface_release(handle as u64);
        let _ = mk_surface_release(handle as u64);
        return Err(e);
    }
    Ok(ctx)
}
