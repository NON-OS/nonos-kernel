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

use nonos_libc::{mk_surface_attach, SurfaceDescriptor};

use super::discover;
use crate::gfx_client;
use crate::state::{Context, DamageAccumulator, FocusTable, SceneTable};

// 1. Wait for the gfx driver service.
// 2. Pull the driver-owned primary surface metadata + registry handle.
// 3. Attach the same DMA-backed pages into this AS via the kernel
//    surface registry, then mark the full screen damaged so the first
//    frame_pacer tick paints + scans out.
pub fn run() -> Result<Context, &'static str> {
    let gfx_pid = discover::lookup_gfx_pid()?;
    let primary = gfx_client::get_primary_surface(gfx_pid, 1)?;
    if primary.handle == 0 || primary.width == 0 || primary.height == 0 {
        return Err("gfx primary surface absent");
    }
    let mut desc = SurfaceDescriptor::default();
    let rc = mk_surface_attach(primary.handle, &mut desc);
    if rc <= 0 {
        return Err("surface attach rejected");
    }
    let mut damage = DamageAccumulator::new();
    damage.mark_full(primary.width, primary.height);
    Ok(Context {
        gfx_pid,
        resource_id: primary.resource_id,
        width: primary.width,
        height: primary.height,
        stride: primary.stride,
        backing_va: rc as u64,
        primary_handle: primary.handle,
        first_scanout_done: false,
        next_request_id: 2,
        scene: SceneTable::new(),
        damage,
        focus: FocusTable::new(),
    })
}
