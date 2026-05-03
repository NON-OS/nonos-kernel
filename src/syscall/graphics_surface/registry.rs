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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::memory::PhysAddr;

use super::pixel_format::PixelFmt;

pub type SurfaceId = u64;

pub struct Surface {
    pub owner_pid: u32,
    pub width: u32,
    pub height: u32,
    pub fmt: PixelFmt,
    pub frames: Vec<PhysAddr>,
    pub mapped_va: Option<u64>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static TABLE: Mutex<BTreeMap<SurfaceId, Surface>> = Mutex::new(BTreeMap::new());

pub fn insert(surface: Surface) -> SurfaceId {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    TABLE.lock().insert(id, surface);
    id
}

pub fn remove(id: SurfaceId, owner_pid: u32) -> Option<Surface> {
    let mut table = TABLE.lock();
    match table.get(&id) {
        Some(s) if s.owner_pid == owner_pid => table.remove(&id),
        _ => None,
    }
}

pub fn record_mapping(id: SurfaceId, owner_pid: u32, base_va: u64) -> Option<()> {
    let mut table = TABLE.lock();
    let surface = table.get_mut(&id)?;
    if surface.owner_pid != owner_pid || surface.mapped_va.is_some() {
        return None;
    }
    surface.mapped_va = Some(base_va);
    Some(())
}

pub fn with_surface_frames(id: SurfaceId, owner_pid: u32) -> Option<Vec<PhysAddr>> {
    let table = TABLE.lock();
    let surface = table.get(&id)?;
    if surface.owner_pid != owner_pid || surface.mapped_va.is_some() {
        return None;
    }
    Some(surface.frames.clone())
}

pub struct SurfaceView {
    pub width: u32,
    pub height: u32,
    pub fmt: PixelFmt,
    pub frames: Vec<PhysAddr>,
}

pub fn snapshot(id: SurfaceId, owner_pid: u32) -> Option<SurfaceView> {
    let table = TABLE.lock();
    let surface = table.get(&id)?;
    if surface.owner_pid != owner_pid {
        return None;
    }
    Some(SurfaceView {
        width: surface.width,
        height: surface.height,
        fmt: surface.fmt,
        frames: surface.frames.clone(),
    })
}
