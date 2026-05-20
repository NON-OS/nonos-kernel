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

//! TOOLKIT_OP_COMPONENT_RENDER handler. The request payload is a
//! fixed prefix of 24 bytes:
//!
//!   0..8   target surface handle (u64 little-endian)
//!   8..12  x position in pixels (u32)
//!   12..16 y position in pixels (u32)
//!   16..20 width  in pixels (u32)
//!   20..24 height in pixels (u32)
//!   24..26 component kind (u16)
//!   26..28 label byte length (u16)
//!   28..   label bytes (UTF-8)

use nonos_libc::{mk_surface_attach, SurfaceDescriptor};
use spin::Mutex;

use crate::protocol::{E_INVAL, E_SHORT, E_SURFACE, STATUS_OK};

use super::kind::ComponentKind;
use super::paint::paint;

const HEADER_LEN: usize = 28;

#[derive(Clone, Copy)]
struct AttachedSurface {
    handle: u64,
    desc: SurfaceDescriptor,
}

static ATTACHED_SURFACE: Mutex<Option<AttachedSurface>> = Mutex::new(None);

pub fn render(payload: &[u8]) -> u16 {
    if payload.len() < HEADER_LEN {
        return E_SHORT;
    }
    let handle = u64::from_le_bytes(payload[0..8].try_into().unwrap_or([0u8; 8]));
    let x = u32::from_le_bytes(payload[8..12].try_into().unwrap_or([0u8; 4]));
    let y = u32::from_le_bytes(payload[12..16].try_into().unwrap_or([0u8; 4]));
    let w = u32::from_le_bytes(payload[16..20].try_into().unwrap_or([0u8; 4]));
    let h = u32::from_le_bytes(payload[20..24].try_into().unwrap_or([0u8; 4]));
    let kind_raw = u16::from_le_bytes(payload[24..26].try_into().unwrap_or([0u8; 2]));
    let label_len = u16::from_le_bytes(payload[26..28].try_into().unwrap_or([0u8; 2])) as usize;
    if w == 0 || h == 0 || handle == 0 {
        return E_INVAL;
    }
    let kind = ComponentKind::from_raw(kind_raw);
    let label_end = HEADER_LEN.saturating_add(label_len);
    if label_end > payload.len() {
        return E_SHORT;
    }
    let label = &payload[HEADER_LEN..label_end];
    let Some(desc) = attached_surface(handle) else { return E_SURFACE };
    paint(&desc, x, y, w, h, kind, label);
    STATUS_OK
}

fn attached_surface(handle: u64) -> Option<SurfaceDescriptor> {
    let mut slot = ATTACHED_SURFACE.lock();
    if let Some(attached) = *slot {
        if attached.handle == handle {
            return Some(attached.desc);
        }
    }
    let mut desc = SurfaceDescriptor::default();
    let va = mk_surface_attach(handle, &mut desc);
    if va <= 0 {
        return None;
    }
    if desc.base_va == 0 {
        desc.base_va = va as u64;
    }
    *slot = Some(AttachedSurface { handle, desc });
    Some(desc)
}
