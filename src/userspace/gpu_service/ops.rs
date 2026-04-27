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

use crate::drivers::gpu;
use crate::services::ServiceResponse;
use alloc::vec::Vec;

const ERR_GPU: i32 = -102;
const ERR_INVAL: i32 = -22;

pub(super) fn gpu_init(seq: u32) -> ServiceResponse {
    match gpu::init_gpu() {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_GPU),
    }
}

pub(super) fn gpu_set_mode(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 4 {
        return ServiceResponse::err(seq, ERR_INVAL);
    }
    let w = u16::from_le_bytes([data[0], data[1]]);
    let h = u16::from_le_bytes([data[2], data[3]]);
    match gpu::set_mode_32bpp(w, h) {
        Ok(_) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_GPU),
    }
}

pub(super) fn gpu_clear(seq: u32, data: &[u8]) -> ServiceResponse {
    let color =
        if data.len() >= 4 { u32::from_le_bytes([data[0], data[1], data[2], data[3]]) } else { 0 };
    gpu::clear_screen(color);
    ServiceResponse::ok(seq, Vec::new())
}

pub(super) fn gpu_status(seq: u32) -> ServiceResponse {
    let init = gpu::is_initialized();
    ServiceResponse::ok(seq, alloc::vec![init as u8])
}

pub(super) fn gpu_get_mode(seq: u32) -> ServiceResponse {
    if let Some((w, h)) = gpu::get_dimensions() {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&w.to_le_bytes());
        out.extend_from_slice(&h.to_le_bytes());
        ServiceResponse::ok(seq, out)
    } else {
        ServiceResponse::err(seq, ERR_GPU)
    }
}
