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

#![no_std]
#![no_main]

extern crate alloc;

mod animation;
mod component_dispatch;
mod components;
mod design;
mod font;
mod image;
mod protocol;
mod qr;
mod server;
mod theme;

use nonos_libc::{
    heap_init, mk_debug, mk_exit, nonos_display_dimensions, nonos_surface_create,
    nonos_surface_destroy, nonos_surface_map, HeapError, NONOS_PIXEL_FMT_ARGB8888,
};

use protocol::{
    TOOLKIT_ENDPOINT, TOOLKIT_OP_ANIMATION_TICK, TOOLKIT_OP_COMPONENT_RENDER,
    TOOLKIT_OP_THEME_APPLY,
};

const TOOLKIT_SELFTEST_REQUEST_ID: u32 = 1;
const TOOLKIT_SELFTEST_W: u32 = 64;
const TOOLKIT_SELFTEST_H: u32 = 32;

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    match heap_init() {
        Ok(()) | Err(HeapError::AlreadyInitialized) => {}
        Err(_) => mk_exit(1),
    }
    emit_policy_markers();
    surface_route_probe();
    let _ = TOOLKIT_ENDPOINT;
    let _ = TOOLKIT_SELFTEST_REQUEST_ID;
    server::runner::run();
}

fn emit_policy_markers() {
    mk_debug(b"theme policy owner".as_ptr(), b"theme policy owner".len());
    mk_debug(b"animation policy owner".as_ptr(), b"animation policy owner".len());
    mk_debug(b"component policy owner".as_ptr(), b"component policy owner".len());
    let _ = (TOOLKIT_OP_THEME_APPLY, TOOLKIT_OP_ANIMATION_TICK, TOOLKIT_OP_COMPONENT_RENDER);
}

fn surface_route_probe() {
    let mut display_w = 0u32;
    let mut display_h = 0u32;
    if nonos_display_dimensions(0, &mut display_w, &mut display_h) < 0 {
        display_w = TOOLKIT_SELFTEST_W;
        display_h = TOOLKIT_SELFTEST_H;
    }
    let w = display_w.clamp(1, TOOLKIT_SELFTEST_W);
    let h = display_h.clamp(1, TOOLKIT_SELFTEST_H);
    let handle = nonos_surface_create(w, h, NONOS_PIXEL_FMT_ARGB8888);
    if handle <= 0 {
        return;
    }
    let base = nonos_surface_map(handle as u64);
    if !base.is_null() {
        let words = (w as usize).saturating_mul(h as usize);
        let pixels = unsafe { core::slice::from_raw_parts_mut(base as *mut u32, words) };
        for px in pixels.iter_mut() {
            *px = 0xFF20_2430;
        }
        mk_debug(b"surface render route".as_ptr(), b"surface render route".len());
    }
    let _ = nonos_surface_destroy(handle as u64);
}
