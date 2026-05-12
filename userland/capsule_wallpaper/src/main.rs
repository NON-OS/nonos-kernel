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

use nonos_libc::{
    mk_debug, mk_exit, nonos_display_dimensions, nonos_surface_create, nonos_surface_destroy,
    nonos_surface_map, nonos_surface_present_full, NONOS_PIXEL_FMT_ARGB8888,
};

const SOLID_ARGB: u32 = 0xFF20_2030;

fn marker(stage: &[u8]) {
    let mut buf = [0u8; 64];
    let prefix = b"[wallpaper] ";
    let mut n = 0usize;
    let cap = buf.len() - 1;
    for &b in prefix.iter().chain(stage.iter()) {
        if n >= cap {
            break;
        }
        buf[n] = b;
        n += 1;
    }
    buf[n] = b'\n';
    n += 1;
    let _ = mk_debug(buf.as_ptr(), n);
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let mut w: u32 = 0;
    let mut h: u32 = 0;
    let rc = nonos_display_dimensions(0, &mut w as *mut u32, &mut h as *mut u32);
    if rc != 0 || w == 0 || h == 0 {
        marker(b"FAIL display_dimensions");
        mk_exit(1);
    }
    marker(b"display ok");

    let id = nonos_surface_create(w, h, NONOS_PIXEL_FMT_ARGB8888);
    if id < 0 {
        marker(b"FAIL surface_create");
        mk_exit(2);
    }
    marker(b"surface created");

    let base = nonos_surface_map(id as u64);
    if base.is_null() {
        marker(b"FAIL surface_map");
        let _ = nonos_surface_destroy(id as u64);
        mk_exit(3);
    }
    let pixels = base as *mut u32;
    let count = (w as usize) * (h as usize);
    for i in 0..count {
        core::ptr::write_volatile(pixels.add(i), SOLID_ARGB);
    }
    marker(b"surface filled");

    let prc = nonos_surface_present_full(0, id as u64);
    if prc != 0 {
        marker(b"FAIL surface_present");
        let _ = nonos_surface_destroy(id as u64);
        mk_exit(4);
    }
    marker(b"present ok");

    let drc = nonos_surface_destroy(id as u64);
    if drc != 0 {
        marker(b"FAIL surface_destroy");
        mk_exit(5);
    }
    marker(b"PASS");
    mk_exit(0)
}
