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
    mk_debug, mk_exit, mk_ipc_recv, mk_yield, nonos_surface_create, nonos_surface_destroy,
    nonos_surface_map, NONOS_PIXEL_FMT_ARGB8888,
};

const TOOLKIT_ENDPOINT: u64 = 4610;
const TOOLKIT_OP_THEME_APPLY: u8 = 1;
const TOOLKIT_OP_ANIMATION_TICK: u8 = 2;
const TOOLKIT_OP_COMPONENT_RENDER: u8 = 3;
const ENOTSUP: i64 = -95;
const TOOLKIT_SURFACE_W: u32 = 8;
const TOOLKIT_SURFACE_H: u32 = 8;
const TOOLKIT_THEME_ARGB: u32 = 0xFF20_2A38;

fn marker(stage: &[u8]) {
    let mut buf = [0u8; 96];
    let prefix = b"[toolkit] ";
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
    marker(b"theme policy owner");
    marker(b"animation policy owner");
    marker(b"component policy owner");
    let _ = TOOLKIT_OP_THEME_APPLY;
    let _ = TOOLKIT_OP_ANIMATION_TICK;
    let _ = TOOLKIT_OP_COMPONENT_RENDER;
    let sid = nonos_surface_create(TOOLKIT_SURFACE_W, TOOLKIT_SURFACE_H, NONOS_PIXEL_FMT_ARGB8888);
    if sid >= 0 {
        let base = nonos_surface_map(sid as u64) as *mut u32;
        if !base.is_null() {
            let count = (TOOLKIT_SURFACE_W as usize) * (TOOLKIT_SURFACE_H as usize);
            for i in 0..count {
                core::ptr::write_volatile(base.add(i), TOOLKIT_THEME_ARGB);
            }
            marker(b"surface render route");
        }
        let _ = nonos_surface_destroy(sid as u64);
    }
    let mut msg = [0u8; 256];
    loop {
        let rc = mk_ipc_recv(TOOLKIT_ENDPOINT, msg.as_mut_ptr(), msg.len(), 0);
        if rc == ENOTSUP {
            marker(b"ipc parked");
            mk_exit(0);
        }
        if rc < 0 {
            let _ = mk_yield();
            continue;
        }
        let _ = mk_yield();
    }
}
