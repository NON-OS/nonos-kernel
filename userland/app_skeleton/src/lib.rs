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

mod app;
mod compositor_client;
mod discover;
mod input;
mod surface;
mod wm_client;

pub use app::{App, Frame, InputEvent, WindowCfg, KIND_BUTTON_DOWN, KIND_KEY_DOWN};

use nonos_libc::{mk_debug, mk_exit, mk_ipc_recv_from, mk_yield};

pub fn marker(prefix: &[u8], stage: &[u8]) {
    let mut buf = [0u8; 96];
    let mut n = 0usize;
    for &b in prefix.iter().chain(stage.iter()) {
        if n >= buf.len() - 1 {
            break;
        }
        buf[n] = b;
        n += 1;
    }
    buf[n] = b'\n';
    n += 1;
    let _ = mk_debug(buf.as_ptr(), n);
}

fn paint<A: App>(app: &mut A, s: &surface::Surface) {
    let stride_px = s.stride / 4;
    let px = surface::pixels(s);
    let mut f = Frame { buf: px, stride: stride_px, width: s.width, height: s.height };
    app.render(&mut f);
}

pub fn run<A: App>(prefix: &'static [u8], mut app: A) -> ! {
    marker(prefix, b"start");
    let cfg = app.window();
    let Some(compositor) = discover::lookup(b"compositor") else {
        marker(prefix, b"compositor not announced");
        mk_exit(2);
    };
    let mut rid: u32 = 1;
    if let Some(wm) = discover::lookup(b"wm") {
        let _ = wm_client::open_window(wm, rid, 1, cfg.x, cfg.y, cfg.width, cfg.height);
        rid += 1;
    }
    let Some(surf) = surface::alloc(cfg.width, cfg.height) else {
        marker(prefix, b"surface alloc failed");
        mk_exit(2);
    };
    let _ = compositor_client::input_subscribe(compositor, rid);
    rid += 1;
    app.init();
    paint(&mut app, &surf);
    if compositor_client::scene_submit(
        compositor, rid, surf.handle, cfg.x, cfg.y, cfg.width, cfg.height, cfg.z,
    ) {
        marker(prefix, b"window_open id=1");
    }
    rid += 1;
    let mut ib = [0u8; 64];
    loop {
        let mut sender: u32 = 0;
        let n = mk_ipc_recv_from(0, ib.as_mut_ptr(), ib.len(), 16, &mut sender as *mut u32);
        let mut repaint = false;
        if n >= 32 {
            if let Some(ev) = input::decode(&ib[..n as usize]) {
                repaint = app.on_input(ev);
            }
        }
        if repaint {
            paint(&mut app, &surf);
            let _ = compositor_client::scene_submit(
                compositor, rid, surf.handle, cfg.x, cfg.y, cfg.width, cfg.height, cfg.z,
            );
            rid = rid.wrapping_add(1).max(1);
        }
        let _ = mk_yield();
    }
}
