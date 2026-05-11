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

use nonos_libc::{mk_debug, mk_exit, mk_ipc_recv, mk_yield};

const DESKTOP_SHELL_ENDPOINT: u64 = 4410;
const SHELL_OP_WALLPAPER_POLICY: u8 = 1;
const SHELL_OP_DOCK_POLICY: u8 = 2;
const SHELL_OP_MENUBAR_POLICY: u8 = 3;
const SHELL_OP_TRAY_POLICY: u8 = 4;
const SHELL_OP_SPOTLIGHT_POLICY: u8 = 5;
const ENOTSUP: i64 = -95;

fn marker(stage: &[u8]) {
    let mut buf = [0u8; 96];
    let prefix = b"[desktop_shell] ";
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
    marker(b"wallpaper policy owner");
    marker(b"dock policy owner");
    marker(b"menubar policy owner");
    marker(b"tray policy owner");
    marker(b"spotlight policy owner");
    let _ = SHELL_OP_WALLPAPER_POLICY;
    let _ = SHELL_OP_DOCK_POLICY;
    let _ = SHELL_OP_MENUBAR_POLICY;
    let _ = SHELL_OP_TRAY_POLICY;
    let _ = SHELL_OP_SPOTLIGHT_POLICY;
    let mut msg = [0u8; 256];
    loop {
        let rc = mk_ipc_recv(DESKTOP_SHELL_ENDPOINT, msg.as_mut_ptr(), msg.len(), 0);
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
