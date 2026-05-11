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

use nonos_libc::{mk_debug, mk_exit, mk_ipc_call, mk_ipc_recv, mk_yield};

const APP_ABOUT_ENDPOINT: u64 = 4710;
const TOOLKIT_ENDPOINT: u64 = 4610;
const APP_OP_UI_FRAME: u8 = 1;
const ENOTSUP: i64 = -95;

fn marker(stage: &[u8]) {
    let mut buf = [0u8; 96];
    let prefix = b"[app_about] ";
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
    marker(b"app ui owner");
    let req = [APP_OP_UI_FRAME];
    let mut resp = [0u8; 16];
    let _ = mk_ipc_call(TOOLKIT_ENDPOINT, req.as_ptr(), req.len(), resp.as_mut_ptr(), resp.len());
    marker(b"toolkit ui route");
    let mut msg = [0u8; 256];
    loop {
        let rc = mk_ipc_recv(APP_ABOUT_ENDPOINT, msg.as_mut_ptr(), msg.len(), 0);
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
