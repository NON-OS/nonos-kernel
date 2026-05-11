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

const COMPOSITOR_ENDPOINT: u64 = 4310;
const COMPOSITOR_OP_SCENE_SUBMIT: u8 = 1;
const COMPOSITOR_OP_DAMAGE_COMMIT: u8 = 2;
const COMPOSITOR_OP_CURSOR_UPDATE: u8 = 3;
const ENOTSUP: i64 = -95;

fn marker(stage: &[u8]) {
    let mut buf = [0u8; 96];
    let prefix = b"[compositor] ";
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
    marker(b"boot");
    marker(b"scene owner");
    marker(b"damage owner");
    marker(b"cursor owner");
    let _ = COMPOSITOR_OP_SCENE_SUBMIT;
    let _ = COMPOSITOR_OP_DAMAGE_COMMIT;
    let _ = COMPOSITOR_OP_CURSOR_UPDATE;
    let mut msg = [0u8; 256];
    loop {
        let rc = mk_ipc_recv(COMPOSITOR_ENDPOINT, msg.as_mut_ptr(), msg.len(), 0);
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
