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

use alloc::vec;

use nonos_libc::{mk_display_vsync_wait, mk_ipc_recv_from};

use crate::protocol::{
    parse, E_BAD_OP, E_INVAL, HDR_LEN, IPC_PAYLOAD_MAX, OP_FADE, OP_GET_WALLPAPER, OP_HEALTHCHECK,
    OP_SET_POLICY, OP_SET_WALLPAPER,
};
use crate::server::{handlers, respond, tick};
use crate::state::Context;

const SERVICE_INBOX: u64 = 0;
const RECV_NOWAIT: u64 = 1;

pub fn run(mut ctx: Context) -> ! {
    let mut rx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut tx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    loop {
        drain_ipc(&mut ctx, &mut rx, &mut tx);
        if !tick::tick(&mut ctx) {
            let _ = mk_display_vsync_wait(0);
        }
    }
}

fn drain_ipc(ctx: &mut Context, rx: &mut [u8], tx: &mut [u8]) {
    loop {
        let mut sender_pid = 0u32;
        let n =
            mk_ipc_recv_from(SERVICE_INBOX, rx.as_mut_ptr(), rx.len(), RECV_NOWAIT, &mut sender_pid);
        if n <= 0 || sender_pid == 0 {
            return;
        }
        let (req, body) = match parse(&rx[..n as usize]) {
            Ok(parsed) => parsed,
            Err((code, req)) => {
                let _ = respond::status(sender_pid, &req, code, tx);
                continue;
            }
        };
        match req.op {
            OP_HEALTHCHECK if body.is_empty() => handlers::health::handle(sender_pid, &req, tx),
            OP_SET_WALLPAPER => handlers::set_wallpaper::handle(ctx, sender_pid, &req, body, tx),
            OP_GET_WALLPAPER if body.is_empty() => {
                handlers::get_wallpaper::handle(ctx, sender_pid, &req, tx)
            }
            OP_SET_POLICY => handlers::set_policy::handle(ctx, sender_pid, &req, body, tx),
            OP_FADE => handlers::fade::handle(ctx, sender_pid, &req, body, tx),
            _ if body.is_empty() => {
                let _ = respond::status(sender_pid, &req, E_BAD_OP, tx);
            }
            _ => {
                let _ = respond::status(sender_pid, &req, E_INVAL, tx);
            }
        }
    }
}
