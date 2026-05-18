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

use nonos_libc::mk_ipc_recv_from;

use crate::frame_pacer;
use crate::protocol::{
    parse, E_BAD_OP, E_INVAL, HDR_LEN, IPC_PAYLOAD_MAX, OP_CURSOR_UPDATE, OP_DAMAGE_COMMIT,
    OP_FOCUS_SET, OP_HEALTHCHECK, OP_INPUT_SUBSCRIBE, OP_SCENE_REMOVE, OP_SCENE_SUBMIT,
};
use crate::server::{handlers, respond};
use crate::state::Context;

const SERVICE_INBOX: u64 = 0;
const RECV_NOWAIT: u64 = 1;

pub fn run(mut ctx: Context) -> ! {
    let mut rx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut tx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    loop {
        drain_ipc(&mut ctx, &mut rx, &mut tx);
        let _ = frame_pacer::tick(&mut ctx);
        let _ = frame_pacer::wait_for_vsync();
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
        dispatch(ctx, sender_pid, req, body, tx);
    }
}

fn dispatch(
    ctx: &mut Context,
    sender_pid: u32,
    req: crate::protocol::Request,
    body: &[u8],
    tx: &mut [u8],
) {
    match req.op {
        OP_HEALTHCHECK if body.is_empty() => handlers::health::handle(sender_pid, &req, tx),
        OP_SCENE_SUBMIT => handlers::scene_submit::handle(ctx, sender_pid, &req, body, tx),
        OP_SCENE_REMOVE => handlers::scene_remove::handle(ctx, sender_pid, &req, body, tx),
        OP_DAMAGE_COMMIT => handlers::damage_commit::handle(ctx, sender_pid, &req, body, tx),
        OP_FOCUS_SET => handlers::focus_set::handle(ctx, sender_pid, &req, body, tx),
        OP_CURSOR_UPDATE => handlers::cursor_update::handle(ctx, sender_pid, &req, body, tx),
        OP_INPUT_SUBSCRIBE if body.is_empty() => {
            handlers::input_subscribe::handle(ctx, sender_pid, &req, tx)
        }
        _ if body.is_empty() => {
            let _ = respond::status(sender_pid, &req, E_BAD_OP, tx);
        }
        _ => {
            let _ = respond::status(sender_pid, &req, E_INVAL, tx);
        }
    }
}
