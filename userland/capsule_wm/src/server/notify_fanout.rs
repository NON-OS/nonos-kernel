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

use nonos_libc::mk_ipc_send_to_pid;

use crate::protocol::{encode_notify, NOTIFY_LEN};
use crate::state::Context;

// Fans an opened/closed event out to every lifecycle subscriber.
// Failures are swallowed (subscriber pid may be dead); the wm
// just keeps the subscription slot for retry on the next event.
pub fn broadcast(ctx: &Context, event_kind: u32, owner_pid: u32, window_id: u32, x: u32, y: u32) {
    let mut frame = [0u8; NOTIFY_LEN];
    encode_notify(&mut frame, event_kind, owner_pid, window_id, x, y);
    for pid in ctx.subscriptions.iter() {
        let _ = mk_ipc_send_to_pid(pid, frame.as_ptr(), frame.len());
    }
}
