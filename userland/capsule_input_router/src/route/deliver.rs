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

use nonos_libc::{mk_ipc_send_to_pid, InputEvent};

use crate::protocol::{encode_delivery, DELIVERY_LEN};

// Encode an event into the NINP envelope and ship it to `target_pid`.
// Returns 1 on success, 0 on send failure (e.g. dead pid). Callers
// fold that into ctx.delivered_count / ctx.dropped_count.
pub fn deliver_one(target_pid: u32, event: &InputEvent) -> u32 {
    if target_pid == 0 {
        return 0;
    }
    let mut frame = [0u8; DELIVERY_LEN];
    encode_delivery(&mut frame, event);
    let rc = mk_ipc_send_to_pid(target_pid, frame.as_ptr(), frame.len());
    if rc < 0 {
        0
    } else {
        1
    }
}
