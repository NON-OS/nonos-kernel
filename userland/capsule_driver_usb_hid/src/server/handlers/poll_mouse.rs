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

use crate::protocol::{Request, HDR_LEN, MAX_EVENTS, MOUSE_EVENT_WIRE_LEN, STATUS_LEN};
use crate::server::respond;
use crate::state::State;

pub fn handle(state: &mut State, sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let base = HDR_LEN + STATUS_LEN;
    let mut count = 0usize;
    while count < MAX_EVENTS {
        let Some(event) = state.mouse.pop() else { break };
        let off = base + 4 + count * MOUSE_EVENT_WIRE_LEN;
        event.write_wire(&mut tx[off..off + MOUSE_EVENT_WIRE_LEN]);
        count += 1;
    }
    tx[base..base + 4].copy_from_slice(&(count as u32).to_le_bytes());
    let body_len = 4 + count * MOUSE_EVENT_WIRE_LEN;
    let _ = respond::payload(sender_pid, req, body_len, tx);
}
