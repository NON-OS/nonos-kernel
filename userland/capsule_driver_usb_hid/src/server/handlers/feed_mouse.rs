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

use crate::protocol::{Request, E_INVAL, MOUSE_REPORT_MAX, MOUSE_REPORT_MIN};
use crate::server::respond;
use crate::state::State;

pub fn handle(state: &mut State, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() < MOUSE_REPORT_MIN || body.len() > MOUSE_REPORT_MAX {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    state.mouse.feed(body);
    state.mouse_reports = state.mouse_reports.wrapping_add(1);
    let _ = respond::status(sender_pid, req, 0, tx);
}
