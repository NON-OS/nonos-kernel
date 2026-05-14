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

use crate::protocol::{Request, E_NO_LINK, E_OK, HDR_LEN, OP_GET_LINK};
use crate::server::respond::respond;
use crate::state::STATE;

// Wire payload for OP_GET_LINK on success: 1 = up, 0 = down.
pub fn handle(sender_pid: u32, req: &Request, tx: &mut [u8]) {
    if STATE.nic_port() == 0 {
        let _ = respond(sender_pid, OP_GET_LINK, E_NO_LINK, req.request_id, 0, tx);
        return;
    }
    tx[HDR_LEN] = 1;
    let _ = respond(sender_pid, OP_GET_LINK, E_OK, req.request_id, 1, tx);
}
