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

extern crate alloc;

use crate::network::stack::get_network_stack;
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_NOT_AVAIL: i32 = -99;
const ERR_INVAL: i32 = -22;

pub(crate) fn handle_send(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 4 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }

    let conn_id =
        u32::from_le_bytes([req.payload[0], req.payload[1], req.payload[2], req.payload[3]]);

    let data = &req.payload[4..];

    let stack = match get_network_stack() {
        Some(s) => s,
        None => return ServiceResponse::err(req.seq, ERR_NOT_AVAIL),
    };

    match stack.tcp_send(conn_id, data) {
        Ok(n) => {
            let mut resp = Vec::with_capacity(4);
            resp.extend_from_slice(&(n as u32).to_le_bytes());
            ServiceResponse::ok(req.seq, resp)
        }
        Err(_) => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}
