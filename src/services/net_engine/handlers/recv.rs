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
const DEFAULT_MAX_LEN: usize = 4096;

pub(crate) fn handle_recv(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 4 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }

    let conn_id =
        u32::from_le_bytes([req.payload[0], req.payload[1], req.payload[2], req.payload[3]]);

    let max_len = parse_max_len(&req.payload);

    let stack = match get_network_stack() {
        Some(s) => s,
        None => return ServiceResponse::err(req.seq, ERR_NOT_AVAIL),
    };

    match stack.tcp_receive(conn_id, max_len) {
        Ok(buf) => ServiceResponse::ok(req.seq, buf),
        Err(_) => ServiceResponse::ok(req.seq, Vec::new()),
    }
}

fn parse_max_len(payload: &[u8]) -> usize {
    if payload.len() >= 8 {
        u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize
    } else {
        DEFAULT_MAX_LEN
    }
}
