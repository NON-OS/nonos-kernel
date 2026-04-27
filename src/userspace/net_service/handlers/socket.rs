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

use crate::network::ip::IpAddress;
use crate::network::stack::get_network_stack;
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_NOT_AVAIL: i32 = -99;
const ERR_CONN_REFUSED: i32 = -111;
const ERR_INVAL: i32 = -22;

pub(crate) fn handle_socket(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 6 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }

    let ip = [req.payload[0], req.payload[1], req.payload[2], req.payload[3]];
    let port = u16::from_be_bytes([req.payload[4], req.payload[5]]);

    let stack = match get_network_stack() {
        Some(s) => s,
        None => return ServiceResponse::err(req.seq, ERR_NOT_AVAIL),
    };

    match stack.connect_tcp(IpAddress::V4(ip), port) {
        Ok(id) => {
            let mut data = Vec::with_capacity(4);
            data.extend_from_slice(&id.to_le_bytes());
            ServiceResponse::ok(req.seq, data)
        }
        Err(_) => ServiceResponse::err(req.seq, ERR_CONN_REFUSED),
    }
}
