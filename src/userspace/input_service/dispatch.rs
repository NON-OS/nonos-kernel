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

use alloc::vec::Vec;
use crate::services::{ServiceRequest, ServiceResponse};
use crate::services::protocol::ServiceOp;
use super::handlers::{read_keyboard, read_mouse, handle_status};

const ERR_INVAL: i32 = -22;
const INPUT_KEYBOARD: u8 = 1;
const INPUT_MOUSE: u8 = 2;

pub(super) fn handle_request(req: ServiceRequest) -> ServiceResponse {
    match req.op {
        ServiceOp::Ping => ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Read => handle_read(req),
        ServiceOp::Subscribe => ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Unsubscribe => ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Query => handle_status(req),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

fn handle_read(req: ServiceRequest) -> ServiceResponse {
    if req.payload.is_empty() {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    match req.payload[0] {
        INPUT_KEYBOARD => read_keyboard(req.seq),
        INPUT_MOUSE => read_mouse(req.seq),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}
