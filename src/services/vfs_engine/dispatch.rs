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

use super::handle_ops::{
    handle_close_req, handle_open_req, handle_read_req, handle_seek_req, handle_write_req,
};
use super::handlers::{handle_read, handle_stat, handle_write};
use crate::services::protocol::ServiceOp;
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;

pub(super) fn handle_request(req: ServiceRequest) -> ServiceResponse {
    match req.op {
        ServiceOp::Ping => ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Open => handle_open_req(req),
        ServiceOp::Close => handle_close_req(req),
        ServiceOp::Read => dispatch_read(req),
        ServiceOp::Write => dispatch_write(req),
        ServiceOp::Query => handle_stat(req),
        ServiceOp::Ioctl => handle_seek_req(req),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

fn dispatch_read(req: ServiceRequest) -> ServiceResponse {
    if !req.payload.is_empty() && req.payload[0] == 0x02 {
        handle_read_req(req)
    } else {
        handle_read(req)
    }
}

fn dispatch_write(req: ServiceRequest) -> ServiceResponse {
    if !req.payload.is_empty() && req.payload[0] == 0x03 {
        handle_write_req(req)
    } else {
        handle_write(req)
    }
}
