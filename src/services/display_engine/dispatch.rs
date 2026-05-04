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

use super::draw::{draw_clear, draw_pixel, draw_rect};
use crate::display::get_framebuffer;
use crate::services::protocol::ServiceOp;
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;
const ERR_NOT_INIT: i32 = -6;
const DRAW_PIXEL: u8 = 1;
const DRAW_RECT: u8 = 2;
const DRAW_CLEAR: u8 = 3;

pub(super) fn handle_request(req: ServiceRequest) -> ServiceResponse {
    match req.op {
        ServiceOp::Ping => ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Write => handle_draw(req),
        ServiceOp::Query => handle_info(req),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

fn handle_draw(req: ServiceRequest) -> ServiceResponse {
    if req.payload.is_empty() {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    match req.payload[0] {
        DRAW_PIXEL => draw_pixel(req.seq, &req.payload[1..]),
        DRAW_RECT => draw_rect(req.seq, &req.payload[1..]),
        DRAW_CLEAR => draw_clear(req.seq, &req.payload[1..]),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

fn handle_info(req: ServiceRequest) -> ServiceResponse {
    match get_framebuffer() {
        Ok(info) => {
            let mut data = Vec::with_capacity(20);
            data.extend_from_slice(&info.width.to_le_bytes());
            data.extend_from_slice(&info.height.to_le_bytes());
            data.extend_from_slice(&info.stride.to_le_bytes());
            data.extend_from_slice(&info.bpp.to_le_bytes());
            ServiceResponse::ok(req.seq, data)
        }
        Err(_) => ServiceResponse::err(req.seq, ERR_NOT_INIT),
    }
}
