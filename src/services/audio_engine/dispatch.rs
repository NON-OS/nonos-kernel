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

use super::ops::{audio_init, audio_pause, audio_play, audio_resume, audio_status, audio_stop};
use crate::services::protocol::ServiceOp;
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;
const OP_INIT: u8 = 1;
const OP_PLAY: u8 = 2;
const OP_PAUSE: u8 = 3;
const OP_RESUME: u8 = 4;
const OP_STOP: u8 = 5;
const OP_STATUS: u8 = 6;

pub(super) fn handle_request(req: ServiceRequest) -> ServiceResponse {
    match req.op {
        ServiceOp::Ping => ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Ioctl => handle_audio_op(req),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

fn handle_audio_op(req: ServiceRequest) -> ServiceResponse {
    if req.payload.is_empty() {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }

    let op = req.payload[0];
    let data = &req.payload[1..];

    match op {
        OP_INIT => audio_init(req.seq),
        OP_PLAY => audio_play(req.seq, data),
        OP_PAUSE => audio_pause(req.seq),
        OP_RESUME => audio_resume(req.seq),
        OP_STOP => audio_stop(req.seq),
        OP_STATUS => audio_status(req.seq),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}
