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

use super::ops::{create_attestation, generate_proof, verify_proof};
use crate::services::protocol::ServiceOp;
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;
const OP_GENERATE: u8 = 1;
const OP_VERIFY: u8 = 2;
const OP_ATTEST: u8 = 3;

pub(super) fn handle_request(req: ServiceRequest) -> ServiceResponse {
    match req.op {
        ServiceOp::Ping => ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Ioctl => handle_zk_op(req),
        ServiceOp::Query => ServiceResponse::ok(req.seq, alloc::vec![1u8]),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

fn handle_zk_op(req: ServiceRequest) -> ServiceResponse {
    if req.payload.is_empty() {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let op = req.payload[0];
    let data = &req.payload[1..];
    match op {
        OP_GENERATE => generate_proof(req.seq, data),
        OP_VERIFY => verify_proof(req.seq, data),
        OP_ATTEST => create_attestation(req.seq, data),
        _ => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}
