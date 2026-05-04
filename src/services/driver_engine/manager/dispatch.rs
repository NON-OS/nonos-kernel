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

use super::super::framework::{DriverOp, DriverRequest, DriverService};
use super::state::DRIVERS;
use crate::services::protocol::ServiceOp;
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

pub(super) fn handle_request(req: ServiceRequest) -> ServiceResponse {
    let mut guard = DRIVERS.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => return ServiceResponse::err(req.seq, -1),
    };
    dispatch_to_driver(req, state)
}

fn dispatch_to_driver(
    req: ServiceRequest,
    state: &mut super::state::DriverState,
) -> ServiceResponse {
    if req.payload.is_empty() {
        return ServiceResponse::err(req.seq, -1);
    }
    let driver_id = req.payload[0];
    let drv_op = match req.op {
        ServiceOp::Ping => return ServiceResponse::ok(req.seq, Vec::new()),
        ServiceOp::Read => DriverOp::Read,
        ServiceOp::Write => DriverOp::Write,
        ServiceOp::Ioctl => DriverOp::Ioctl,
        _ => return ServiceResponse::err(req.seq, -2),
    };
    let drv_req = build_driver_request(drv_op, &req.payload);
    let drv_resp = match driver_id {
        0 => state.pci.handle(drv_req),
        1 => state.nvme.handle(drv_req),
        2 => state.virtio.handle(drv_req),
        _ => return ServiceResponse::err(req.seq, -3),
    };
    ServiceResponse { seq: req.seq, status: drv_resp.status, payload: drv_resp.data }
}

fn build_driver_request(op: DriverOp, payload: &[u8]) -> DriverRequest {
    DriverRequest {
        op,
        device_id: parse_u32_at(payload, 1),
        offset: parse_u64_at(payload, 5),
        data: payload.get(13..).unwrap_or(&[]).to_vec(),
    }
}

fn parse_u32_at(data: &[u8], start: usize) -> u32 {
    u32::from_le_bytes([
        data.get(start).copied().unwrap_or(0),
        data.get(start + 1).copied().unwrap_or(0),
        data.get(start + 2).copied().unwrap_or(0),
        data.get(start + 3).copied().unwrap_or(0),
    ])
}

fn parse_u64_at(data: &[u8], start: usize) -> u64 {
    u64::from_le_bytes([
        data.get(start).copied().unwrap_or(0),
        data.get(start + 1).copied().unwrap_or(0),
        data.get(start + 2).copied().unwrap_or(0),
        data.get(start + 3).copied().unwrap_or(0),
        data.get(start + 4).copied().unwrap_or(0),
        data.get(start + 5).copied().unwrap_or(0),
        data.get(start + 6).copied().unwrap_or(0),
        data.get(start + 7).copied().unwrap_or(0),
    ])
}
