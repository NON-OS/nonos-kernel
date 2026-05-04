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

use super::handles::{close_handle, open_handle, read_handle, seek_handle, write_handle};
use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;
const ERR_NOENT: i32 = -2;

pub(super) fn handle_open_req(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 13 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let path_len =
        u32::from_le_bytes([req.payload[1], req.payload[2], req.payload[3], req.payload[4]])
            as usize;
    let flags =
        i32::from_le_bytes([req.payload[5], req.payload[6], req.payload[7], req.payload[8]]);
    if req.payload.len() < 13 + path_len {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let path_bytes = &req.payload[13..13 + path_len];
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => return ServiceResponse::err(req.seq, ERR_INVAL),
    };
    match open_handle(path, flags) {
        Some(handle) => ServiceResponse::ok(req.seq, handle.to_le_bytes().to_vec()),
        None => ServiceResponse::err(req.seq, ERR_NOENT),
    }
}

pub(super) fn handle_read_req(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 17 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let handle = u64::from_le_bytes(req.payload[1..9].try_into().unwrap_or([0; 8]));
    let count = u64::from_le_bytes(req.payload[9..17].try_into().unwrap_or([0; 8])) as usize;
    match read_handle(handle, count) {
        Some(data) => ServiceResponse::ok(req.seq, data),
        None => ServiceResponse::err(req.seq, ERR_NOENT),
    }
}

pub(super) fn handle_write_req(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 17 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let handle = u64::from_le_bytes(req.payload[1..9].try_into().unwrap_or([0; 8]));
    let len = u64::from_le_bytes(req.payload[9..17].try_into().unwrap_or([0; 8])) as usize;
    if req.payload.len() < 17 + len {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let data = &req.payload[17..17 + len];
    match write_handle(handle, data) {
        Some(written) => ServiceResponse::ok(req.seq, (written as u64).to_le_bytes().to_vec()),
        None => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

pub(super) fn handle_close_req(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 9 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let handle = u64::from_le_bytes(req.payload[1..9].try_into().unwrap_or([0; 8]));
    close_handle(handle);
    ServiceResponse::ok(req.seq, Vec::new())
}

pub(super) fn handle_seek_req(req: ServiceRequest) -> ServiceResponse {
    if req.payload.len() < 18 {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    let handle = u64::from_le_bytes(req.payload[1..9].try_into().unwrap_or([0; 8]));
    let offset = i64::from_le_bytes(req.payload[9..17].try_into().unwrap_or([0; 8]));
    let whence = req.payload[17];
    match seek_handle(handle, offset, whence) {
        Some(new_pos) => ServiceResponse::ok(req.seq, (new_pos as u64).to_le_bytes().to_vec()),
        None => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}
