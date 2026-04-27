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

use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;
const ERR_NOT_FOUND: i32 = -2;

pub(super) fn handle_read(req: ServiceRequest) -> ServiceResponse {
    let (path, _) = match parse_path_request(&req.payload) {
        Some(p) => p,
        None => return ServiceResponse::err(req.seq, ERR_INVAL),
    };
    match crate::fs::read_file(&path) {
        Ok(data) => ServiceResponse::ok(req.seq, data),
        Err(_) => ServiceResponse::err(req.seq, ERR_NOT_FOUND),
    }
}

pub(super) fn handle_write(req: ServiceRequest) -> ServiceResponse {
    let (path, data_start) = match parse_path_request(&req.payload) {
        Some(p) => p,
        None => return ServiceResponse::err(req.seq, ERR_INVAL),
    };
    let data = &req.payload[data_start..];
    if data.len() > MAX_WRITE_SIZE {
        return ServiceResponse::err(req.seq, ERR_INVAL);
    }
    match crate::fs::write_file(&path, data) {
        Ok(()) => ServiceResponse::ok(req.seq, Vec::new()),
        Err(_) => ServiceResponse::err(req.seq, ERR_INVAL),
    }
}

pub(super) fn handle_stat(req: ServiceRequest) -> ServiceResponse {
    let (path, _) = match parse_path_request(&req.payload) {
        Some(p) => p,
        None => return ServiceResponse::err(req.seq, ERR_INVAL),
    };
    let mut statbuf = [0u8; 144];
    let mut path_cstr = Vec::with_capacity(path.len() + 1);
    path_cstr.extend_from_slice(path.as_bytes());
    path_cstr.push(0);
    if crate::fs::stat_file_syscall(path_cstr.as_ptr(), statbuf.as_mut_ptr()) {
        let mut data = Vec::with_capacity(16);
        let st_size = u64::from_ne_bytes(statbuf[48..56].try_into().unwrap_or([0; 8]));
        let st_mode = u32::from_ne_bytes(statbuf[24..28].try_into().unwrap_or([0; 4]));
        data.extend_from_slice(&st_size.to_le_bytes());
        data.extend_from_slice(&st_mode.to_le_bytes());
        ServiceResponse::ok(req.seq, data)
    } else {
        ServiceResponse::err(req.seq, ERR_NOT_FOUND)
    }
}

const MAX_PATH_LEN: usize = 4096;
const MAX_WRITE_SIZE: usize = 1024 * 1024;

fn parse_path_request(payload: &[u8]) -> Option<(alloc::string::String, usize)> {
    if payload.len() < 8 {
        return None;
    }
    let path_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if path_len > MAX_PATH_LEN {
        return None;
    }
    let total_len = 8usize.checked_add(path_len)?;
    if payload.len() < total_len {
        return None;
    }
    let path_bytes = &payload[8..total_len];
    let path = core::str::from_utf8(path_bytes).ok()?;
    Some((alloc::string::String::from(path), total_len))
}
