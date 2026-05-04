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

use crate::apps;
use crate::services::ServiceResponse;
use alloc::vec::Vec;

const ERR_APPS: i32 = -103;

pub(super) fn app_start(seq: u32, data: &[u8]) -> ServiceResponse {
    let name = core::str::from_utf8(data).unwrap_or("");
    match apps::start_app(name) {
        Ok(id) => {
            let mut out = Vec::with_capacity(8);
            out.extend_from_slice(&id.as_u64().to_le_bytes());
            ServiceResponse::ok(seq, out)
        }
        Err(_) => ServiceResponse::err(seq, ERR_APPS),
    }
}

pub(super) fn app_stop(seq: u32, data: &[u8]) -> ServiceResponse {
    let name = core::str::from_utf8(data).unwrap_or("");
    match apps::stop_app(name) {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_APPS),
    }
}

pub(super) fn app_suspend(seq: u32, data: &[u8]) -> ServiceResponse {
    let name = core::str::from_utf8(data).unwrap_or("");
    match apps::suspend_app(name) {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_APPS),
    }
}

pub(super) fn app_resume(seq: u32, data: &[u8]) -> ServiceResponse {
    let name = core::str::from_utf8(data).unwrap_or("");
    match apps::resume_app(name) {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_APPS),
    }
}

pub(super) fn app_list(seq: u32) -> ServiceResponse {
    let list = apps::list_apps();
    let mut out = Vec::new();
    for name in list {
        out.extend_from_slice(name.as_bytes());
        out.push(0);
    }
    ServiceResponse::ok(seq, out)
}
