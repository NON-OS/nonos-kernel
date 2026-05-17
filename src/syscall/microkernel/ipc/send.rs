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

use crate::ipc::kernel_ipc::kernel_route_ipc;
use crate::process::current_pid;
use crate::services::registry::{lookup_port, lookup_service};
use crate::syscall::microkernel::errnos::{ERRNO_FAULT, ERRNO_INVAL};

pub fn sys_ipc_send(endpoint: u64, buf: u64, len: usize) -> i64 {
    if len == 0 {
        return ERRNO_INVAL;
    }
    if crate::usercopy::validate_user_read(buf, len).is_err() {
        return ERRNO_FAULT;
    }
    let mut data = alloc::vec![0u8; len];
    if crate::usercopy::copy_from_user(buf, &mut data).is_err() {
        return ERRNO_FAULT;
    }
    let pid = current_pid().unwrap_or(0);
    let target = resolve_send_target(endpoint);
    match kernel_route_ipc(pid, &target, &data) {
        Ok(()) => 0,
        Err(e) => e as i64,
    }
}

fn resolve_send_target(endpoint: u64) -> alloc::string::String {
    let numeric = alloc::format!("endpoint.{}", endpoint);
    if lookup_service(&numeric).is_some() {
        return numeric;
    }
    lookup_port(endpoint as u32).map(|ep| ep.name).unwrap_or(numeric)
}
