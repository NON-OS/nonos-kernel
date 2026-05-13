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

use crate::ipc::nonos_inbox;
use crate::process::current_pid;
use crate::services::registry::lookup_service;
use crate::syscall::microkernel::errnos::{
    ERRNO_ACCES, ERRNO_FAULT, ERRNO_INVAL, ERRNO_NOENT, ERRNO_TIMEDOUT,
};

// Receive contract:
//   endpoint == 0  : default per-process inbox at `proc.<pid>`. No
//                    registry consult.
//   endpoint != 0  : named server inbox at `endpoint.<endpoint>`. The
//                    process must own the endpoint in the service
//                    registry. Non-owners denied with EACCES.
pub fn sys_ipc_recv(endpoint: u64, buf: u64, len: usize, timeout_ms: u64) -> i64 {
    if len == 0 {
        return ERRNO_INVAL;
    }
    if crate::usercopy::validate_user_write(buf, len).is_err() {
        return ERRNO_FAULT;
    }
    let pid = current_pid().unwrap_or(0);
    let inbox_name = if endpoint == 0 {
        alloc::format!("proc.{}", pid)
    } else {
        let target = alloc::format!("endpoint.{}", endpoint);
        match lookup_service(&target) {
            None => return ERRNO_NOENT,
            Some(ep) if ep.pid == pid => target,
            Some(_) => return ERRNO_ACCES,
        }
    };
    if !nonos_inbox::exists(&inbox_name) {
        return ERRNO_NOENT;
    }
    let start = crate::time::timestamp_millis();
    loop {
        if let Some(msg) = nonos_inbox::try_dequeue_existing(&inbox_name) {
            let copy_len = msg.data.len().min(len);
            if crate::usercopy::copy_to_user(buf, &msg.data[..copy_len]).is_err() {
                return ERRNO_FAULT;
            }
            return copy_len as i64;
        }
        let elapsed = crate::time::timestamp_millis().saturating_sub(start);
        if timeout_ms > 0 && elapsed >= timeout_ms {
            return ERRNO_TIMEDOUT;
        }
        crate::sched::yield_now();
    }
}
