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

use super::errnos::{ERRNO_ACCES, ERRNO_FAULT, ERRNO_INVAL, ERRNO_NOENT, ERRNO_TIMEDOUT};
use crate::ipc::kernel_ipc::kernel_route_ipc;
use crate::ipc::nonos_inbox;
use crate::process::current_pid;
use crate::services::registry::lookup_service;

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
    let target = alloc::format!("endpoint.{}", endpoint);
    match kernel_route_ipc(pid, &target, &data) {
        Ok(()) => 0,
        Err(e) => e as i64,
    }
}

// Receive contract:
//   endpoint == 0  : default per-process inbox at `proc.<pid>`. No registry
//                    consult. The kernel-side capsule clients post directly
//                    to this inbox and the libc receive loop reads from it.
//   endpoint != 0  : named server inbox at `endpoint.<endpoint>`. The
//                    process must own the endpoint in the service registry
//                    (`registry.pid == current_pid()`). A future per-endpoint
//                    `CapEndpointReceive` would unlock the second arm; the
//                    capability type does not exist yet, so non-owners are
//                    denied with EACCES.
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
    // No lazy registration on the recv path — `proc.{pid}` is set
    // up by `capsule_spawn::runner` when the process is created, and
    // `endpoint.<ep>` is set up at registration time. A missing
    // inbox here is an architectural error, not a race we paper
    // over by recreating it.
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

// Send-then-recv. The reply lands in the caller's per-process inbox, not
// on `endpoint.<ep>`; recv with endpoint = 0 to read it. Using `ep` here
// would route the recv through the registry-owned named inbox and deny.
pub fn sys_ipc_call(
    ep: u64,
    req: u64,
    req_len: usize,
    resp: u64,
    resp_len: usize,
) -> i64 {
    let send_result = sys_ipc_send(ep, req, req_len);
    if send_result < 0 {
        return send_result;
    }
    sys_ipc_recv(0, resp, resp_len, 5000)
}
