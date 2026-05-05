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
use crate::ipc::nonos_inbox;
use crate::process::current_pid;
use crate::services::registry::lookup_service;

const E_NOENT: i64 = -2;
const E_ACCES: i64 = -13;
const E_FAULT: i64 = -14;
const E_INVAL: i64 = -22;
const E_TIMEDOUT: i64 = -110;

pub fn sys_ipc_send(endpoint: u64, buf: *const u8, len: usize) -> i64 {
    if buf.is_null() || len == 0 {
        return E_INVAL;
    }
    let addr = buf as u64;
    if crate::usercopy::validate_user_read(addr, len).is_err() {
        return E_FAULT;
    }
    let mut data = alloc::vec![0u8; len];
    if crate::usercopy::copy_from_user(addr, &mut data).is_err() {
        return E_FAULT;
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
pub fn sys_ipc_recv(endpoint: u64, buf: *mut u8, len: usize, timeout_ms: u64) -> i64 {
    if buf.is_null() || len == 0 {
        return E_INVAL;
    }
    let addr = buf as u64;
    if crate::usercopy::validate_user_write(addr, len).is_err() {
        return E_FAULT;
    }
    let pid = current_pid().unwrap_or(0);
    let inbox_name = if endpoint == 0 {
        alloc::format!("proc.{}", pid)
    } else {
        let target = alloc::format!("endpoint.{}", endpoint);
        match lookup_service(&target) {
            None => return E_NOENT,
            Some(ep) if ep.pid == pid => target,
            Some(_) => return E_ACCES,
        }
    };
    // No lazy registration on the recv path — `proc.{pid}` is set
    // up by `capsule_spawn::runner` when the process is created, and
    // `endpoint.<ep>` is set up at registration time. A missing
    // inbox here is an architectural error, not a race we paper
    // over by recreating it.
    if !nonos_inbox::exists(&inbox_name) {
        return E_NOENT;
    }
    let start = crate::time::timestamp_millis();
    loop {
        if let Some(msg) = nonos_inbox::try_dequeue_existing(&inbox_name) {
            let copy_len = msg.data.len().min(len);
            if crate::usercopy::copy_to_user(addr, &msg.data[..copy_len]).is_err() {
                return E_FAULT;
            }
            return copy_len as i64;
        }
        let elapsed = crate::time::timestamp_millis().saturating_sub(start);
        if timeout_ms > 0 && elapsed >= timeout_ms {
            return E_TIMEDOUT;
        }
        crate::sched::yield_now();
    }
}

// Send-then-recv. The reply lands in the caller's per-process inbox, not
// on `endpoint.<ep>`; recv with endpoint = 0 to read it. Using `ep` here
// would route the recv through the registry-owned named inbox and deny.
pub fn sys_ipc_call(
    ep: u64,
    req: *const u8,
    req_len: usize,
    resp: *mut u8,
    resp_len: usize,
) -> i64 {
    let send_result = sys_ipc_send(ep, req, req_len);
    if send_result < 0 {
        return send_result;
    }
    sys_ipc_recv(0, resp, resp_len, 5000)
}
