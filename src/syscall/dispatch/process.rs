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

use alloc::vec::Vec;
use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value, copy_from_user, copy_to_user};
use super::{errno, require_capability, parse_string_from_user};

pub fn handle_exit(status: u64) -> SyscallResult {
    #[allow(unused)]
    {
        if let Some(_proc) = crate::process::current_process() {
            crate::process::nonos_core::syscalls::sys_exit(status as i32);
        }
    }
    loop {
        x86_64::instructions::hlt();
    }
}

pub fn handle_getpid() -> SyscallResult {
    if let Err(e) = require_capability(Capability::CoreExec) {
        return e;
    }

    let tgid = crate::process::current_process()
        .map(|p| p.thread_group_id())
        .unwrap_or(0);
    SyscallResult { value: tgid as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_fork() -> SyscallResult {
    if let Err(e) = require_capability(Capability::CoreExec) {
        return e;
    }

    let Some(parent) = crate::process::current_process() else {
        return errno(1);
    };

    match crate::process::fork_process(&parent) {
        Ok(child_pid) => SyscallResult { value: child_pid as i64, capability_consumed: false, audit_required: true },
        Err(_) => errno(12),
    }
}

pub fn handle_execve(pathname: u64, argv: u64, envp: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::CoreExec) {
        return e;
    }

    if pathname == 0 {
        return errno(22);
    }

    let path = match parse_string_from_user(pathname, 4096) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };

    let args = read_string_array(argv);
    let env = read_string_array(envp);

    match crate::process::exec_process(&path, &args, &env) {
        Ok(()) => errno(5),
        Err(_) => errno(2),
    }
}

fn read_string_array(ptr: u64) -> Vec<alloc::string::String> {
    let mut result = Vec::new();
    if ptr == 0 {
        return result;
    }
    for i in 0..256usize {
        let offset = match (i as u64).checked_mul(8) { Some(v) => v, None => break };
        let ptr_addr = match ptr.checked_add(offset) { Some(v) => v, None => break };
        let string_ptr: u64 = match read_user_value(ptr_addr) {
            Ok(v) => v,
            Err(_) => break,
        };
        if string_ptr == 0 { break; }
        if let Ok(s) = parse_string_from_user(string_ptr, 4096) { result.push(s); }
    }
    result
}

pub fn handle_nanosleep(req_ptr: u64, rem_ptr: u64) -> SyscallResult {
    if req_ptr == 0 {
        return errno(22);
    }

    let tv_sec: i64 = match read_user_value(req_ptr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let req_nsec_ptr = match req_ptr.checked_add(8) { Some(v) => v, None => return errno(14) };
    let tv_nsec: i64 = match read_user_value(req_nsec_ptr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 { return errno(22); }
    let sec_ms = (tv_sec as u64).saturating_mul(1000);
    let sleep_ms = sec_ms.saturating_add((tv_nsec as u64) / 1_000_000);
    let Some(proc) = crate::process::current_process() else { return errno(1); };
    let now_ms = crate::time::timestamp_millis();
    let wake_time_ms = now_ms.saturating_add(sleep_ms);

    crate::sched::sleep_until(proc.pid, wake_time_ms);
    crate::sched::yield_cpu();

    let actual_wake_time = crate::time::timestamp_millis();
    let remaining_ms = if actual_wake_time < wake_time_ms {
        wake_time_ms - actual_wake_time
    } else {
        0
    };

    if rem_ptr != 0 && remaining_ms > 0 {
        let rem_sec = (remaining_ms / 1000) as i64;
        let rem_nsec = (remaining_ms % 1000).saturating_mul(1_000_000) as i64;
        let _ = write_user_value(rem_ptr, &rem_sec);
        if let Some(rem_nsec_ptr) = rem_ptr.checked_add(8) {
            let _ = write_user_value(rem_nsec_ptr, &rem_nsec);
        }
        return errno(4);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_yield() -> SyscallResult {
    crate::sched::yield_cpu();
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_ipc_send(channel: u64, buf: u64, len: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::IPC) { return e; }

    if buf == 0 || len == 0 || len > 65536 {
        return errno(22);
    }

    let mut data = alloc::vec![0u8; len as usize];
    if copy_from_user(buf, &mut data).is_err() {
        return errno(14);
    }

    match crate::ipc::send_message(channel as u32, &data) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(crate::ipc::IpcError::ChannelNotFound) => errno(2),
        Err(crate::ipc::IpcError::BufferFull) => errno(11),
        Err(crate::ipc::IpcError::PermissionDenied) => errno(1),
        Err(_) => errno(5),
    }
}

pub fn handle_ipc_recv(channel: u64, buf: u64, max_len: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::IPC) { return e; }

    if buf == 0 || max_len == 0 {
        return errno(22);
    }

    let mut buffer = alloc::vec![0u8; max_len as usize];
    match crate::ipc::recv_message(channel as u32, &mut buffer) {
        Ok(received_len) => {
            if copy_to_user(buf, &buffer[..received_len]).is_err() {
                return errno(14);
            }
            SyscallResult { value: received_len as i64, capability_consumed: false, audit_required: false }
        }
        Err(crate::ipc::IpcError::ChannelNotFound) => errno(2),
        Err(crate::ipc::IpcError::WouldBlock) => errno(11),
        Err(crate::ipc::IpcError::PermissionDenied) => errno(1),
        Err(_) => errno(5),
    }
}

pub fn handle_ipc_create(flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::IPC) { return e; }

    match crate::ipc::create_channel(flags as u32) {
        Ok(channel_id) => SyscallResult { value: channel_id as i64, capability_consumed: false, audit_required: true },
        Err(crate::ipc::IpcError::TooManyChannels) => errno(24),
        Err(crate::ipc::IpcError::PermissionDenied) => errno(1),
        Err(_) => errno(5),
    }
}

pub fn handle_ipc_destroy(channel: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::IPC) { return e; }

    match crate::ipc::destroy_channel(channel as u32) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(crate::ipc::IpcError::ChannelNotFound) => errno(2),
        Err(crate::ipc::IpcError::PermissionDenied) => errno(1),
        Err(_) => errno(5),
    }
}
