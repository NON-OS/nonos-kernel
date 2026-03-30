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

mod file_fs;
mod memory;
mod process;
mod signal;
mod network;
mod time;
mod ipc_crypto;
mod admin;

use core::sync::atomic::Ordering;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;
use super::audit::{audit_syscall, SYSCALL_STATS};
use super::util::errno;

pub fn handle_syscall_dispatch(syscall: SyscallNumber, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> SyscallResult {
    SYSCALL_STATS.total_calls.fetch_add(1, Ordering::Relaxed);
    let result = dispatch_syscall(syscall, a0, a1, a2, a3, a4, a5);
    if result.value >= 0 { SYSCALL_STATS.successful_calls.fetch_add(1, Ordering::Relaxed); }
    else { SYSCALL_STATS.failed_calls.fetch_add(1, Ordering::Relaxed); if result.value == -1 { SYSCALL_STATS.permission_denied.fetch_add(1, Ordering::Relaxed); } }
    if result.audit_required { audit_syscall(syscall, [a0, a1, a2, a3], &result); }
    result
}

fn dispatch_syscall(syscall: SyscallNumber, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> SyscallResult {
    let num = syscall as u64;
    if num <= 130 { return file_fs::dispatch_file_fs(syscall, a0, a1, a2, a3, a4, a5); }
    if num <= 145 { return memory::dispatch_memory(syscall, a0, a1, a2, a3, a4, a5); }
    if num <= 178 { return process::dispatch_process(syscall, a0, a1, a2, a3, a4, a5); }
    if num <= 161 { return signal::dispatch_signal(syscall, a0, a1, a2, a3, a4, a5); }
    if num <= 275 { return network::dispatch_network(syscall, a0, a1, a2, a3, a4, a5); }
    if num <= 239 { return time::dispatch_time(syscall, a0, a1, a2, a3, a4, a5); }
    if num <= 909 { return ipc_crypto::dispatch_ipc_crypto(syscall, a0, a1, a2, a3, a4, a5); }
    if num <= 1204 { return admin::dispatch_admin(syscall, a0, a1, a2, a3, a4, a5); }
    errno(38)
}
