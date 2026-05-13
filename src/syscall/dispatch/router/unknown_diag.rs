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

use core::sync::atomic::{AtomicU64, Ordering};

use crate::syscall::numbers::SyscallNumber;

// One-shot ENOSYS diagnostic per pid. Smoke-only: kept behind the
// `nonos-user-entry-proof` feature so production builds emit nothing.
static SEEN_PIDS: AtomicU64 = AtomicU64::new(0);

pub(super) fn log_first_per_pid(nr: SyscallNumber) {
    let pid = crate::process::current_pid().unwrap_or(0);
    if pid >= 64 {
        return;
    }
    let mask: u64 = 1u64 << pid;
    let prev = SEEN_PIDS.fetch_or(mask, Ordering::Relaxed);
    if prev & mask != 0 {
        return;
    }
    crate::sys::serial::print(b"[SYSCALL-UNKNOWN] pid=");
    crate::sys::serial::print_hex(pid as u64);
    crate::sys::serial::print(b" nr=");
    crate::sys::serial::print_hex(nr as u64);
    crate::sys::serial::println(b"");
}
