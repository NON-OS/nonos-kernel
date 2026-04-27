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

use super::types::RobustListHead;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::write_user_value;

pub fn handle_get_robust_list(pid: i32, head_ptr: u64, len_ptr: u64) -> SyscallResult {
    if head_ptr == 0 || len_ptr == 0 {
        return errno(14);
    }
    let target_pid =
        if pid == 0 { crate::process::current_pid().unwrap_or(1) as u64 } else { pid as u64 };
    match RobustListHead::get(target_pid) {
        Some((head, len)) => {
            if write_user_value(head_ptr, &head).is_err() {
                return errno(14);
            }
            let len_val = len as u64;
            if write_user_value(len_ptr, &len_val).is_err() {
                return errno(14);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        None => errno(22),
    }
}
