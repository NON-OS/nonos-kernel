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

use super::notify::{register_notification, unregister_notification};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::read_user_value;

#[repr(C)]
#[derive(Clone, Copy)]
struct SigEvent {
    sigev_value: u64,
    sigev_signo: i32,
    sigev_notify: i32,
    _pad: [u64; 6],
}

pub fn handle_mq_notify(mqdes: i32, sevp: u64) -> SyscallResult {
    if mqdes < 100 {
        return errno(9);
    }
    if sevp == 0 {
        unregister_notification(mqdes);
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }
    let sev: SigEvent = match read_user_value(sevp) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let pid = crate::process::current_pid().unwrap_or(0);
    match register_notification(mqdes, sev.sigev_notify, sev.sigev_signo, sev.sigev_value, pid) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => errno(e),
    }
}
