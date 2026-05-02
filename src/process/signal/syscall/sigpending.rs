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

use crate::process::{current_pid, with_process};
use crate::usercopy::write_user_value;

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const ESRCH: i64 = -3;

pub fn sys_rt_sigpending(set: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    if set == 0 {
        return EFAULT;
    }
    let pid = current_pid().unwrap_or(0);
    let pending = match with_process(pid, |pcb| pcb.signals.lock().get_pending_mask()) {
        Some(p) => p,
        None => return ESRCH,
    };
    if write_user_value(set, &pending).is_err() {
        return EFAULT;
    }
    0
}
