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

use super::perm::may_signal;
use crate::process::signal::constants::SIGRTMAX;
use crate::process::signal::send::send_signal;

const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const ESRCH: i64 = -3;

pub fn sys_tkill(tid: u64, sig: u64) -> i64 {
    if sig > SIGRTMAX as u64 {
        return EINVAL;
    }
    let target = tid as u32;
    if !may_signal(target) {
        return EPERM;
    }
    match send_signal(target, sig as u32) {
        Ok(()) => 0,
        Err(_) => ESRCH,
    }
}
