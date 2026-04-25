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

use super::util::{ok, resolve_pid};
use crate::process::scheduler as policy;
use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;

pub fn handle_sched_rr_get_interval(pid: i32, tp: u64) -> SyscallResult {
    if tp == 0 {
        return errno(14);
    }
    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };
    let attr = policy::get_sched_attr(target_pid);
    let timeslice_ms = attr.get_timeslice();
    let tv_sec = (timeslice_ms / 1000) as i64;
    let tv_nsec = ((timeslice_ms % 1000) * 1_000_000) as i64;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&tv_sec.to_ne_bytes());
    buf[8..16].copy_from_slice(&tv_nsec.to_ne_bytes());
    if copy_to_user(tp, &buf).is_err() {
        return errno(14);
    }
    ok(0)
}
