// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub fn syscall_nanosleep(req: u64, rem: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_nanosleep(req, rem);
    result.value as u64
}

pub fn syscall_sched_yield(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_yield();
    result.value as u64
}

pub fn syscall_clock_gettime(clk_id: u64, tp: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::timer::handle_clock_gettime(clk_id as i32, tp);
    result.value as u64
}

pub fn syscall_gettimeofday(tv: u64, tz: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::handle_gettimeofday(tv, tz);
    result.value as u64
}

pub fn syscall_alarm(seconds: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    // { SIGALRM not fully implemented (Needs more work) }
    let _ = seconds;
    0
}
