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

pub fn syscall_rt_sigaction(sig: u64, act: u64, oact: u64, sigsetsize: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::signals::syscalls::handle_rt_sigaction(sig, act, oact, sigsetsize);
    result.value as u64
}

pub fn syscall_rt_sigprocmask(how: u64, set: u64, oldset: u64, sigsetsize: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::signals::syscalls::handle_rt_sigprocmask(how, set, oldset, sigsetsize);
    result.value as u64
}

pub fn syscall_rt_sigreturn(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::signals::syscalls::handle_rt_sigreturn();
    result.value as u64
}

pub fn syscall_kill(pid: u64, sig: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::signals::send_signal(pid as u32, sig as u32);
    result.value as u64
}
