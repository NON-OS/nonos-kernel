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

use super::attach::*;
use super::control::*;
use super::memory::*;
use super::regs::*;
use super::types::*;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;

pub fn handle_ptrace(request: u32, pid: u32, addr: u64, data: u64) -> SyscallResult {
    let result: Result<i64, i32> = match request {
        PTRACE_TRACEME => do_traceme().map(|_| 0i64),
        PTRACE_PEEKTEXT => do_peektext(pid, addr).map(|v| v as i64),
        PTRACE_PEEKDATA => do_peekdata(pid, addr).map(|v| v as i64),
        PTRACE_PEEKUSER => do_peekuser(pid, addr).map(|v| v as i64),
        PTRACE_POKETEXT => do_poketext(pid, addr, data).map(|_| 0i64),
        PTRACE_POKEDATA => do_pokedata(pid, addr, data).map(|_| 0i64),
        PTRACE_POKEUSER => do_pokeuser(pid, addr, data).map(|_| 0i64),
        PTRACE_CONT => do_cont(pid, data as u32).map(|_| 0i64),
        PTRACE_KILL => do_kill(pid).map(|_| 0i64),
        PTRACE_SINGLESTEP => do_singlestep(pid, data as u32).map(|_| 0i64),
        PTRACE_GETREGS => do_getregs(pid, data).map(|_| 0i64),
        PTRACE_SETREGS => do_setregs(pid, data).map(|_| 0i64),
        PTRACE_ATTACH => do_attach(pid).map(|_| 0i64),
        PTRACE_DETACH => do_detach(pid, data as u32).map(|_| 0i64),
        PTRACE_SYSCALL => do_syscall(pid, data as u32).map(|_| 0i64),
        PTRACE_SETOPTIONS => do_setoptions(pid, data as u32).map(|_| 0i64),
        PTRACE_GETEVENTMSG => do_geteventmsg(pid, data).map(|_| 0i64),
        PTRACE_GETREGSET => do_getregset(pid, addr as u32, data).map(|_| 0i64),
        PTRACE_SETREGSET => do_setregset(pid, addr as u32, data).map(|_| 0i64),
        PTRACE_SEIZE => do_seize(pid, data as u32).map(|_| 0i64),
        PTRACE_INTERRUPT => do_interrupt(pid).map(|_| 0i64),
        PTRACE_LISTEN => do_listen(pid).map(|_| 0i64),
        _ => Err(22),
    };
    match result {
        Ok(v) => SyscallResult { value: v, capability_consumed: false, audit_required: true },
        Err(e) => errno(e),
    }
}

pub fn ptrace_report_syscall_entry(pid: u32, syscall_nr: i32) {
    if super::state::is_traced(pid) && super::state::is_syscall_entry(pid) {
        super::state::set_event_msg(pid, syscall_nr as u64);
        let _ = crate::process::stop_process(pid);
    }
}

pub fn ptrace_report_syscall_exit(pid: u32, retval: i64) {
    if super::state::is_traced(pid) && super::state::is_syscall_entry(pid) {
        super::state::set_event_msg(pid, retval as u64);
        super::state::set_syscall_entry(pid, false);
        let _ = crate::process::stop_process(pid);
    }
}
