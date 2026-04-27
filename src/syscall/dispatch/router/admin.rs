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

use crate::syscall::dispatch::hardware::*;
use crate::syscall::dispatch::util::errno;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

pub(super) fn dispatch_admin(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    _a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::IoPortRead => handle_io_port_read(a0 as u16),
        SyscallNumber::IoPortWrite => handle_io_port_write(a0 as u16, a1 as u8),
        SyscallNumber::MmioMap => handle_mmio_map(a0, a1, a2),
        SyscallNumber::Iopl => crate::syscall::extended::handle_iopl(a0 as i32),
        SyscallNumber::Ioperm => crate::syscall::extended::handle_ioperm(a0, a1, a2 as i32),
        SyscallNumber::DebugLog => handle_debug_log(a0, a1),
        SyscallNumber::DebugTrace => handle_debug_trace(a0),
        SyscallNumber::Ptrace => {
            crate::syscall::extended::handle_ptrace(a0 as i64, a1 as i64, a2, a3)
        }
        SyscallNumber::AdminReboot => handle_admin_reboot(),
        SyscallNumber::AdminShutdown => handle_admin_shutdown(),
        SyscallNumber::AdminModLoad => handle_admin_mod_load(a0, a1, a2, a3, a4),
        SyscallNumber::AdminCapGrant => handle_admin_cap_grant(a0 as u32, a1, a2),
        SyscallNumber::AdminCapRevoke => handle_admin_cap_revoke(a0 as u32, a1),
        SyscallNumber::Reboot => {
            crate::syscall::extended::handle_reboot(a0 as i32, a1 as i32, a2 as u32, a3)
        }
        SyscallNumber::InitModule => crate::syscall::extended::handle_init_module(a0, a1, a2),
        SyscallNumber::DeleteModule => {
            crate::syscall::extended::handle_delete_module(a0, a1 as u32)
        }
        SyscallNumber::FinitModule => {
            crate::syscall::extended::handle_finit_module(a0 as i32, a1, a2 as i32)
        }
        SyscallNumber::Acct => crate::syscall::extended::handle_acct(a0),
        SyscallNumber::Swapon => crate::syscall::extended::handle_swapon(a0, a1 as i32),
        SyscallNumber::Swapoff => crate::syscall::extended::handle_swapoff(a0),
        SyscallNumber::Quotactl => {
            crate::syscall::extended::handle_quotactl(a0 as u32, a1, a2 as i32, a3)
        }
        SyscallNumber::SchedSetparam => {
            crate::syscall::extended::handle_sched_setparam(a0 as i32, a1)
        }
        SyscallNumber::SchedGetparam => {
            crate::syscall::extended::handle_sched_getparam(a0 as i32, a1)
        }
        SyscallNumber::SchedSetscheduler => {
            crate::syscall::extended::handle_sched_setscheduler(a0 as i32, a1 as i32, a2)
        }
        SyscallNumber::SchedGetscheduler => {
            crate::syscall::extended::handle_sched_getscheduler(a0 as i32)
        }
        SyscallNumber::SchedGetPriorityMax => {
            crate::syscall::extended::handle_sched_get_priority_max(a0 as i32)
        }
        SyscallNumber::SchedGetPriorityMin => {
            crate::syscall::extended::handle_sched_get_priority_min(a0 as i32)
        }
        SyscallNumber::SchedRrGetInterval => {
            crate::syscall::extended::handle_sched_rr_get_interval(a0 as i32, a1)
        }
        SyscallNumber::SchedSetaffinity => {
            crate::syscall::extended::handle_sched_setaffinity(a0 as i32, a1, a2)
        }
        SyscallNumber::SchedGetaffinity => {
            crate::syscall::extended::handle_sched_getaffinity(a0 as i32, a1, a2)
        }
        SyscallNumber::SchedSetattr => {
            crate::syscall::extended::handle_sched_setattr(a0 as i32, a1, a2 as u32)
        }
        SyscallNumber::SchedGetattr => {
            crate::syscall::extended::handle_sched_getattr(a0 as i32, a1, a2 as u32, a3 as u32)
        }
        SyscallNumber::Getpriority => {
            crate::syscall::extended::handle_getpriority(a0 as i32, a1 as u32)
        }
        SyscallNumber::Setpriority => {
            crate::syscall::extended::handle_setpriority(a0 as i32, a1 as u32, a2 as i32)
        }
        SyscallNumber::IoprioSet => {
            crate::syscall::extended::handle_ioprio_set(a0 as i32, a1 as i32, a2 as i32)
        }
        SyscallNumber::IoprioGet => {
            crate::syscall::extended::handle_ioprio_get(a0 as i32, a1 as i32)
        }
        _ => errno(38),
    }
}
