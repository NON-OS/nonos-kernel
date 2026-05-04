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
        // Linux scheduler API has no place in the microkernel ABI.
        // Production scheduler control is microkernel-capability shaped
        // (MkYield + cap-gated priority controls), not Linux sched_*.
        // Numbers retained for `from_u64` totality; dispatch ENOSYS,
        // gate denies.
        SyscallNumber::SchedSetparam
        | SyscallNumber::SchedGetparam
        | SyscallNumber::SchedSetscheduler
        | SyscallNumber::SchedGetscheduler
        | SyscallNumber::SchedGetPriorityMax
        | SyscallNumber::SchedGetPriorityMin
        | SyscallNumber::SchedRrGetInterval
        | SyscallNumber::SchedSetaffinity
        | SyscallNumber::SchedGetaffinity
        | SyscallNumber::SchedSetattr
        | SyscallNumber::SchedGetattr
        | SyscallNumber::Getpriority
        | SyscallNumber::Setpriority
        | SyscallNumber::IoprioSet
        | SyscallNumber::IoprioGet => errno(38),
        _ => errno(38),
    }
}
