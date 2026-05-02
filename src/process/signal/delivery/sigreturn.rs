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

use crate::process::signal::frame::parse_from_user_stack;
use crate::process::signal::SIGSEGV;
use crate::process::{current_pid, terminate_current_with_signal, with_process_mut};

pub fn sigreturn_current() -> ! {
    let pid = current_pid().unwrap_or(0);
    let user_rsp = read_user_rsp();
    let frame = match parse_from_user_stack(user_rsp) {
        Ok(f) => f,
        Err(_) => terminate_current_with_signal(SIGSEGV),
    };
    with_process_mut(pid, |pcb| {
        pcb.signals.lock().set_blocked_mask(frame.saved_blocked);
    });
    frame.saved_ctx.resume_user()
}

#[inline]
fn read_user_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: ek@nonos.systems — gs:0x10 is the per-CPU slot the
    // syscall asm shim writes the user RSP to on entry. The kernel GS
    // base has been swapped in by `swapgs` at the same shim and is
    // still active until the eventual sysret/iretq, so this read is
    // safe and produces the user-mode RSP captured at SYSCALL time.
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:0x10",
            out(reg) rsp,
            options(nomem, nostack, preserves_flags),
        );
    }
    rsp
}
