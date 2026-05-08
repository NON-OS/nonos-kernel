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

use crate::process::context::Context;
use crate::process::signal::delivery::run_on_syscall_return;

#[repr(C)]
pub struct SyscallSavedFrame {
    pub rax: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub rcx: u64,
    pub r11: u64,
    pub rbp: u64,
}

#[no_mangle]
pub extern "C" fn syscall_return_signal_hook(frame: *const SyscallSavedFrame) {
    // SAFETY: ek@nonos.systems — after the entry shim drops the
    // stack-passed sixth argument and the saved syscall number, it
    // pushes the syscall return value on top of the still-saved
    // r8/r9/r10/rcx/r11/rbp set. The layout starting at `frame` is
    // exactly the seven u64 fields of `SyscallSavedFrame`.
    let frame = unsafe { &*frame };
    run_on_syscall_return(|| capture_user_context(frame));
}

fn capture_user_context(frame: &SyscallSavedFrame) -> Context {
    let user_rsp = read_user_rsp();
    let (rbx, r12, r13, r14, r15) = read_callee_saved();
    Context {
        rax: frame.rax,
        rbx,
        rcx: frame.rcx,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rbp: frame.rbp,
        rsp: user_rsp,
        r8: frame.r8,
        r9: frame.r9,
        r10: frame.r10,
        r11: frame.r11,
        r12,
        r13,
        r14,
        r15,
        rip: frame.rcx,
        rflags: frame.r11,
    }
}

#[inline]
fn read_user_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: ek@nonos.systems — gs:0x28 is the per-CPU slot the entry
    // shim wrote the user RSP to before switching stacks. Kernel GS is
    // active across this hook, so the read targets the right base.
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:0x28",
            out(reg) rsp,
            options(nomem, nostack, preserves_flags),
        );
    }
    rsp
}

#[inline]
fn read_callee_saved() -> (u64, u64, u64, u64, u64) {
    let rbx: u64;
    let r12: u64;
    let r13: u64;
    let r14: u64;
    let r15: u64;
    // SAFETY: ek@nonos.systems — extern "C" preserves rbx/r12-r15
    // across the call into this hook, so at this point those registers
    // still hold the user-mode values they had at SYSCALL entry. Each
    // explicit `mov` captures the live register before any further
    // Rust code can clobber it.
    unsafe {
        core::arch::asm!(
            "mov {0}, rbx",
            "mov {1}, r12",
            "mov {2}, r13",
            "mov {3}, r14",
            "mov {4}, r15",
            out(reg) rbx,
            out(reg) r12,
            out(reg) r13,
            out(reg) r14,
            out(reg) r15,
            options(nomem, nostack, preserves_flags),
        );
    }
    (rbx, r12, r13, r14, r15)
}
