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

use super::contract::{dispatch as contract_dispatch, SyscallArgs};
use super::numbers::SyscallNumber;
use super::types::errnos;

#[inline(always)]
fn ret_errno(e: i32) -> u64 {
    (-(e as i64)) as u64
}

#[inline(always)]
pub fn handle_syscall(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let Some(number) = SyscallNumber::from_u64(id) else {
        return ret_errno(errnos::ENOSYS);
    };
    contract_dispatch(number, SyscallArgs::new([a0, a1, a2, a3, a4, a5])).value as u64
}

// Legacy entry. Reads syscall regs after the Rust prologue, which is
// fragile against codegen; only kept for callers that hit this symbol
// directly. The production path is the asm shim
// `crate::arch::x86_64::asm::syscall_entry_asm` (arch/x86_64/asm/syscall.S).
#[no_mangle]
pub extern "C" fn handle_interrupt() {
    // SAFETY: ek@nonos.systems — the inline asm reads the syscall ABI
    // registers (rax, rdi, rsi, rdx, r10, r8, r9) and stores them into
    // local variables. The unsafety is intrinsic to inline asm; the
    // operands and clobbers accurately describe the access pattern.
    unsafe {
        let (rax, rdi, rsi, rdx, r10, r8, r9): (u64, u64, u64, u64, u64, u64, u64);
        ::core::arch::asm!(
            "mov {rax}, rax",
            "mov {rdi}, rdi",
            "mov {rsi}, rsi",
            "mov {rdx}, rdx",
            "mov {r10}, r10",
            "mov {r8},  r8",
            "mov {r9},  r9",
            rax = out(reg) rax,
            rdi = out(reg) rdi,
            rsi = out(reg) rsi,
            rdx = out(reg) rdx,
            r10 = out(reg) r10,
            r8  = out(reg) r8,
            r9  = out(reg) r9,
            options(nostack, preserves_flags),
        );
        let res = handle_syscall(rax, rdi, rsi, rdx, r10, r8, r9);
        ::core::arch::asm!("mov rax, {res}", res = in(reg) res, options(nostack, preserves_flags));
    }
}
