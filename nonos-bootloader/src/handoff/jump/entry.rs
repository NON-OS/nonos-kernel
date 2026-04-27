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

const STACK_ALIGNMENT_MASK: u64 = !0xF;

/// Transfer control to kernel. Caller must validate all addresses beforehand.
/// # Safety
/// entry_addr must point to valid kernel code, stack_top to allocated stack,
/// boothandoff_ptr to initialized BootHandoffV1. Never returns.
#[inline(never)]
pub unsafe fn jump_to_kernel(entry_addr: u64, stack_top: u64, boothandoff_ptr: u64) -> ! {
    let stack_aligned = stack_top & STACK_ALIGNMENT_MASK;
    // cli: disable interrupts, cld: clear direction flag, wbinvd: flush caches
    // Zero segment regs and scratch regs per SysV ABI, handoff ptr in rdi
    core::arch::asm!(
        "cli", "cld", "wbinvd",
        "mov rax, {entry}", "mov rcx, {stack}", "mov rdi, {handoff}",
        "xor rdx, rdx", "mov ds, dx", "mov es, dx", "mov fs, dx", "mov gs, dx",
        "mov rsp, rcx", "xor rbp, rbp", "xor rsi, rsi",
        "xor r8, r8", "xor r9, r9", "xor r10, r10", "xor r11, r11",
        "jmp rax",
        entry = in(reg) entry_addr,
        stack = in(reg) stack_aligned,
        handoff = in(reg) boothandoff_ptr,
        options(noreturn)
    );
}
