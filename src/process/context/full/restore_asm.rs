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

use super::definition::Context;

// Naked context-restore for kernel-mode resume. Layout offsets match
// `Context` (see definition.rs); rsp/rip/rflags are loaded from the
// caller-prepared safe context. Diverges via `ret` after restoring sp
// and the iretq-style frame.
#[unsafe(naked)]
pub(super) extern "C" fn context_restore_asm(_ctx: *const Context) -> ! {
    core::arch::naked_asm!(
        "mov rax, [rdi + 0]",
        "mov rbx, [rdi + 8]",
        "mov rcx, [rdi + 16]",
        "mov rdx, [rdi + 24]",
        "mov rsi, [rdi + 32]",
        "mov rbp, [rdi + 48]",
        "mov r8, [rdi + 64]",
        "mov r9, [rdi + 72]",
        "mov r10, [rdi + 80]",
        "mov r11, [rdi + 88]",
        "mov r12, [rdi + 96]",
        "mov r13, [rdi + 104]",
        "mov r14, [rdi + 112]",
        "mov r15, [rdi + 120]",
        "mov rsp, [rdi + 56]",
        "push qword ptr [rdi + 128]",
        "push qword ptr [rdi + 136]",
        "push qword ptr [rdi + 40]",
        "pop rdi",
        "popfq",
        "ret",
    );
}
