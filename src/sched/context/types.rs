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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl Context {
    pub fn save() -> Self {
        let mut ctx = Context {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0, rflags: 0,
        };
        // SAFETY: Reading CPU registers into local struct fields is safe.
        unsafe {
            core::arch::asm!("mov {}, rax", out(reg) ctx.rax, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, rbx", out(reg) ctx.rbx, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, rcx", out(reg) ctx.rcx, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, rdx", out(reg) ctx.rdx, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, rsi", out(reg) ctx.rsi, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, rdi", out(reg) ctx.rdi, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, rbp", out(reg) ctx.rbp, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, rsp", out(reg) ctx.rsp, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r8", out(reg) ctx.r8, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r9", out(reg) ctx.r9, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r10", out(reg) ctx.r10, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r11", out(reg) ctx.r11, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r12", out(reg) ctx.r12, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r13", out(reg) ctx.r13, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r14", out(reg) ctx.r14, options(preserves_flags, nostack));
            core::arch::asm!("mov {}, r15", out(reg) ctx.r15, options(preserves_flags, nostack));
            core::arch::asm!("lea {}, [rip]", out(reg) ctx.rip, options(preserves_flags, nostack));
            core::arch::asm!("pushfq", "pop {}", out(reg) ctx.rflags, options(nostack));
        }
        ctx
    }

    pub fn restore(&self) -> ! {
        let ctx_ptr = self as *const Context;
        context_restore_asm(ctx_ptr)
    }
}

#[unsafe(naked)]
extern "C" fn context_restore_asm(ctx: *const Context) -> ! {
    // SAFETY: Naked function restores all registers from Context struct and jumps to saved rip.
    core::arch::naked_asm!(
        "mov rax, [rdi + 0]",
        "mov rbx, [rdi + 8]",
        "mov rcx, [rdi + 16]",
        "mov rdx, [rdi + 24]",
        "mov rbp, [rdi + 48]",
        "mov r8, [rdi + 64]",
        "mov r9, [rdi + 72]",
        "mov r10, [rdi + 80]",
        "mov r11, [rdi + 88]",
        "mov r12, [rdi + 96]",
        "mov r13, [rdi + 104]",
        "mov r14, [rdi + 112]",
        "mov r15, [rdi + 120]",
        "push qword ptr [rdi + 128]",
        "push qword ptr [rdi + 136]",
        "mov rsi, [rdi + 32]",
        "mov r11, [rdi + 56]",
        "mov rdi, [rdi + 40]",
        "mov rsp, r11",
        "popfq",
        "ret",
    );
}
