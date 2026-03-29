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

impl Context {
    pub fn save() -> Self {
        let mut ctx = Context {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0, rflags: 0,
        };
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
}
