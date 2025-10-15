//! NØNOS Kernel Context Switching
#[repr(C)]
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
    /// Save the current CPU context into a Context struct
    pub fn save() -> Self {
        let mut ctx = Context {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0, rflags: 0,
        };
        unsafe {
            core::arch::asm!(
                "mov {}, rax", out(reg) ctx.rax,
                "mov {}, rbx", out(reg) ctx.rbx,
                "mov {}, rcx", out(reg) ctx.rcx,
                "mov {}, rdx", out(reg) ctx.rdx,
                "mov {}, rsi", out(reg) ctx.rsi,
                "mov {}, rdi", out(reg) ctx.rdi,
                "mov {}, rbp", out(reg) ctx.rbp,
                "mov {}, rsp", out(reg) ctx.rsp,
                "mov {}, r8",  out(reg) ctx.r8,
                "mov {}, r9",  out(reg) ctx.r9,
                "mov {}, r10", out(reg) ctx.r10,
                "mov {}, r11", out(reg) ctx.r11,
                "mov {}, r12", out(reg) ctx.r12,
                "mov {}, r13", out(reg) ctx.r13,
                "mov {}, r14", out(reg) ctx.r14,
                "mov {}, r15", out(reg) ctx.r15,
                "lea {}, [rip]", out(reg) ctx.rip,
                "pushfq; pop {}", out(reg) ctx.rflags,
            );
        }
        ctx
    }

    /// Restore a saved CPU context (jumps to saved rip)
    pub fn restore(&self) -> ! {
        unsafe {
            core::arch::asm!(
                "mov rax, {}", in(reg) self.rax,
                "mov rbx, {}", in(reg) self.rbx,
                "mov rcx, {}", in(reg) self.rcx,
                "mov rdx, {}", in(reg) self.rdx,
                "mov rsi, {}", in(reg) self.rsi,
                "mov rdi, {}", in(reg) self.rdi,
                "mov rbp, {}", in(reg) self.rbp,
                "mov rsp, {}", in(reg) self.rsp,
                "mov r8, {}",  in(reg) self.r8,
                "mov r9, {}",  in(reg) self.r9,
                "mov r10, {}", in(reg) self.r10,
                "mov r11, {}", in(reg) self.r11,
                "mov r12, {}", in(reg) self.r12,
                "mov r13, {}", in(reg) self.r13,
                "mov r14, {}", in(reg) self.r14,
                "mov r15, {}", in(reg) self.r15,
                "push {}", in(reg) self.rflags,
                "push {}", in(reg) self.rip,
                "ret",
                options(noreturn)
            );
        }
    }
}
