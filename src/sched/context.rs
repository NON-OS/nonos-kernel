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
                "mov {rax}, rax",
                "mov {rcx}, rcx", 
                "mov {rdx}, rdx",
                "mov {rsi}, rsi",
                "mov {rdi}, rdi",
                "mov {rbp}, rbp",
                "mov {rsp}, rsp",
                "mov {r8}, r8",
                "mov {r9}, r9",
                "mov {r10}, r10",
                "mov {r11}, r11",
                "mov {r12}, r12",
                "mov {r13}, r13",
                "mov {r14}, r14",
                "mov {r15}, r15",
                "lea {rip}, [rip + 7]",
                "pushfq",
                "pop {rflags}",
                rax = out(reg) ctx.rax,
                rcx = out(reg) ctx.rcx,
                rdx = out(reg) ctx.rdx,
                rsi = out(reg) ctx.rsi,
                rdi = out(reg) ctx.rdi,
                rbp = out(reg) ctx.rbp,
                rsp = out(reg) ctx.rsp,
                r8 = out(reg) ctx.r8,
                r9 = out(reg) ctx.r9,
                r10 = out(reg) ctx.r10,
                r11 = out(reg) ctx.r11,
                r12 = out(reg) ctx.r12,
                r13 = out(reg) ctx.r13,
                r14 = out(reg) ctx.r14,
                r15 = out(reg) ctx.r15,
                rip = out(reg) ctx.rip,
                rflags = out(reg) ctx.rflags,
            );
            
            core::arch::asm!(
                "mov {}, rbx",
                out(reg) ctx.rbx,
                options(preserves_flags, nostack)
            );
        }
        ctx
    }

    /// Restore a saved CPU context (jumps to saved rip)
    pub fn restore(&self) -> ! {
        unsafe {
            core::arch::asm!(
                "mov rbx, {rbx}",
                "push {rflags}",
                "push {rip}",
                "mov rax, {rax}",
                "mov rcx, {rcx}",
                "mov rdx, {rdx}",
                "mov rsi, {rsi}",
                "mov rdi, {rdi}",
                "mov rbp, {rbp}",
                "mov r8, {r8}",
                "mov r9, {r9}",
                "mov r10, {r10}",
                "mov r11, {r11}",
                "mov r12, {r12}",
                "mov r13, {r13}",
                "mov r14, {r14}",
                "mov r15, {r15}",
                "mov rsp, {rsp}",
                "popfq",
                "ret",
                rax = in(reg) self.rax,
                rbx = in(reg) self.rbx,
                rcx = in(reg) self.rcx,
                rdx = in(reg) self.rdx,
                rsi = in(reg) self.rsi,
                rdi = in(reg) self.rdi,
                rbp = in(reg) self.rbp,
                rsp = in(reg) self.rsp,
                r8 = in(reg) self.r8,
                r9 = in(reg) self.r9,
                r10 = in(reg) self.r10,
                r11 = in(reg) self.r11,
                r12 = in(reg) self.r12,
                r13 = in(reg) self.r13,
                r14 = in(reg) self.r14,
                r15 = in(reg) self.r15,
                rip = in(reg) self.rip,
                rflags = in(reg) self.rflags,
                options(noreturn)
            );
        }
    }
}
