/// x86_64 CPU context layout for process/thread switching.

#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuContext {
    // Register (System V AMD64 ABI)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,

    // Control/entry state
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,

    // Segment selectors used when transitioning to user mode (if applicable).
    pub cs: u64,
    pub ss: u64,
}

impl CpuContext {
    /// Create a zeroed context (no implicit flags). Configured by the caller.
    #[inline]
    pub const fn new() -> Self {
        Self {
            r15: 0, r14: 0, r13: 0, r12: 0, rbx: 0, rbp: 0,
            rip: 0, rsp: 0, rflags: 0,
            cs: 0, ss: 0,
        }
    }

    /// Initialize the context for a first entry to user mode.
    #[inline]
    pub fn prepare_user_entry(
        &mut self,
        entry: u64,
        user_stack_top: u64,
        user_cs: u64,
        user_ss: u64,
        rflags: u64,
    ) {
        self.rip = entry;
        self.rsp = user_stack_top;
        self.cs = user_cs;
        self.ss = user_ss;
        self.rflags = rflags | 1 << 1; // Bit 1 must be set on x86_64
    }

    /// Initialize the context for a first entry to a kernel thread/function.
    #[inline]
    pub fn prepare_kernel_entry(&mut self, entry: u64, kernel_stack_top: u64, rflags: u64) {
        self.rip = entry;
        self.rsp = kernel_stack_top;
        self.cs = 0;
        self.ss = 0;
        self.rflags = rflags | 1 << 1; // reserved bit set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_layout_is_stable() {
        // Basic sanity: all fields are 64-bit, count matches.
        // 6 callee-saved + 3 control + 2 segments = 11 u64s
        let expected_size = core::mem::size_of::<u64>() * 11;
        assert_eq!(core::mem::size_of::<CpuContext>(), expected_size);
        assert_eq!(core::mem::align_of::<CpuContext>(), core::mem::align_of::<u64>());
    }

    #[test]
    fn prepare_user_entry_sets_reserved_flag() {
        let mut ctx = CpuContext::new();
        ctx.prepare_user_entry(0x401000, 0x7fff_ffff_f000, 0x1b, 0x23, 0x202);
        assert_eq!(ctx.rip, 0x401000);
        assert_eq!(ctx.rsp, 0x7fff_ffff_f000);
        assert_eq!(ctx.cs, 0x1b);
        assert_eq!(ctx.ss, 0x23);
        // Bit 1 must always be set
        assert_ne!(ctx.rflags & (1 << 1), 0);
    }

    #[test]
    fn prepare_kernel_entry_sets_reserved_flag() {
        let mut ctx = CpuContext::new();
        ctx.prepare_kernel_entry(0xdead_beef, 0xffff_ffff_ffff_f000, 0x200);
        assert_eq!(ctx.rip, 0xdead_beef);
        assert_eq!(ctx.rsp, 0xffff_ffff_ffff_f000);
        assert_ne!(ctx.rflags & (1 << 1), 0);
    }
}
