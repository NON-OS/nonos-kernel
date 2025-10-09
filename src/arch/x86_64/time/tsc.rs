//! Time Stamp Counter (TSC) Utilities

/// Read Time Stamp Counter (TSC)
#[inline(always)]
pub fn rdtsc() -> u64 {
    unsafe {
        let mut hi: u32;
        let mut lo: u32;
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

/// Convert TSC ticks to nanoseconds
pub fn tsc_to_ns(tsc_ticks: u64, tsc_freq: u64) -> u64 {
    if tsc_freq == 0 { return 0; }
    (tsc_ticks * 1_000_000_000) / tsc_freq
}
