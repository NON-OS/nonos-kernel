//! NONOS Timer System
//! 
//! High-resolution timing with TSC and HPET support

use core::sync::atomic::{AtomicU64, Ordering};

static BOOT_TIME: AtomicU64 = AtomicU64::new(0);

/// Get nanoseconds since boot
pub fn now_ns() -> u64 {
    // Would use TSC or HPET
    rdtsc() * 1000 // Approximate conversion
}

/// Safe version that checks if timer is initialized
pub fn now_ns_checked() -> Option<u64> {
    let boot = BOOT_TIME.load(Ordering::Relaxed);
    if boot != 0 {
        Some(now_ns())
    } else {
        None
    }
}

/// Sleep for specified nanoseconds
pub fn sleep_long_ns<F>(ns: u64, callback: F) 
where 
    F: Fn(),
{
    let start = now_ns();
    while now_ns() - start < ns {
        callback();
        // Yield CPU
        unsafe {
            core::arch::asm!("pause");
        }
    }
}

/// Initialize timer system
pub fn init() {
    BOOT_TIME.store(rdtsc(), Ordering::SeqCst);
}

/// Initialize timer system with frequency parameter
pub fn init_with_freq(freq_hz: u32) {
    BOOT_TIME.store(rdtsc(), Ordering::SeqCst);
    // In a real implementation, would configure timer frequency
}

/// Get milliseconds since boot
pub fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

/// Check if timer is in deadline mode
pub fn is_deadline_mode() -> bool {
    // Simple implementation - always false for now
    false
}

/// Busy sleep for nanoseconds
pub fn busy_sleep_ns(ns: u64) {
    let start = now_ns();
    while now_ns() - start < ns {
        unsafe {
            core::arch::asm!("pause");
        }
    }
}

/// High resolution timer callback
pub fn hrtimer_after_ns<F>(ns: u64, callback: F) -> u64
where 
    F: Fn(),
{
    // Simple implementation - execute callback after sleep
    busy_sleep_ns(ns);
    callback();
    rdtsc() // Return timer ID
}

/// Read Time Stamp Counter
fn rdtsc() -> u64 {
    unsafe {
        let mut hi: u32;
        let mut lo: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}
