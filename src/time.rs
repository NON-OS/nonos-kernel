//! Time management for NONOS kernel
//! Provides Instant implementation and timing utilities

use core::time::Duration;

/// Boot time reference for relative timing
static mut BOOT_TIME: u64 = 0;

/// Simple Instant implementation for kernel timing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    ticks: u64,
}

impl Instant {
    /// Get current time instant
    pub fn now() -> Self {
        Self {
            ticks: current_ticks(),
        }
    }
    
    /// Calculate elapsed time since this instant
    pub fn elapsed(&self) -> Duration {
        let current = current_ticks();
        let elapsed_ticks = current.saturating_sub(self.ticks);
        Duration::from_nanos(elapsed_ticks * 1000) // Assume ticks are microseconds
    }
    
    /// Calculate duration since another instant
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        let elapsed_ticks = self.ticks.saturating_sub(earlier.ticks);
        Duration::from_nanos(elapsed_ticks * 1000)
    }
    
    /// Check if this instant is after another
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        if self.ticks >= earlier.ticks {
            Some(self.duration_since(earlier))
        } else {
            None
        }
    }
    
    /// Add duration to this instant
    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        let additional_ticks = duration.as_nanos() as u64 / 1000;
        self.ticks.checked_add(additional_ticks).map(|ticks| Instant { ticks })
    }
    
    /// Subtract duration from this instant
    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        let subtracted_ticks = duration.as_nanos() as u64 / 1000;
        self.ticks.checked_sub(subtracted_ticks).map(|ticks| Instant { ticks })
    }
}

/// Initialize timing subsystem
pub fn init() {
    unsafe {
        BOOT_TIME = rdtsc();
    }
}

/// Get current uptime in seconds since boot
pub fn current_uptime() -> u64 {
    let current = current_ticks();
    current / 1_000_000 // Convert microseconds to seconds
}

/// Get current tick count (microseconds since boot)
pub fn current_ticks() -> u64 {
    unsafe {
        let current = rdtsc();
        // Convert TSC cycles to microseconds (assuming 1GHz for simplicity)
        (current - BOOT_TIME) / 1000
    }
}

/// Read timestamp counter
#[inline]
unsafe fn rdtsc() -> u64 {
    let mut low: u32;
    let mut high: u32;
    
    core::arch::asm!(
        "rdtsc",
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    
    ((high as u64) << 32) | (low as u64)
}

/// Sleep for specified duration (busy wait)
pub fn sleep(duration: Duration) {
    let start = Instant::now();
    while start.elapsed() < duration {
        core::hint::spin_loop();
    }
}

/// Get current timestamp in nanoseconds
pub fn timestamp_nanos() -> u64 {
    current_ticks() * 1000
}

/// Get current timestamp in milliseconds  
pub fn timestamp_millis() -> u64 {
    current_ticks() / 1000
}

/// Get current timestamp in milliseconds with error handling
pub fn get_timestamp_ms() -> Option<u64> {
    Some(timestamp_millis())
}

/// Get kernel time in nanoseconds (for capability engine)
pub fn get_kernel_time_ns() -> u64 {
    timestamp_nanos()
}
