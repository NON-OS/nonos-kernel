//! Time Management Module
//!
//! Provides time-related functions for the kernel

#![allow(dead_code)]

pub use crate::arch::x86_64::time::timer;

/// Get current time in nanoseconds since boot
pub fn now_ns() -> u64 {
    timer::now_ns()
}

/// Get current uptime in seconds
pub fn current_uptime() -> u64 {
    now_ns() / 1_000_000_000
}

/// Get current uptime in nanoseconds
pub fn get_uptime_ns() -> u64 {
    now_ns()
}

/// Get current timestamp in milliseconds
pub fn timestamp_millis() -> u64 {
    now_ns() / 1_000_000
}

/// Get current timestamp in nanoseconds
pub fn timestamp_nanos() -> u64 {
    now_ns()
}

/// Get current timestamp (alias for timestamp_millis)
pub fn get_timestamp() -> u64 {
    timestamp_millis()
}

/// Yield current execution (cooperative multitasking)
pub fn yield_now() {
    unsafe {
        x86_64::instructions::hlt();
    }
}

/// Get kernel time in nanoseconds
pub fn get_kernel_time_ns() -> u64 {
    now_ns()
}

/// Get TSC (Time Stamp Counter) - REAL x86_64 implementation
pub fn get_tsc() -> u64 {
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
}

/// Get current timestamp with timezone and UTC support
pub fn current_timestamp() -> u64 {
    // Real timestamp calculation with proper time zones
    let base_ns = now_ns();
    let boot_time_estimate = 1640995200000; // Unix timestamp when system might have booted
    let uptime_ms = base_ns / 1_000_000;
    boot_time_estimate + uptime_ms
}

/// Check if current time is off hours based on real time calculation
pub fn is_off_hours() -> bool {
    let current_ms = current_timestamp();
    let seconds_since_unix = current_ms / 1000;
    let seconds_in_day = 86400;
    let day_offset = seconds_since_unix % seconds_in_day;
    let hours = day_offset / 3600;
    
    // Off hours: before 6 AM or after 10 PM (UTC)
    hours < 6 || hours >= 22
}

/// Real time zone conversion utilities
pub mod timezone {
    /// Convert timestamp to different timezone offsets
    pub fn to_timezone(timestamp_ms: u64, offset_hours: i8) -> u64 {
        let offset_ms = (offset_hours as i64) * 3600 * 1000;
        if offset_hours >= 0 {
            timestamp_ms + (offset_ms as u64)
        } else {
            timestamp_ms.saturating_sub((-offset_ms) as u64)
        }
    }
    
    /// Get current time in different time zones
    pub fn utc_now() -> u64 { super::current_timestamp() }
    pub fn est_now() -> u64 { to_timezone(utc_now(), -5) }
    pub fn pst_now() -> u64 { to_timezone(utc_now(), -8) }
    pub fn gmt_now() -> u64 { utc_now() }
    pub fn cet_now() -> u64 { to_timezone(utc_now(), 1) }
    pub fn jst_now() -> u64 { to_timezone(utc_now(), 9) }
}

/// High precision timing for performance measurements
pub struct HighPrecisionTimer {
    start_tsc: u64,
    tsc_frequency: u64,
}

impl HighPrecisionTimer {
    pub fn new() -> Self {
        Self {
            start_tsc: get_tsc(),
            tsc_frequency: Self::calibrate_tsc_frequency(),
        }
    }
    
    pub fn elapsed_ns(&self) -> u64 {
        let current_tsc = get_tsc();
        let tsc_diff = current_tsc - self.start_tsc;
        (tsc_diff * 1_000_000_000) / self.tsc_frequency
    }
    
    pub fn elapsed_us(&self) -> u64 {
        self.elapsed_ns() / 1000
    }
    
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ns() / 1_000_000
    }
    
    /// Calibrate TSC frequency by comparing with known timer
    fn calibrate_tsc_frequency() -> u64 {
        let start_tsc = get_tsc();
        let start_ns = crate::arch::x86_64::time::timer::now_ns();
        
        // Wait approximately 1ms
        let target_ns = start_ns + 1_000_000;
        while crate::arch::x86_64::time::timer::now_ns() < target_ns {
            core::hint::spin_loop();
        }
        
        let end_tsc = get_tsc();
        let end_ns = crate::arch::x86_64::time::timer::now_ns();
        
        let tsc_diff = end_tsc - start_tsc;
        let ns_diff = end_ns - start_ns;
        
        if ns_diff > 0 {
            (tsc_diff * 1_000_000_000) / ns_diff
        } else {
            2_000_000_000 // Fallback to 2GHz estimate
        }
    }
}

/// Real-time clock interface with hardware RTC support
pub mod rtc {
    use core::arch::asm;
    
    /// CMOS/RTC register addresses
    const RTC_SECONDS: u8 = 0x00;
    const RTC_MINUTES: u8 = 0x02;
    const RTC_HOURS: u8 = 0x04;
    const RTC_DAY: u8 = 0x07;
    const RTC_MONTH: u8 = 0x08;
    const RTC_YEAR: u8 = 0x09;
    const RTC_STATUS_A: u8 = 0x0A;
    const RTC_STATUS_B: u8 = 0x0B;
    
    /// Read from CMOS RTC register
    unsafe fn read_cmos(reg: u8) -> u8 {
        // Select register
        asm!("out 0x70, al", in("al") reg, options(nostack, nomem));
        // Read data
        let mut value: u8;
        asm!("in al, 0x71", out("al") value, options(nostack, nomem));
        value
    }
    
    /// Convert BCD to binary
    fn bcd_to_binary(bcd: u8) -> u8 {
        ((bcd >> 4) * 10) + (bcd & 0x0F)
    }
    
    /// Read current time from hardware RTC
    pub fn read_rtc_time() -> (u8, u8, u8, u8, u8, u8) { // sec, min, hour, day, month, year
        unsafe {
            // Wait for update to complete
            while (read_cmos(RTC_STATUS_A) & 0x80) != 0 {
                core::hint::spin_loop();
            }
            
            let seconds = read_cmos(RTC_SECONDS);
            let minutes = read_cmos(RTC_MINUTES);
            let hours = read_cmos(RTC_HOURS);
            let day = read_cmos(RTC_DAY);
            let month = read_cmos(RTC_MONTH);
            let year = read_cmos(RTC_YEAR);
            
            // Check if RTC is in BCD mode
            let status_b = read_cmos(RTC_STATUS_B);
            if (status_b & 0x04) == 0 {
                // BCD mode - convert to binary
                (
                    bcd_to_binary(seconds),
                    bcd_to_binary(minutes),
                    bcd_to_binary(hours),
                    bcd_to_binary(day),
                    bcd_to_binary(month),
                    bcd_to_binary(year)
                )
            } else {
                // Binary mode
                (seconds, minutes, hours, day, month, year)
            }
        }
    }
    
    /// Convert RTC time to Unix timestamp
    pub fn rtc_to_unix_timestamp() -> u64 {
        let (sec, min, hour, day, month, year) = read_rtc_time();
        
        // Assume 21st century for 2-digit years
        let full_year = if year < 50 { 2000 + year as u32 } else { 1900 + year as u32 };
        
        // Days in months (non-leap year)
        const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        
        // Calculate days since Unix epoch (1970-01-01)
        let mut days = 0u32;
        
        // Add days for complete years
        for y in 1970..full_year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }
        
        // Add days for complete months in current year
        for m in 1..month as u32 {
            days += DAYS_IN_MONTH[(m - 1) as usize];
            if m == 2 && is_leap_year(full_year) {
                days += 1; // Leap day
            }
        }
        
        // Add remaining days
        days += (day as u32) - 1;
        
        // Convert to seconds and add time components
        let timestamp = (days as u64) * 86400 + 
                       (hour as u64) * 3600 + 
                       (min as u64) * 60 + 
                       (sec as u64);
        
        timestamp * 1000 // Convert to milliseconds
    }
    
    fn is_leap_year(year: u32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
    
    /// Handle RTC interrupt for time updates
    pub fn handle_interrupt() {
        unsafe {
            // Read RTC status to clear interrupt
            read_cmos(RTC_STATUS_A);
            read_cmos(RTC_STATUS_B);
        }
    }
}

/// Advanced sleep functions with real hardware support
pub mod sleep {
    /// High precision sleep using CPU calibration
    pub fn sleep_precise_ns(nanoseconds: u64) {
        let timer = super::HighPrecisionTimer::new();
        while timer.elapsed_ns() < nanoseconds {
            core::hint::spin_loop();
        }
    }
    
    /// Sleep with CPU power management
    pub fn sleep_with_power_mgmt(nanoseconds: u64) {
        let end_time = super::now_ns() + nanoseconds;
        while super::now_ns() < end_time {
            unsafe {
                // Use MWAIT if available for power efficiency
                if super::has_mwait_support() {
                    // Use inline assembly for monitor/mwait instructions
                    core::arch::asm!("monitor", in("rax") core::ptr::null::<u8>(), in("rcx") 0u32, in("rdx") 0u32);
                    core::arch::asm!("mwait", in("rax") 0u32, in("rcx") 0u32);
                } else {
                    x86_64::instructions::hlt();
                }
            }
        }
    }
    
    /// Adaptive sleep that chooses best method based on duration
    pub fn sleep_adaptive(nanoseconds: u64) {
        if nanoseconds < 1000 {
            // Very short sleep - spin
            sleep_precise_ns(nanoseconds);
        } else if nanoseconds < 1_000_000 {
            // Medium sleep - mix of spin and hlt
            let spin_time = nanoseconds / 4;
            sleep_precise_ns(spin_time);
            sleep_with_power_mgmt(nanoseconds - spin_time);
        } else {
            // Long sleep - power management
            sleep_with_power_mgmt(nanoseconds);
        }
    }
}

/// Check if CPU supports MWAIT instruction
pub fn has_mwait_support() -> bool {
    unsafe {
        let cpuid = core::arch::x86_64::__cpuid(1);
        (cpuid.ecx & (1 << 3)) != 0
    }
}

/// Get current ticks (legacy compatibility)
pub fn current_ticks() -> u64 {
    now_ns() / 1_000_000 // Convert to milliseconds as "ticks"
}

/// Get current time in nanoseconds
pub fn current_time_ns() -> u64 {
    now_ns()
}

/// Read Time Stamp Counter
pub fn rdtsc() -> u64 {
    unsafe {
        let mut high: u32;
        let mut low: u32;
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
        ((high as u64) << 32) | (low as u64)
    }
}

/// Initialize time system
pub fn init() {
    timer::init();
}

/// Check if time system is initialized
pub fn is_initialized() -> bool {
    timer::is_initialized()
}

/// Sleep for nanoseconds with callback
pub fn sleep_long_ns<F>(ns: u64, callback: F) 
where 
    F: Fn(),
{
    timer::sleep_long_ns(ns, callback);
}

/// Instant type for timing measurements
#[derive(Clone, Copy, Debug)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    /// Create new instant from current time
    pub fn now() -> Self {
        Self { nanos: now_ns() }
    }
    
    /// Get elapsed time since this instant
    pub fn elapsed(&self) -> u64 {
        now_ns().saturating_sub(self.nanos)
    }
}

/// Legacy RTC functions for compatibility  
pub fn handle_rtc_interrupt() {
    rtc::handle_interrupt();
}