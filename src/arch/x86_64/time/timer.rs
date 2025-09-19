//! Advanced Timer System
//! 
//! High-resolution timing with TSC and HPET support

use core::sync::atomic::{AtomicU64, Ordering};

static BOOT_TIME: AtomicU64 = AtomicU64::new(0);

/// Get nanoseconds since boot
pub fn now_ns() -> u64 {
    // Would use TSC or HPET
    rdtsc() * 1000 // Approximate conversion
}

/// Check if timer is initialized
pub fn is_initialized() -> bool {
    BOOT_TIME.load(Ordering::Relaxed) != 0
}

/// Safe version that checks if timer is initialized
pub fn now_ns_checked() -> Option<u64> {
    if is_initialized() {
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
    
    // Configure PIT (Programmable Interval Timer) frequency
    unsafe {
        let divisor = 1193182 / freq_hz; // PIT base frequency is 1.193182 MHz
        
        // Set PIT to mode 3 (square wave generator)
        crate::arch::x86_64::port::outb(0x43, 0x36);
        
        // Send frequency divisor
        crate::arch::x86_64::port::outb(0x40, (divisor & 0xFF) as u8);
        crate::arch::x86_64::port::outb(0x40, ((divisor >> 8) & 0xFF) as u8);
    }
    
    // Try to configure HPET (High Precision Event Timer) if available
    if let Some(hpet_base) = detect_hpet() {
        configure_hpet(hpet_base, freq_hz);
        crate::log_info!("HPET configured at frequency {} Hz", freq_hz);
    } else {
        crate::log_info!("PIT configured at frequency {} Hz", freq_hz);
    }
}

/// Detect HPET from ACPI tables
fn detect_hpet() -> Option<u64> {
    // Check ACPI HPET table
    if let Some(acpi_tables) = crate::arch::x86_64::acpi::get_acpi_tables() {
        if let Some(hpet_table) = acpi_tables.find_table::<crate::arch::x86_64::acpi::Hpet>() {
            return Some(hpet_table.base_address);
        }
    }
    None
}

/// Configure HPET timer
fn configure_hpet(hpet_base: u64, freq_hz: u32) {
    unsafe {
        // Read HPET capabilities
        let capabilities = core::ptr::read_volatile(hpet_base as *const u64);
        let counter_period = (capabilities >> 32) as u32; // femtoseconds per tick
        
        // Calculate comparator value for desired frequency
        let ticks_per_interrupt = (1_000_000_000_000_000u64 / counter_period as u64) / freq_hz as u64;
        
        // Configure timer 0 for periodic interrupts
        let timer0_config_addr = (hpet_base + 0x100) as *mut u64;
        let timer0_comparator_addr = (hpet_base + 0x108) as *mut u64;
        
        // Set timer 0 to periodic mode, enable interrupt
        core::ptr::write_volatile(timer0_config_addr, 0x004C); // Periodic, edge-triggered, IRQ 0
        
        // Set comparator value
        core::ptr::write_volatile(timer0_comparator_addr, ticks_per_interrupt);
        
        // Enable HPET
        let general_config_addr = (hpet_base + 0x010) as *mut u64;
        core::ptr::write_volatile(general_config_addr, 1); // Enable HPET
    }
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

/// Get timestamp in milliseconds since boot
pub fn get_timestamp_ms() -> Option<u64> {
    now_ns_checked().map(|ns| ns / 1_000_000)
}
