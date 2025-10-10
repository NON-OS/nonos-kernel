//! Timer Management
//!
//! Provides system timing functionality

use core::sync::atomic::{AtomicU64, Ordering};

/// System ticks since boot
static SYSTEM_TICKS: AtomicU64 = AtomicU64::new(0);

/// Timer frequency (Hz)
const TIMER_FREQUENCY: u64 = 1000; // 1kHz = 1ms per tick

/// Initialize system timer
pub fn init() {
    // PIT (Programmable Interval Timer) setup
    unsafe {
        use x86_64::instructions::port::Port;

        let frequency = 1193180 / TIMER_FREQUENCY; // PIT frequency divided by desired frequency

        // Command port - channel 0, lobyte/hibyte, rate generator
        Port::new(0x43).write(0x36u8);

        // Data port - set frequency
        Port::new(0x40).write((frequency & 0xFF) as u8);
        Port::new(0x40).write(((frequency >> 8) & 0xFF) as u8);
    }

    crate::log::logger::log_critical("Timer initialized at 1kHz");
}

/// Called by timer interrupt
pub fn tick() {
    SYSTEM_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Get current system tick count
pub fn get_ticks() -> u64 {
    SYSTEM_TICKS.load(Ordering::Relaxed)
}

/// Get uptime in milliseconds
pub fn get_uptime_ms() -> u64 {
    get_ticks() // Since we run at 1kHz, ticks = milliseconds
}

/// Get uptime in seconds
pub fn get_uptime_seconds() -> u64 {
    get_ticks() / TIMER_FREQUENCY
}

/// Sleep for specified number of ticks
pub fn sleep_ticks(ticks: u64) {
    let start = get_ticks();
    while get_ticks() < start + ticks {
        x86_64::instructions::hlt();
    }
}

/// Sleep for specified milliseconds
pub fn sleep_ms(ms: u64) {
    sleep_ticks(ms); // Since we run at 1kHz
}
