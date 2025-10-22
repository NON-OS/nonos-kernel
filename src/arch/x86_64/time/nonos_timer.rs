//! Timer System

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;
use alloc::{collections::BTreeMap, boxed::Box};

static BOOT_TIME: AtomicU64 = AtomicU64::new(0);
static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);
static TIMER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HPET_BASE: AtomicU64 = AtomicU64::new(0);
static ACTIVE_TIMERS: Mutex<BTreeMap<u64, TimerCallback>> = Mutex::new(BTreeMap::new());
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

/// Timer callback structure
struct TimerCallback {
    expiry_ns: u64,
    callback: Box<dyn Fn() + Send + Sync>,
}

/// Get nanoseconds since boot with real TSC calibration
pub fn now_ns() -> u64 {
    if !TIMER_INITIALIZED.load(Ordering::Relaxed) {
        return 0;
    }
    let current_tsc = rdtsc();
    let boot_tsc = BOOT_TIME.load(Ordering::Relaxed);
    let tsc_freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if tsc_freq == 0 {
        return 0;
    }
    let tsc_diff = current_tsc.saturating_sub(boot_tsc);
    (tsc_diff * 1_000_000_000) / tsc_freq
}

/// Check if timer is initialized
pub fn is_initialized() -> bool {
    TIMER_INITIALIZED.load(Ordering::Relaxed)
}

/// Safe version that checks if timer is initialized
pub fn now_ns_checked() -> Option<u64> {
    if is_initialized() {
        Some(now_ns())
    } else {
        None
    }
}

/// Sleep for specified nanoseconds with hardware-aware strategy
pub fn sleep_long_ns<F>(ns: u64, callback: F)
where
    F: Fn(),
{
    let start = now_ns();
    let end_time = start + ns;
    while now_ns() < end_time {
        callback();
        let remaining_ns = end_time.saturating_sub(now_ns());
        if remaining_ns > 10_000_000 {
            // Use HLT for longer sleeps
            unsafe {
                x86_64::instructions::interrupts::enable();
                x86_64::instructions::hlt();
                x86_64::instructions::interrupts::disable();
            }
        } else if remaining_ns > 1000 {
            for _ in 0..(remaining_ns / 100) {
                unsafe { core::arch::asm!("pause"); }
            }
        } else {
            unsafe { core::arch::asm!("nop"); }
        }
    }
}

/// Initialize timer system with real TSC calibration and HPET setup
pub fn init() {
    let boot_tsc = rdtsc();
    BOOT_TIME.store(boot_tsc, Ordering::SeqCst);
    let tsc_freq = calibrate_tsc_frequency();
    TSC_FREQUENCY.store(tsc_freq, Ordering::SeqCst);
    if let Some(hpet_base) = detect_hpet() {
        HPET_BASE.store(hpet_base, Ordering::SeqCst);
        configure_hpet_for_timing(hpet_base);
    }
    ACTIVE_TIMERS.lock().clear();
    TIMER_INITIALIZED.store(true, Ordering::SeqCst);
    if let Some(logger) = crate::log::logger::try_get_logger() {
        if let Some(log_mgr) = logger.lock().as_mut() {
            log_mgr.log(crate::log::nonos_logger::Severity::Info, &alloc::format!("[TIMER] Initialized with TSC frequency: {} Hz", tsc_freq));
        }
    }
}

/// Real TSC frequency calibration using PIT
fn calibrate_tsc_frequency() -> u64 {
    unsafe {
        crate::arch::x86_64::port::outb(0x43, 0xB0); // Channel 2, one-shot
        crate::arch::x86_64::port::outb(0x42, 0xFF);
        crate::arch::x86_64::port::outb(0x42, 0xFF);
        let speaker_port = crate::arch::x86_64::port::inb(0x61);
        crate::arch::x86_64::port::outb(0x61, speaker_port | 0x03);
        while (crate::arch::x86_64::port::inb(0x61) & 0x20) == 0 {}
        let start_tsc = rdtsc();
        while (crate::arch::x86_64::port::inb(0x61) & 0x20) != 0 {}
        let end_tsc = rdtsc();
        crate::arch::x86_64::port::outb(0x61, speaker_port);
        let tsc_ticks = end_tsc - start_tsc;
        let time_ns = 54925484; // 65535 / 1193182 * 1000000000
        (tsc_ticks * 1_000_000_000) / time_ns
    }
}

/// Configure HPET for high-precision timing
fn configure_hpet_for_timing(hpet_base: u64) {
    unsafe {
        let capabilities = core::ptr::read_volatile(hpet_base as *const u64);
        let period_fs = (capabilities >> 32) as u32;
        let config_reg = (hpet_base + 0x10) as *mut u64;
        core::ptr::write_volatile(config_reg, 0);
        let counter_reg = (hpet_base + 0xF0) as *mut u64;
        core::ptr::write_volatile(counter_reg, 0);
        core::ptr::write_volatile(config_reg, 1);
        if let Some(logger) = crate::log::logger::try_get_logger() {
            if let Some(log_mgr) = logger.lock().as_mut() {
                log_mgr.log(crate::log::Severity::Info, &alloc::format!("[TIMER] HPET configured, period: {} fs", period_fs));
            }
        }
    }
}

/// Initialize timer system with frequency parameter
pub fn init_with_freq(freq_hz: u32) {
    BOOT_TIME.store(rdtsc(), Ordering::SeqCst);
    unsafe {
        let divisor = 1193182 / freq_hz;
        crate::arch::x86_64::port::outb(0x43, 0x36);
        crate::arch::x86_64::port::outb(0x40, (divisor & 0xFF) as u8);
        crate::arch::x86_64::port::outb(0x40, ((divisor >> 8) & 0xFF) as u8);
    }
    if let Some(hpet_base) = detect_hpet() {
        configure_hpet(hpet_base, freq_hz);
        crate::log_info!("HPET configured at frequency {} Hz", freq_hz);
    } else {
        crate::log_info!("PIT configured at frequency {} Hz", freq_hz);
    }
}

/// Detect HPET from ACPI tables 
fn detect_hpet() -> Option<u64> {
    const HPET_DEFAULT_BASE: u64 = 0xFED00000;
    if is_valid_hpet_base(HPET_DEFAULT_BASE) {
        return Some(HPET_DEFAULT_BASE);
    }
    for base in (0xFED00000..=0xFED10000).step_by(0x1000) {
        if is_valid_hpet_base(base) {
            return Some(base);
        }
    }
    if let Some(acpi_base) = try_acpi_hpet_detection() {
        if is_valid_hpet_base(acpi_base) {
            return Some(acpi_base);
        }
    }
    None
}

/// Check if given address contains valid HPET
pub fn is_valid_hpet_base(base: u64) -> bool {
    unsafe {
        let capabilities_ptr = base as *const u64;
        let capabilities = core::ptr::read_volatile(capabilities_ptr);
        let vendor_id = (capabilities >> 48) as u16;
        matches!(vendor_id, 0x8086 | 0x1022 | 0x10DE | 0x1002) || vendor_id != 0
    }
}

/// Try ACPI-based HPET detection
fn try_acpi_hpet_detection() -> Option<u64> {
    // TODO: ACPI table search for HPET. Return None until implemented.
    None
}

/// Configure HPET timer
fn configure_hpet(hpet_base: u64, freq_hz: u32) {
    unsafe {
        let capabilities = core::ptr::read_volatile(hpet_base as *const u64);
        let counter_period = (capabilities >> 32) as u32;
        let ticks_per_interrupt = (1_000_000_000_000_000u64 / counter_period as u64) / freq_hz as u64;
        let timer0_config_addr = (hpet_base + 0x100) as *mut u64;
        let timer0_comparator_addr = (hpet_base + 0x108) as *mut u64;
        core::ptr::write_volatile(timer0_config_addr, 0x004C);
        core::ptr::write_volatile(timer0_comparator_addr, ticks_per_interrupt);
        let general_config_addr = (hpet_base + 0x010) as *mut u64;
        core::ptr::write_volatile(general_config_addr, 1);
    }
}

/// Get milliseconds since boot
pub fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

/// Check if timer is in deadline mode
pub fn is_deadline_mode() -> bool {
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

/// High resolution timer callback with real timer management
pub fn hrtimer_after_ns<F>(ns: u64, callback: F) -> u64
where
    F: Fn() + Send + Sync + 'static,
{
    let timer_id = NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed);
    let expiry_time = now_ns() + ns;
    let timer_callback = TimerCallback {
        expiry_ns: expiry_time,
        callback: Box::new(callback),
    };
    ACTIVE_TIMERS.lock().insert(timer_id, timer_callback);
    check_expired_timers();
    timer_id
}

/// Process expired timers
fn check_expired_timers() {
    let current_time = now_ns();
    let mut timers = ACTIVE_TIMERS.lock();
    let mut expired_timers = alloc::vec::Vec::new();
    for (&timer_id, timer) in timers.iter() {
        if current_time >= timer.expiry_ns {
            expired_timers.push((timer_id, timer.callback));
        }
    }
    for &(timer_id, _) in &expired_timers {
        timers.remove(&timer_id);
    }
    drop(timers);
    for (_, callback) in expired_timers {
        callback();
    }
}

/// Cancel a timer by ID
pub fn cancel_timer(timer_id: u64) -> bool {
    ACTIVE_TIMERS.lock().remove(&timer_id).is_some()
}

/// Get number of active timers
pub fn get_active_timer_count() -> usize {
    ACTIVE_TIMERS.lock().len()
}

/// Read Time Stamp Counter
fn rdtsc() -> u64 {
    unsafe {
        let mut hi: u32;
        let mut lo: u32;
        unsafe {
            core::arch::asm!(
                "lfence",
                "rdtsc",
                "lfence",
                out("eax") lo,
                out("edx") hi,
                options(nostack, preserves_flags)
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
}

/// Read timestamp counter with processor serialization
pub fn rdtscp() -> (u64, u32) {
    unsafe {
        let mut hi: u32;
        let mut lo: u32;
        let mut aux: u32;
        unsafe {
            core::arch::asm!(
                "rdtscp",
                out("eax") lo,
                out("edx") hi,
                out("ecx") aux,
                options(nostack, preserves_flags)
            );
        }
        (((hi as u64) << 32) | (lo as u64), aux)
    }
}

/// Get TSC frequency
pub fn get_tsc_frequency() -> u64 {
    TSC_FREQUENCY.load(Ordering::Relaxed)
}

/// Convert TSC ticks to nanoseconds
pub fn tsc_to_ns(tsc_ticks: u64) -> u64 {
    let freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if freq == 0 {
        return 0;
    }
    (tsc_ticks * 1_000_000_000) / freq
}

/// Convert nanoseconds to TSC ticks
pub fn ns_to_tsc(nanoseconds: u64) -> u64 {
    let freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if freq == 0 {
        return 0;
    }
    (nanoseconds * freq) / 1_000_000_000
}

/// Get timestamp in milliseconds since boot
pub fn get_timestamp_ms() -> Option<u64> {
    now_ns_checked().map(|ns| ns / 1_000_000)
}

/// Tick function called by interrupt handler
pub fn tick() {
    check_expired_timers();
    if let Some(scheduler) = crate::sched::current_scheduler() {
        scheduler.tick();
    }
}

/// Get HPET counter value if available
pub fn get_hpet_counter() -> Option<u64> {
    let hpet_base = HPET_BASE.load(Ordering::Relaxed);
    if hpet_base == 0 {
        return None;
    }
    unsafe {
        let counter_reg = (hpet_base + 0xF0) as *const u64;
        Some(core::ptr::read_volatile(counter_reg))
    }
}

/// Convert HPET counter to nanoseconds
pub fn hpet_to_ns(hpet_ticks: u64) -> Option<u64> {
    let hpet_base = HPET_BASE.load(Ordering::Relaxed);
    if hpet_base == 0 {
        return None;
    }
    unsafe {
        let capabilities = core::ptr::read_volatile(hpet_base as *const u64);
        let period_fs = (capabilities >> 32) as u32;
        Some((hpet_ticks * period_fs as u64) / 1_000_000)
    }
}

/// High precision delay using TSC
pub fn delay_precise_ns(nanoseconds: u64) {
    let start_tsc = rdtsc();
    let target_ticks = ns_to_tsc(nanoseconds);
    let end_tsc = start_tsc + target_ticks;
    while rdtsc() < end_tsc {
        unsafe {
            core::arch::asm!("pause");
        }
    }
}

/// Microsecond delay
pub fn delay_us(microseconds: u64) {
    delay_precise_ns(microseconds * 1000)
}

/// Millisecond delay
pub fn delay_ms(milliseconds: u64) {
    delay_precise_ns(milliseconds * 1_000_000)
}

/// Timer statistics
pub struct TimerStats {
    pub tsc_frequency: u64,
    pub active_timers: usize,
    pub hpet_available: bool,
    pub uptime_ns: u64,
}

/// Get timer system statistics
pub fn get_timer_stats() -> TimerStats {
    TimerStats {
        tsc_frequency: TSC_FREQUENCY.load(Ordering::Relaxed),
        active_timers: ACTIVE_TIMERS.lock().len(),
        hpet_available: HPET_BASE.load(Ordering::Relaxed) != 0,
        uptime_ns: now_ns(),
    }
}
