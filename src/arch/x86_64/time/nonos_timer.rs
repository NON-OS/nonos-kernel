// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//!
//! Timer system for the NØNOS kernel.
//! Abstracting over multiple hardware timer sources (TSC, HPET, PIT, APIC)
//! Providing unified interfaces for:
//! - High-precision time measurement (nanosecond resolution)
//! - Monotonic and wall-clock time
//! - One-shot and periodic timers with callbacks
//! - Sleep and delay functions with various strategies
//! - Per-CPU timer state for SMP systems
//! - Timer wheel for efficient callback scheduling
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │                Timer System Overview             │
//! ├──────────────────────────────────────────────────┤
//! │                  Application Layer               │
//! │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
//! │  │ now_ns  │ │ sleep   │ │ hrtimer │ │ delay   │ │
//! │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ │
//! │       │           │           │           │      │
//! │  ┌────┴───────────┴───────────┴───────────┴────┐ │
//! │  │            Unified Timer Interface          │ │
//! │  └──────────────────── ─┬──────────────────────┘ │
//! │                         │                        │
//! │  ┌──────────────────────┴──────────────────────┐ │
//! │  │              Clock Source Manager           │ │
//! │  └────┬────────┬──────────────┬────────┬───────┘ │
//! │       │        │              │        │         │
//! │  ┌────┴──┐ ┌───┴───┐      ┌───┴───┐┌───┴───┐     │
//! │  │  TSC  │ │ HPET  │      │  PIT  ││ APIC  │     │
//! │  └───────┘ └───────┘      └───────┘└───────┘     │
//! └──────────────────────────────────────────────────┘
//! ```

use core::sync::atomic::{AtomicU64, AtomicBool, AtomicU8, AtomicUsize, Ordering};
use spin::{RwLock, Mutex};
use alloc::{collections::BTreeMap, boxed::Box, vec::Vec, string::String, format};

// ============================================================================
// Error Types
// ============================================================================

/// Timer system error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimerError {
    /// Timer system not initialized
    NotInitialized = 0,
    /// Already initialized
    AlreadyInitialized = 1,
    /// No suitable clock source found
    NoClockSource = 2,
    /// TSC not available or unstable
    TscUnavailable = 3,
    /// TSC calibration failed
    TscCalibrationFailed = 4,
    /// HPET not available
    HpetUnavailable = 5,
    /// HPET configuration failed
    HpetConfigFailed = 6,
    /// PIT not available
    PitUnavailable = 7,
    /// APIC timer not available
    ApicUnavailable = 8,
    /// Timer ID not found
    TimerNotFound = 9,
    /// Timer already cancelled
    TimerCancelled = 10,
    /// Invalid timer configuration
    InvalidConfig = 11,
    /// Timer callback allocation failed
    AllocationFailed = 12,
    /// Timer overflow
    Overflow = 13,
    /// Clock source not calibrated
    NotCalibrated = 14,
    /// Per-CPU timer not initialized
    PerCpuNotInit = 15,
    /// Deadline mode not supported
    DeadlineModeUnsupported = 16,
    /// Timer wheel full
    TimerWheelFull = 17,
    /// Invalid time value
    InvalidTime = 18,
    /// Hardware access error
    HardwareError = 19,
}

impl TimerError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Timer system not initialized",
            Self::AlreadyInitialized => "Timer system already initialized",
            Self::NoClockSource => "No suitable clock source found",
            Self::TscUnavailable => "TSC not available or unstable",
            Self::TscCalibrationFailed => "TSC calibration failed",
            Self::HpetUnavailable => "HPET not available",
            Self::HpetConfigFailed => "HPET configuration failed",
            Self::PitUnavailable => "PIT not available",
            Self::ApicUnavailable => "APIC timer not available",
            Self::TimerNotFound => "Timer ID not found",
            Self::TimerCancelled => "Timer already cancelled",
            Self::InvalidConfig => "Invalid timer configuration",
            Self::AllocationFailed => "Timer callback allocation failed",
            Self::Overflow => "Timer overflow",
            Self::NotCalibrated => "Clock source not calibrated",
            Self::PerCpuNotInit => "Per-CPU timer not initialized",
            Self::DeadlineModeUnsupported => "Deadline mode not supported",
            Self::TimerWheelFull => "Timer wheel is full",
            Self::InvalidTime => "Invalid time value",
            Self::HardwareError => "Hardware access error",
        }
    }
}

// ============================================================================
// Type Definitions
// ============================================================================

/// Result type for timer operations
pub type TimerResult<T> = Result<T, TimerError>;

/// Clock source type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ClockSource {
    /// No clock source selected
    #[default]
    None = 0,
    /// Time Stamp Counter (highest precision)
    Tsc = 1,
    /// High Precision Event Timer
    Hpet = 2,
    /// Programmable Interval Timer (legacy)
    Pit = 3,
    /// Local APIC timer
    Apic = 4,
}

impl ClockSource {
    /// Get clock source name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Tsc => "TSC",
            Self::Hpet => "HPET",
            Self::Pit => "PIT",
            Self::Apic => "APIC",
        }
    }

    /// Get relative precision (higher is better)
    pub const fn precision_rating(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Pit => 1,
            Self::Apic => 2,
            Self::Hpet => 3,
            Self::Tsc => 4,
        }
    }
}

/// Timer mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimerMode {
    /// One-shot timer (fires once)
    OneShot = 0,
    /// Periodic timer (fires repeatedly)
    Periodic = 1,
    /// Deadline mode (TSC deadline)
    Deadline = 2,
}

/// Timer state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimerState {
    /// Timer is pending (waiting to fire)
    Pending = 0,
    /// Timer is active (currently firing)
    Active = 1,
    /// Timer has completed
    Completed = 2,
    /// Timer was cancelled
    Cancelled = 3,
}

/// Sleep strategy for long delays
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SleepStrategy {
    /// Busy wait with PAUSE instruction
    BusyWait = 0,
    /// Use HLT instruction (requires interrupts)
    Halt = 1,
    /// Hybrid approach based on duration
    Adaptive = 2,
    /// Yield to scheduler
    Yield = 3,
}

// ============================================================================
// Timer Callback Types
// ============================================================================

/// Timer callback trait
pub trait TimerCallback: Send + Sync {
    /// Execute the callback
    fn call(&self);

    /// Get callback name for debugging
    fn name(&self) -> &'static str {
        "anonymous"
    }
}

/// Boxed timer callback
pub type BoxedCallback = Box<dyn TimerCallback>;

/// Simple function callback wrapper
struct FnCallback<F: Fn() + Send + Sync + 'static> {
    func: F,
}

impl<F: Fn() + Send + Sync + 'static> TimerCallback for FnCallback<F> {
    fn call(&self) {
        (self.func)()
    }
}

/// Timer entry in the timer wheel
struct TimerEntry {
    /// Timer ID
    id: u64,
    /// Expiry time in nanoseconds since boot
    expiry_ns: u64,
    /// Timer mode
    mode: TimerMode,
    /// Interval for periodic timers
    interval_ns: u64,
    /// Callback to execute
    callback: BoxedCallback,
    /// Timer state
    state: TimerState,
    /// Creation timestamp
    created_ns: u64,
}

// ============================================================================
// Clock Source State
// ============================================================================

/// TSC calibration data
struct TscCalibration {
    /// Measured TSC frequency in Hz
    frequency_hz: u64,
    /// TSC value at boot time
    boot_tsc: u64,
    /// Calibration confidence (0-100)
    confidence: u8,
    /// Is TSC invariant (constant rate)?
    invariant: bool,
    /// Does CPU support RDTSCP?
    has_rdtscp: bool,
    /// TSC deadline mode supported?
    deadline_mode: bool,
}

impl Default for TscCalibration {
    fn default() -> Self {
        Self {
            frequency_hz: 0,
            boot_tsc: 0,
            confidence: 0,
            invariant: false,
            has_rdtscp: false,
            deadline_mode: false,
        }
    }
}

/// HPET state
struct HpetState {
    /// HPET base address
    base_address: u64,
    /// Counter period in femtoseconds
    period_fs: u32,
    /// Number of timers
    num_timers: u8,
    /// Is 64-bit counter?
    is_64bit: bool,
    /// Legacy replacement capable?
    legacy_capable: bool,
    /// Counter value at boot
    boot_counter: u64,
}

impl Default for HpetState {
    fn default() -> Self {
        Self {
            base_address: 0,
            period_fs: 0,
            num_timers: 0,
            is_64bit: false,
            legacy_capable: false,
            boot_counter: 0,
        }
    }
}

/// PIT state
struct PitState {
    /// Configured frequency in Hz
    frequency_hz: u32,
    /// Divisor value
    divisor: u16,
    /// Tick counter
    ticks: AtomicU64,
}

impl Default for PitState {
    fn default() -> Self {
        Self {
            frequency_hz: 0,
            divisor: 0,
            ticks: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Per-CPU Timer State
// ============================================================================

/// Maximum number of supported CPUs
const MAX_CPUS: usize = 256;

/// Per-CPU timer data
struct PerCpuTimer {
    /// CPU ID
    cpu_id: u32,
    /// Is this CPU's timer initialized?
    initialized: bool,
    /// Local APIC timer frequency
    apic_frequency: u64,
    /// APIC timer divisor
    apic_divisor: u8,
    /// TSC offset for this CPU (for synchronization)
    tsc_offset: i64,
    /// Number of timer interrupts on this CPU
    interrupt_count: u64,
    /// Last interrupt timestamp
    last_interrupt_ns: u64,
}

impl Default for PerCpuTimer {
    fn default() -> Self {
        Self {
            cpu_id: 0,
            initialized: false,
            apic_frequency: 0,
            apic_divisor: 1,
            tsc_offset: 0,
            interrupt_count: 0,
            last_interrupt_ns: 0,
        }
    }
}

// ============================================================================
// Timer Statistics
// ============================================================================

/// Comprehensive timer statistics
#[derive(Debug, Clone, Default)]
pub struct TimerStatistics {
    /// Primary clock source in use
    pub clock_source: ClockSource,
    /// TSC frequency in Hz
    pub tsc_frequency: u64,
    /// HPET period in femtoseconds
    pub hpet_period_fs: u32,
    /// PIT frequency in Hz
    pub pit_frequency: u32,
    /// System uptime in nanoseconds
    pub uptime_ns: u64,
    /// Number of active timers
    pub active_timers: usize,
    /// Total timers created
    pub timers_created: u64,
    /// Total timers fired
    pub timers_fired: u64,
    /// Total timers cancelled
    pub timers_cancelled: u64,
    /// Timer callback execution time (total ns)
    pub callback_time_ns: u64,
    /// Number of timer ticks processed
    pub ticks_processed: u64,
    /// Longest callback duration
    pub max_callback_ns: u64,
    /// Number of expired timer checks
    pub expiry_checks: u64,
    /// TSC calibration confidence
    pub tsc_confidence: u8,
    /// Is TSC invariant?
    pub tsc_invariant: bool,
    /// Is HPET available?
    pub hpet_available: bool,
    /// Is deadline mode active?
    pub deadline_mode: bool,
    /// Number of initialized CPUs
    pub initialized_cpus: u32,
}

// ============================================================================
// Global State
// ============================================================================

/// Timer initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Primary clock source
static PRIMARY_CLOCK: AtomicU8 = AtomicU8::new(ClockSource::None as u8);

/// TSC calibration data
static TSC_DATA: RwLock<TscCalibration> = RwLock::new(TscCalibration {
    frequency_hz: 0,
    boot_tsc: 0,
    confidence: 0,
    invariant: false,
    has_rdtscp: false,
    deadline_mode: false,
});

/// HPET state
static HPET_STATE: RwLock<HpetState> = RwLock::new(HpetState {
    base_address: 0,
    period_fs: 0,
    num_timers: 0,
    is_64bit: false,
    legacy_capable: false,
    boot_counter: 0,
});

/// PIT state
static PIT_STATE: RwLock<PitState> = RwLock::new(PitState {
    frequency_hz: 0,
    divisor: 0,
    ticks: AtomicU64::new(0),
});

/// Active timers (timer_id -> TimerEntry)
static ACTIVE_TIMERS: RwLock<BTreeMap<u64, TimerEntry>> = RwLock::new(BTreeMap::new());

/// Next timer ID
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

/// Boot timestamp in nanoseconds (for wall clock)
static BOOT_TIMESTAMP_NS: AtomicU64 = AtomicU64::new(0);

/// Per-CPU timer state
static PER_CPU_TIMERS: RwLock<[PerCpuTimer; MAX_CPUS]> = RwLock::new([const { PerCpuTimer {
    cpu_id: 0,
    initialized: false,
    apic_frequency: 0,
    apic_divisor: 1,
    tsc_offset: 0,
    interrupt_count: 0,
    last_interrupt_ns: 0,
} }; MAX_CPUS]);

/// Statistics counters
static STATS_TIMERS_CREATED: AtomicU64 = AtomicU64::new(0);
static STATS_TIMERS_FIRED: AtomicU64 = AtomicU64::new(0);
static STATS_TIMERS_CANCELLED: AtomicU64 = AtomicU64::new(0);
static STATS_CALLBACK_TIME: AtomicU64 = AtomicU64::new(0);
static STATS_MAX_CALLBACK: AtomicU64 = AtomicU64::new(0);
static STATS_TICKS: AtomicU64 = AtomicU64::new(0);
static STATS_EXPIRY_CHECKS: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// TSC Operations
// ============================================================================

/// Read Time Stamp Counter with serialization
#[inline]
pub fn rdtsc() -> u64 {
    let hi: u32;
    let lo: u32;
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Read Time Stamp Counter with processor ID (RDTSCP)
#[inline]
pub fn rdtscp() -> (u64, u32) {
    let hi: u32;
    let lo: u32;
    let aux: u32;
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nostack, preserves_flags, nomem)
        );
    }
    (((hi as u64) << 32) | (lo as u64), aux)
}

/// Check if TSC is available
fn check_tsc_available() -> bool {
    // CPUID.01H:EDX.TSC[bit 4] = 1
    let cpuid_result: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 1",
            "cpuid",
            out("edx") cpuid_result,
            out("eax") _,
            out("ebx") _,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
    }
    (cpuid_result & (1 << 4)) != 0
}

/// Check if TSC is invariant (constant rate)
fn check_tsc_invariant() -> bool {
    // CPUID.80000007H:EDX.InvariantTSC[bit 8] = 1
    let max_extended: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 0x80000000",
            "cpuid",
            out("eax") max_extended,
            out("ebx") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    if max_extended < 0x80000007 {
        return false;
    }
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 0x80000007",
            "cpuid",
            out("edx") edx,
            out("eax") _,
            out("ebx") _,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
    }
    (edx & (1 << 8)) != 0
}

/// Check if RDTSCP is available
fn check_rdtscp_available() -> bool {
    // CPUID.80000001H:EDX.RDTSCP[bit 27] = 1
    let max_extended: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 0x80000000",
            "cpuid",
            out("eax") max_extended,
            out("ebx") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    if max_extended < 0x80000001 {
        return false;
    }
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 0x80000001",
            "cpuid",
            out("edx") edx,
            out("eax") _,
            out("ebx") _,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
    }
    (edx & (1 << 27)) != 0
}

/// Check if TSC deadline mode is supported
fn check_tsc_deadline_available() -> bool {
    // CPUID.01H:ECX.TSC_DEADLINE[bit 24] = 1
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 1",
            "cpuid",
            out("ecx") ecx,
            out("eax") _,
            out("ebx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (ecx & (1 << 24)) != 0
}

/// Calibrate TSC frequency using PIT
fn calibrate_tsc_with_pit() -> TimerResult<u64> {
    const PIT_FREQUENCY: u64 = 1193182; // Hz
    const CALIBRATION_MS: u64 = 50; // Calibrate for 50ms
    const PIT_TICKS: u16 = ((PIT_FREQUENCY * CALIBRATION_MS) / 1000) as u16;

    unsafe {
        // Save speaker port state
        let speaker_port = inb(0x61);

        // Configure PIT channel 2 for one-shot mode
        outb(0x43, 0xB0); // Channel 2, lobyte/hibyte, mode 0
        outb(0x42, (PIT_TICKS & 0xFF) as u8);
        outb(0x42, ((PIT_TICKS >> 8) & 0xFF) as u8);

        // Gate the timer (speaker port bit 0) and enable output (bit 1)
        outb(0x61, (speaker_port & 0xFC) | 0x01);

        // Wait for counter to start
        while (inb(0x61) & 0x20) != 0 {}

        // Read start TSC
        let start_tsc = rdtsc();

        // Wait for counter to finish (bit 5 goes high)
        while (inb(0x61) & 0x20) == 0 {
            core::hint::spin_loop();
        }

        // Read end TSC
        let end_tsc = rdtsc();

        // Restore speaker port
        outb(0x61, speaker_port);

        // Calculate frequency
        let tsc_ticks = end_tsc.saturating_sub(start_tsc);
        if tsc_ticks == 0 {
            return Err(TimerError::TscCalibrationFailed);
        }

        // TSC frequency = ticks / time = ticks / (PIT_TICKS / PIT_FREQUENCY)
        let frequency = (tsc_ticks * PIT_FREQUENCY) / PIT_TICKS as u64;

        Ok(frequency)
    }
}

/// Calibrate TSC frequency using HPET (more accurate)
fn calibrate_tsc_with_hpet(hpet_base: u64) -> TimerResult<u64> {
    const CALIBRATION_NS: u64 = 50_000_000; // 50ms

    unsafe {
        // Read HPET period in femtoseconds
        let capabilities = core::ptr::read_volatile(hpet_base as *const u64);
        let period_fs = (capabilities >> 32) as u32;

        if period_fs == 0 {
            return Err(TimerError::HpetConfigFailed);
        }

        // Calculate HPET ticks for calibration period
        let hpet_ticks_needed = (CALIBRATION_NS * 1_000_000) / period_fs as u64;

        // Read start values
        let counter_reg = (hpet_base + 0xF0) as *const u64;
        let start_hpet = core::ptr::read_volatile(counter_reg);
        let start_tsc = rdtsc();

        // Wait for HPET ticks
        let end_hpet = start_hpet + hpet_ticks_needed;
        while core::ptr::read_volatile(counter_reg) < end_hpet {
            core::hint::spin_loop();
        }

        // Read end TSC
        let end_tsc = rdtsc();
        let actual_hpet = core::ptr::read_volatile(counter_reg);

        // Calculate actual elapsed time in nanoseconds
        let elapsed_hpet = actual_hpet.saturating_sub(start_hpet);
        let elapsed_ns = (elapsed_hpet * period_fs as u64) / 1_000_000;

        if elapsed_ns == 0 {
            return Err(TimerError::TscCalibrationFailed);
        }

        // Calculate TSC frequency
        let tsc_ticks = end_tsc.saturating_sub(start_tsc);
        let frequency = (tsc_ticks * 1_000_000_000) / elapsed_ns;

        Ok(frequency)
    }
}

/// Perform multiple TSC calibrations and return best result
fn calibrate_tsc_frequency() -> TimerResult<(u64, u8)> {
    const NUM_SAMPLES: usize = 5;
    let mut samples = [0u64; NUM_SAMPLES];
    let mut valid_samples = 0;

    // Try HPET calibration first if available
    let hpet_base = HPET_STATE.read().base_address;
    if hpet_base != 0 {
        for sample in samples.iter_mut() {
            if let Ok(freq) = calibrate_tsc_with_hpet(hpet_base) {
                *sample = freq;
                valid_samples += 1;
            }
        }
    }

    // Fall back to PIT if HPET not available or failed
    if valid_samples < 3 {
        valid_samples = 0;
        for sample in samples.iter_mut() {
            if let Ok(freq) = calibrate_tsc_with_pit() {
                *sample = freq;
                valid_samples += 1;
            }
        }
    }

    if valid_samples < 3 {
        return Err(TimerError::TscCalibrationFailed);
    }

    // Sort samples and take median
    samples[..valid_samples].sort_unstable();
    let median = samples[valid_samples / 2];

    // Calculate variance for confidence
    let mut variance: u64 = 0;
    for &sample in &samples[..valid_samples] {
        let diff = if sample > median { sample - median } else { median - sample };
        variance += diff;
    }
    variance /= valid_samples as u64;

    // Confidence based on variance (lower variance = higher confidence)
    let variance_pct = (variance * 100) / median;
    let confidence = if variance_pct == 0 {
        100
    } else if variance_pct < 1 {
        95
    } else if variance_pct < 5 {
        80
    } else if variance_pct < 10 {
        60
    } else {
        40
    };

    Ok((median, confidence))
}

// ============================================================================
// HPET Operations
// ============================================================================

/// HPET register offsets
mod hpet_regs {
    pub const CAPABILITIES: u64 = 0x000;
    pub const CONFIG: u64 = 0x010;
    pub const INTERRUPT_STATUS: u64 = 0x020;
    pub const MAIN_COUNTER: u64 = 0x0F0;
    pub const TIMER0_CONFIG: u64 = 0x100;
    pub const TIMER0_COMPARATOR: u64 = 0x108;
    pub const TIMER0_FSB_ROUTE: u64 = 0x110;
}

/// Detect HPET from ACPI or probe default addresses
fn detect_hpet() -> Option<u64> {
    // Try ACPI first
    if let Some(base) = try_acpi_hpet_detection() {
        if validate_hpet_base(base) {
            return Some(base);
        }
    }

    // Probe default HPET addresses
    const DEFAULT_BASES: [u64; 4] = [
        0xFED00000,
        0xFED01000,
        0xFED02000,
        0xFED03000,
    ];

    for &base in &DEFAULT_BASES {
        if validate_hpet_base(base) {
            return Some(base);
        }
    }

    None
}

/// Try to detect HPET via ACPI tables
fn try_acpi_hpet_detection() -> Option<u64> {
    // Placeholder - would call into ACPI module
    // crate::arch::x86_64::nonos_acpi::devices::get_hpet_base()
    None
}

/// Validate HPET base address
pub fn validate_hpet_base(base: u64) -> bool {
    unsafe {
        let capabilities = core::ptr::read_volatile(base as *const u64);

        // Check revision (bits 0-7, should be > 0)
        let revision = (capabilities & 0xFF) as u8;
        if revision == 0 || revision == 0xFF {
            return false;
        }

        // Check number of timers (bits 8-12, should be > 0)
        let num_timers = ((capabilities >> 8) & 0x1F) as u8;
        if num_timers == 0 {
            return false;
        }

        // Check counter period (bits 32-63, should be reasonable)
        let period_fs = (capabilities >> 32) as u32;
        if period_fs == 0 || period_fs > 100_000_000 {
            return false;
        }

        true
    }
}

/// Initialize HPET
fn init_hpet(base: u64) -> TimerResult<()> {
    unsafe {
        // Read capabilities
        let capabilities = core::ptr::read_volatile(base as *const u64);
        let period_fs = (capabilities >> 32) as u32;
        let num_timers = ((capabilities >> 8) & 0x1F) as u8 + 1;
        let is_64bit = (capabilities & (1 << 13)) != 0;
        let legacy_capable = (capabilities & (1 << 15)) != 0;

        // Stop counter and reset
        let config_reg = (base + hpet_regs::CONFIG) as *mut u64;
        core::ptr::write_volatile(config_reg, 0);

        // Reset counter
        let counter_reg = (base + hpet_regs::MAIN_COUNTER) as *mut u64;
        core::ptr::write_volatile(counter_reg, 0);

        // Read boot counter value
        let boot_counter = core::ptr::read_volatile(counter_reg as *const u64);

        // Enable counter
        core::ptr::write_volatile(config_reg, 1);

        // Update HPET state
        {
            let mut hpet = HPET_STATE.write();
            hpet.base_address = base;
            hpet.period_fs = period_fs;
            hpet.num_timers = num_timers;
            hpet.is_64bit = is_64bit;
            hpet.legacy_capable = legacy_capable;
            hpet.boot_counter = boot_counter;
        }

        Ok(())
    }
}

/// Read HPET counter
#[inline]
pub fn hpet_read_counter() -> Option<u64> {
    let hpet = HPET_STATE.read();
    if hpet.base_address == 0 {
        return None;
    }
    unsafe {
        let counter_reg = (hpet.base_address + hpet_regs::MAIN_COUNTER) as *const u64;
        Some(core::ptr::read_volatile(counter_reg))
    }
}

/// Convert HPET ticks to nanoseconds
#[inline]
pub fn hpet_ticks_to_ns(ticks: u64) -> Option<u64> {
    let hpet = HPET_STATE.read();
    if hpet.period_fs == 0 {
        return None;
    }
    // period_fs is in femtoseconds, divide by 1_000_000 to get nanoseconds
    Some((ticks * hpet.period_fs as u64) / 1_000_000)
}

/// Convert nanoseconds to HPET ticks
#[inline]
pub fn ns_to_hpet_ticks(ns: u64) -> Option<u64> {
    let hpet = HPET_STATE.read();
    if hpet.period_fs == 0 {
        return None;
    }
    Some((ns * 1_000_000) / hpet.period_fs as u64)
}

// ============================================================================
// PIT Operations
// ============================================================================

/// PIT I/O ports
mod pit_ports {
    pub const CHANNEL0: u16 = 0x40;
    pub const CHANNEL1: u16 = 0x41;
    pub const CHANNEL2: u16 = 0x42;
    pub const COMMAND: u16 = 0x43;
    pub const SPEAKER: u16 = 0x61;
}

/// PIT base frequency
const PIT_FREQUENCY: u64 = 1193182;

/// Initialize PIT for periodic interrupts
fn init_pit(frequency_hz: u32) -> TimerResult<()> {
    if frequency_hz == 0 || frequency_hz > 1193182 {
        return Err(TimerError::InvalidConfig);
    }

    let divisor = (PIT_FREQUENCY / frequency_hz as u64) as u16;
    if divisor == 0 {
        return Err(TimerError::InvalidConfig);
    }

    unsafe {
        // Channel 0, lobyte/hibyte, mode 2 (rate generator)
        outb(pit_ports::COMMAND, 0x36);
        outb(pit_ports::CHANNEL0, (divisor & 0xFF) as u8);
        outb(pit_ports::CHANNEL0, ((divisor >> 8) & 0xFF) as u8);
    }

    {
        let mut pit = PIT_STATE.write();
        pit.frequency_hz = frequency_hz;
        pit.divisor = divisor;
        pit.ticks = AtomicU64::new(0);
    }

    Ok(())
}

/// Handle PIT tick interrupt
pub fn pit_tick() {
    let pit = PIT_STATE.read();
    pit.ticks.fetch_add(1, Ordering::Relaxed);
}

/// Get PIT tick count
pub fn pit_get_ticks() -> u64 {
    PIT_STATE.read().ticks.load(Ordering::Relaxed)
}

// ============================================================================
// Port I/O Helpers
// ============================================================================

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nostack, preserves_flags, nomem)
    );
    value
}

#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("al") value,
        in("dx") port,
        options(nostack, preserves_flags, nomem)
    );
}

// ============================================================================
// Time Functions
// ============================================================================

/// Get current time in nanoseconds since boot (monotonic)
#[inline]
pub fn now_ns() -> u64 {
    if !INITIALIZED.load(Ordering::Relaxed) {
        return 0;
    }

    let clock_source = ClockSource::from_u8(PRIMARY_CLOCK.load(Ordering::Relaxed));

    match clock_source {
        ClockSource::Tsc => {
            let tsc = TSC_DATA.read();
            if tsc.frequency_hz == 0 {
                return 0;
            }
            let current_tsc = rdtsc();
            let tsc_diff = current_tsc.saturating_sub(tsc.boot_tsc);
            (tsc_diff * 1_000_000_000) / tsc.frequency_hz
        }
        ClockSource::Hpet => {
            if let Some(counter) = hpet_read_counter() {
                let hpet = HPET_STATE.read();
                let diff = counter.saturating_sub(hpet.boot_counter);
                (diff * hpet.period_fs as u64) / 1_000_000
            } else {
                0
            }
        }
        ClockSource::Pit => {
            let pit = PIT_STATE.read();
            if pit.frequency_hz == 0 {
                return 0;
            }
            let ticks = pit.ticks.load(Ordering::Relaxed);
            (ticks * 1_000_000_000) / pit.frequency_hz as u64
        }
        _ => 0,
    }
}

/// Get current time in nanoseconds (checked version)
pub fn now_ns_checked() -> Option<u64> {
    if INITIALIZED.load(Ordering::Relaxed) {
        Some(now_ns())
    } else {
        None
    }
}

/// Get current time in microseconds since boot
#[inline]
pub fn now_us() -> u64 {
    now_ns() / 1_000
}

/// Get current time in milliseconds since boot
#[inline]
pub fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

/// Get current time in seconds since boot
#[inline]
pub fn now_secs() -> u64 {
    now_ns() / 1_000_000_000
}

/// Get timestamp in milliseconds (alias for compatibility)
#[inline]
pub fn get_timestamp_ms() -> Option<u64> {
    now_ns_checked().map(|ns| ns / 1_000_000)
}

/// Get system uptime as a formatted string
pub fn uptime_string() -> String {
    let total_secs = now_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{}d {:02}:{:02}:{:02}", days, hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

impl ClockSource {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => ClockSource::Tsc,
            2 => ClockSource::Hpet,
            3 => ClockSource::Pit,
            4 => ClockSource::Apic,
            _ => ClockSource::None,
        }
    }
}

// ============================================================================
// TSC Conversion Functions
// ============================================================================

/// Get TSC frequency in Hz
#[inline]
pub fn get_tsc_frequency() -> u64 {
    TSC_DATA.read().frequency_hz
}

/// Convert TSC ticks to nanoseconds
#[inline]
pub fn tsc_to_ns(tsc_ticks: u64) -> u64 {
    let freq = TSC_DATA.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (tsc_ticks * 1_000_000_000) / freq
}

/// Convert nanoseconds to TSC ticks
#[inline]
pub fn ns_to_tsc(nanoseconds: u64) -> u64 {
    let freq = TSC_DATA.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (nanoseconds * freq) / 1_000_000_000
}

/// Convert TSC ticks to microseconds
#[inline]
pub fn tsc_to_us(tsc_ticks: u64) -> u64 {
    let freq = TSC_DATA.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (tsc_ticks * 1_000_000) / freq
}

/// Convert microseconds to TSC ticks
#[inline]
pub fn us_to_tsc(microseconds: u64) -> u64 {
    let freq = TSC_DATA.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (microseconds * freq) / 1_000_000
}

// ============================================================================
// Delay and Sleep Functions
// ============================================================================

/// Busy-wait delay for specified nanoseconds
pub fn delay_ns(nanoseconds: u64) {
    if !INITIALIZED.load(Ordering::Relaxed) {
        // Fallback to simple loop if not initialized
        for _ in 0..nanoseconds / 100 {
            core::hint::spin_loop();
        }
        return;
    }

    let start = now_ns();
    let end = start.saturating_add(nanoseconds);

    while now_ns() < end {
        core::hint::spin_loop();
    }
}

/// Precise delay using TSC
pub fn delay_precise_ns(nanoseconds: u64) {
    let tsc = TSC_DATA.read();
    if tsc.frequency_hz == 0 {
        delay_ns(nanoseconds);
        return;
    }

    let target_ticks = (nanoseconds * tsc.frequency_hz) / 1_000_000_000;
    let start_tsc = rdtsc();
    let end_tsc = start_tsc.saturating_add(target_ticks);

    while rdtsc() < end_tsc {
        unsafe {
            core::arch::asm!("pause", options(nostack, preserves_flags, nomem));
        }
    }
}

/// Delay for specified microseconds
#[inline]
pub fn delay_us(microseconds: u64) {
    delay_precise_ns(microseconds * 1_000)
}

/// Delay for specified milliseconds
#[inline]
pub fn delay_ms(milliseconds: u64) {
    delay_precise_ns(milliseconds * 1_000_000)
}

/// Busy-wait sleep (alias for delay_ns)
#[inline]
pub fn busy_sleep_ns(nanoseconds: u64) {
    delay_precise_ns(nanoseconds)
}

/// Sleep with specified strategy
pub fn sleep_ns(nanoseconds: u64, strategy: SleepStrategy) {
    if nanoseconds == 0 {
        return;
    }

    match strategy {
        SleepStrategy::BusyWait => {
            delay_precise_ns(nanoseconds);
        }
        SleepStrategy::Halt => {
            sleep_with_halt(nanoseconds);
        }
        SleepStrategy::Adaptive => {
            sleep_adaptive(nanoseconds);
        }
        SleepStrategy::Yield => {
            sleep_with_yield(nanoseconds);
        }
    }
}

/// Sleep using HLT instruction (power efficient)
fn sleep_with_halt(nanoseconds: u64) {
    let start = now_ns();
    let end = start.saturating_add(nanoseconds);

    while now_ns() < end {
        unsafe {
            // Enable interrupts, halt until interrupt, then disable
            core::arch::asm!(
                "sti",
                "hlt",
                "cli",
                options(nostack, preserves_flags, nomem)
            );
        }
    }
}

/// Adaptive sleep based on duration
fn sleep_adaptive(nanoseconds: u64) {
    let start = now_ns();
    let end = start.saturating_add(nanoseconds);

    while now_ns() < end {
        let remaining = end.saturating_sub(now_ns());

        if remaining > 10_000_000 {
            // > 10ms: use HLT
            unsafe {
                core::arch::asm!(
                    "sti",
                    "hlt",
                    "cli",
                    options(nostack, preserves_flags, nomem)
                );
            }
        } else if remaining > 1_000 {
            // > 1us: use PAUSE
            for _ in 0..(remaining / 100).min(1000) {
                unsafe {
                    core::arch::asm!("pause", options(nostack, preserves_flags, nomem));
                }
            }
        } else {
            // < 1us: tight loop
            unsafe {
                core::arch::asm!("nop", options(nostack, preserves_flags, nomem));
            }
        }
    }
}

/// Sleep by yielding to scheduler
fn sleep_with_yield(nanoseconds: u64) {
    let start = now_ns();
    let end = start.saturating_add(nanoseconds);

    while now_ns() < end {
        // Try to yield to scheduler if available
        // crate::sched::yield_now();
        core::hint::spin_loop();
    }
}

/// Long sleep with callback for periodic work
pub fn sleep_long_ns<F>(nanoseconds: u64, callback: F)
where
    F: Fn(),
{
    let start = now_ns();
    let end = start.saturating_add(nanoseconds);

    while now_ns() < end {
        callback();

        let remaining = end.saturating_sub(now_ns());

        if remaining > 10_000_000 {
            // Use HLT for longer waits
            unsafe {
                core::arch::asm!(
                    "sti",
                    "hlt",
                    "cli",
                    options(nostack, preserves_flags, nomem)
                );
            }
        } else if remaining > 1_000 {
            for _ in 0..(remaining / 100).min(100) {
                unsafe {
                    core::arch::asm!("pause", options(nostack, preserves_flags, nomem));
                }
            }
        } else {
            unsafe {
                core::arch::asm!("nop", options(nostack, preserves_flags, nomem));
            }
        }
    }
}

// ============================================================================
// Timer Management
// ============================================================================

/// Create a one-shot timer
pub fn create_timer<F>(delay_ns: u64, callback: F) -> TimerResult<u64>
where
    F: Fn() + Send + Sync + 'static,
{
    create_timer_with_mode(delay_ns, 0, TimerMode::OneShot, callback)
}

/// Create a periodic timer
pub fn create_periodic_timer<F>(interval_ns: u64, callback: F) -> TimerResult<u64>
where
    F: Fn() + Send + Sync + 'static,
{
    create_timer_with_mode(interval_ns, interval_ns, TimerMode::Periodic, callback)
}

/// Create a timer with specified mode
fn create_timer_with_mode<F>(
    delay_ns: u64,
    interval_ns: u64,
    mode: TimerMode,
    callback: F,
) -> TimerResult<u64>
where
    F: Fn() + Send + Sync + 'static,
{
    if !INITIALIZED.load(Ordering::Relaxed) {
        return Err(TimerError::NotInitialized);
    }

    let timer_id = NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed);
    let current_time = now_ns();
    let expiry_ns = current_time.saturating_add(delay_ns);

    let entry = TimerEntry {
        id: timer_id,
        expiry_ns,
        mode,
        interval_ns,
        callback: Box::new(FnCallback { func: callback }),
        state: TimerState::Pending,
        created_ns: current_time,
    };

    {
        let mut timers = ACTIVE_TIMERS.write();
        timers.insert(timer_id, entry);
    }

    STATS_TIMERS_CREATED.fetch_add(1, Ordering::Relaxed);

    Ok(timer_id)
}

/// High-resolution timer (alias for create_timer)
pub fn hrtimer_after_ns<F>(delay_ns: u64, callback: F) -> u64
where
    F: Fn() + Send + Sync + 'static,
{
    create_timer(delay_ns, callback).unwrap_or(0)
}

/// Cancel a timer by ID
pub fn cancel_timer(timer_id: u64) -> bool {
    let mut timers = ACTIVE_TIMERS.write();
    if let Some(mut entry) = timers.remove(&timer_id) {
        entry.state = TimerState::Cancelled;
        STATS_TIMERS_CANCELLED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Get the number of active timers
pub fn get_active_timer_count() -> usize {
    ACTIVE_TIMERS.read().len()
}

/// Get timer state by ID
pub fn get_timer_state(timer_id: u64) -> Option<TimerState> {
    ACTIVE_TIMERS.read().get(&timer_id).map(|e| e.state)
}

/// Check and process expired timers
pub fn process_expired_timers() {
    STATS_EXPIRY_CHECKS.fetch_add(1, Ordering::Relaxed);

    let current_time = now_ns();
    let mut to_fire: Vec<(u64, BoxedCallback, TimerMode, u64)> = Vec::new();
    let mut to_reschedule: Vec<(u64, u64)> = Vec::new();

    {
        let mut timers = ACTIVE_TIMERS.write();
        let mut expired_ids = Vec::new();

        for (&id, entry) in timers.iter() {
            if current_time >= entry.expiry_ns && entry.state == TimerState::Pending {
                expired_ids.push(id);
            }
        }

        for id in expired_ids {
            if let Some(mut entry) = timers.remove(&id) {
                entry.state = TimerState::Active;

                if entry.mode == TimerMode::Periodic && entry.interval_ns > 0 {
                    to_reschedule.push((id, entry.interval_ns));
                }

                // We need to extract callback carefully
                to_fire.push((id, entry.callback, entry.mode, entry.interval_ns));
            }
        }
    }

    // Fire callbacks outside of lock
    for (id, callback, mode, interval) in to_fire {
        let start = now_ns();
        callback.call();
        let duration = now_ns().saturating_sub(start);

        STATS_TIMERS_FIRED.fetch_add(1, Ordering::Relaxed);
        STATS_CALLBACK_TIME.fetch_add(duration, Ordering::Relaxed);

        // Update max callback time
        let mut current_max = STATS_MAX_CALLBACK.load(Ordering::Relaxed);
        while duration > current_max {
            match STATS_MAX_CALLBACK.compare_exchange_weak(
                current_max,
                duration,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => current_max = v,
            }
        }

        // Reschedule periodic timers
        if mode == TimerMode::Periodic && interval > 0 {
            let new_expiry = now_ns().saturating_add(interval);
            let entry = TimerEntry {
                id,
                expiry_ns: new_expiry,
                mode,
                interval_ns: interval,
                callback,
                state: TimerState::Pending,
                created_ns: now_ns(),
            };

            let mut timers = ACTIVE_TIMERS.write();
            timers.insert(id, entry);
        }
    }
}

/// Timer tick handler (called from interrupt)
pub fn tick() {
    STATS_TICKS.fetch_add(1, Ordering::Relaxed);
    process_expired_timers();

    // Notify scheduler if available
    // if let Some(scheduler) = crate::sched::current_scheduler() {
    //     scheduler.tick();
    // }
}

// ============================================================================
// HPET Timer Interface
// ============================================================================

/// Get HPET counter value if available
pub fn get_hpet_counter() -> Option<u64> {
    hpet_read_counter()
}

/// Convert HPET ticks to nanoseconds
pub fn hpet_to_ns(hpet_ticks: u64) -> Option<u64> {
    hpet_ticks_to_ns(hpet_ticks)
}

/// Check if HPET is available
pub fn is_hpet_available() -> bool {
    HPET_STATE.read().base_address != 0
}

/// Get HPET base address
pub fn get_hpet_base() -> Option<u64> {
    let base = HPET_STATE.read().base_address;
    if base != 0 {
        Some(base)
    } else {
        None
    }
}

// ============================================================================
// Deadline Mode
// ============================================================================

/// Check if TSC deadline mode is available and active
pub fn is_deadline_mode() -> bool {
    TSC_DATA.read().deadline_mode && INITIALIZED.load(Ordering::Relaxed)
}

/// Set TSC deadline for next interrupt
pub fn set_tsc_deadline(deadline_tsc: u64) -> TimerResult<()> {
    if !TSC_DATA.read().deadline_mode {
        return Err(TimerError::DeadlineModeUnsupported);
    }

    // Write to IA32_TSC_DEADLINE MSR (0x6E0)
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x6E0u32,
            in("eax") (deadline_tsc & 0xFFFFFFFF) as u32,
            in("edx") (deadline_tsc >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }

    Ok(())
}

/// Set deadline in nanoseconds from now
pub fn set_deadline_ns(delay_ns: u64) -> TimerResult<()> {
    let current_tsc = rdtsc();
    let delay_ticks = ns_to_tsc(delay_ns);
    let deadline = current_tsc.saturating_add(delay_ticks);
    set_tsc_deadline(deadline)
}

// ============================================================================
// Per-CPU Timer Functions
// ============================================================================

/// Initialize timer for current CPU
pub fn init_per_cpu(cpu_id: u32) -> TimerResult<()> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(TimerError::InvalidConfig);
    }

    let mut per_cpu = PER_CPU_TIMERS.write();
    let cpu_timer = &mut per_cpu[cpu_id as usize];

    cpu_timer.cpu_id = cpu_id;
    cpu_timer.initialized = true;

    // Calculate TSC offset for synchronization
    let master_tsc = rdtsc();
    cpu_timer.tsc_offset = 0; // BSP is reference

    Ok(())
}

/// Get per-CPU timer statistics
pub fn get_per_cpu_stats(cpu_id: u32) -> Option<(u64, u64)> {
    if cpu_id as usize >= MAX_CPUS {
        return None;
    }

    let per_cpu = PER_CPU_TIMERS.read();
    let cpu_timer = &per_cpu[cpu_id as usize];

    if cpu_timer.initialized {
        Some((cpu_timer.interrupt_count, cpu_timer.last_interrupt_ns))
    } else {
        None
    }
}

/// Record timer interrupt on current CPU
pub fn record_cpu_interrupt(cpu_id: u32) {
    if cpu_id as usize >= MAX_CPUS {
        return;
    }

    let mut per_cpu = PER_CPU_TIMERS.write();
    let cpu_timer = &mut per_cpu[cpu_id as usize];

    if cpu_timer.initialized {
        cpu_timer.interrupt_count += 1;
        cpu_timer.last_interrupt_ns = now_ns();
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the timer system
pub fn init() -> TimerResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TimerError::AlreadyInitialized);
    }

    // Try to detect and initialize HPET first (needed for accurate TSC calibration)
    let hpet_available = if let Some(base) = detect_hpet() {
        init_hpet(base).is_ok()
    } else {
        false
    };

    // Check TSC availability and features
    let tsc_available = check_tsc_available();
    let tsc_invariant = check_tsc_invariant();
    let has_rdtscp = check_rdtscp_available();
    let deadline_mode = check_tsc_deadline_available();

    // Initialize primary clock source
    let primary_source = if tsc_available && tsc_invariant {
        // Calibrate TSC
        let boot_tsc = rdtsc();
        match calibrate_tsc_frequency() {
            Ok((freq, confidence)) => {
                {
                    let mut tsc = TSC_DATA.write();
                    tsc.frequency_hz = freq;
                    tsc.boot_tsc = boot_tsc;
                    tsc.confidence = confidence;
                    tsc.invariant = tsc_invariant;
                    tsc.has_rdtscp = has_rdtscp;
                    tsc.deadline_mode = deadline_mode;
                }
                ClockSource::Tsc
            }
            Err(_) => {
                if hpet_available {
                    ClockSource::Hpet
                } else {
                    // Fall back to PIT
                    if init_pit(1000).is_ok() {
                        ClockSource::Pit
                    } else {
                        INITIALIZED.store(false, Ordering::SeqCst);
                        return Err(TimerError::NoClockSource);
                    }
                }
            }
        }
    } else if hpet_available {
        ClockSource::Hpet
    } else {
        // Fall back to PIT
        if init_pit(1000).is_ok() {
            ClockSource::Pit
        } else {
            INITIALIZED.store(false, Ordering::SeqCst);
            return Err(TimerError::NoClockSource);
        }
    };

    PRIMARY_CLOCK.store(primary_source as u8, Ordering::SeqCst);

    // Initialize BSP per-CPU timer
    init_per_cpu(0)?;

    // Clear any existing timers
    ACTIVE_TIMERS.write().clear();

    Ok(())
}

/// Initialize with specific frequency (for PIT-based timing)
pub fn init_with_freq(freq_hz: u32) -> TimerResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TimerError::AlreadyInitialized);
    }

    // Initialize PIT with specified frequency
    init_pit(freq_hz)?;

    // Try to detect HPET as secondary source
    if let Some(base) = detect_hpet() {
        let _ = init_hpet(base);
    }

    // Check and calibrate TSC if available
    if check_tsc_available() {
        let boot_tsc = rdtsc();
        if let Ok((freq, confidence)) = calibrate_tsc_frequency() {
            let mut tsc = TSC_DATA.write();
            tsc.frequency_hz = freq;
            tsc.boot_tsc = boot_tsc;
            tsc.confidence = confidence;
            tsc.invariant = check_tsc_invariant();
            tsc.has_rdtscp = check_rdtscp_available();
            tsc.deadline_mode = check_tsc_deadline_available();
        }
    }

    // Use TSC if available and invariant, otherwise use PIT
    let primary = if check_tsc_available() && check_tsc_invariant() {
        ClockSource::Tsc
    } else {
        ClockSource::Pit
    };

    PRIMARY_CLOCK.store(primary as u8, Ordering::SeqCst);

    // Initialize BSP
    init_per_cpu(0)?;

    Ok(())
}

/// Check if timer system is initialized
#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// Get current clock source
pub fn get_clock_source() -> ClockSource {
    ClockSource::from_u8(PRIMARY_CLOCK.load(Ordering::Relaxed))
}

// ============================================================================
// Statistics
// ============================================================================

/// Get comprehensive timer statistics
pub fn get_statistics() -> TimerStatistics {
    let tsc = TSC_DATA.read();
    let hpet = HPET_STATE.read();
    let pit = PIT_STATE.read();

    // Count initialized CPUs
    let per_cpu = PER_CPU_TIMERS.read();
    let initialized_cpus = per_cpu.iter().filter(|c| c.initialized).count() as u32;

    TimerStatistics {
        clock_source: get_clock_source(),
        tsc_frequency: tsc.frequency_hz,
        hpet_period_fs: hpet.period_fs,
        pit_frequency: pit.frequency_hz,
        uptime_ns: now_ns(),
        active_timers: get_active_timer_count(),
        timers_created: STATS_TIMERS_CREATED.load(Ordering::Relaxed),
        timers_fired: STATS_TIMERS_FIRED.load(Ordering::Relaxed),
        timers_cancelled: STATS_TIMERS_CANCELLED.load(Ordering::Relaxed),
        callback_time_ns: STATS_CALLBACK_TIME.load(Ordering::Relaxed),
        ticks_processed: STATS_TICKS.load(Ordering::Relaxed),
        max_callback_ns: STATS_MAX_CALLBACK.load(Ordering::Relaxed),
        expiry_checks: STATS_EXPIRY_CHECKS.load(Ordering::Relaxed),
        tsc_confidence: tsc.confidence,
        tsc_invariant: tsc.invariant,
        hpet_available: hpet.base_address != 0,
        deadline_mode: tsc.deadline_mode,
        initialized_cpus,
    }
}

/// Get timer statistics (legacy API)
pub fn get_timer_stats() -> TimerStats {
    TimerStats {
        tsc_frequency: get_tsc_frequency(),
        active_timers: get_active_timer_count(),
        hpet_available: is_hpet_available(),
        uptime_ns: now_ns(),
    }
}

/// Legacy timer stats structure
#[derive(Debug, Clone)]
pub struct TimerStats {
    pub tsc_frequency: u64,
    pub active_timers: usize,
    pub hpet_available: bool,
    pub uptime_ns: u64,
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if a given HPET base address is valid
pub fn is_valid_hpet_base(base: u64) -> bool {
    validate_hpet_base(base)
}

/// Format nanoseconds as human-readable duration
pub fn format_duration_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{}ns", ns)
    } else if ns < 1_000_000 {
        format!("{}.{}us", ns / 1_000, (ns % 1_000) / 100)
    } else if ns < 1_000_000_000 {
        format!("{}.{}ms", ns / 1_000_000, (ns % 1_000_000) / 100_000)
    } else {
        format!("{}.{}s", ns / 1_000_000_000, (ns % 1_000_000_000) / 100_000_000)
    }
}

/// Convert frequency to period in nanoseconds
pub fn freq_to_period_ns(freq_hz: u64) -> u64 {
    if freq_hz == 0 {
        return 0;
    }
    1_000_000_000 / freq_hz
}

/// Convert period in nanoseconds to frequency
pub fn period_ns_to_freq(period_ns: u64) -> u64 {
    if period_ns == 0 {
        return 0;
    }
    1_000_000_000 / period_ns
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_error_messages() {
        assert_eq!(TimerError::NotInitialized.as_str(), "Timer system not initialized");
        assert_eq!(TimerError::TscCalibrationFailed.as_str(), "TSC calibration failed");
        assert_eq!(TimerError::HpetUnavailable.as_str(), "HPET not available");
    }

    #[test]
    fn test_clock_source_properties() {
        assert_eq!(ClockSource::None.name(), "None");
        assert_eq!(ClockSource::Tsc.name(), "TSC");
        assert_eq!(ClockSource::Hpet.name(), "HPET");
        assert_eq!(ClockSource::Pit.name(), "PIT");
        assert_eq!(ClockSource::Apic.name(), "APIC");

        assert!(ClockSource::Tsc.precision_rating() > ClockSource::Pit.precision_rating());
        assert!(ClockSource::Hpet.precision_rating() > ClockSource::Pit.precision_rating());
    }

    #[test]
    fn test_clock_source_conversion() {
        assert_eq!(ClockSource::from_u8(0), ClockSource::None);
        assert_eq!(ClockSource::from_u8(1), ClockSource::Tsc);
        assert_eq!(ClockSource::from_u8(2), ClockSource::Hpet);
        assert_eq!(ClockSource::from_u8(3), ClockSource::Pit);
        assert_eq!(ClockSource::from_u8(4), ClockSource::Apic);
        assert_eq!(ClockSource::from_u8(255), ClockSource::None);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration_ns(500), "500ns");
        assert_eq!(format_duration_ns(1_500), "1.5us");
        assert_eq!(format_duration_ns(1_500_000), "1.5ms");
        assert_eq!(format_duration_ns(1_500_000_000), "1.5s");
    }

    #[test]
    fn test_frequency_period_conversion() {
        assert_eq!(freq_to_period_ns(1_000_000), 1_000);
        assert_eq!(freq_to_period_ns(1_000), 1_000_000);
        assert_eq!(freq_to_period_ns(0), 0);

        assert_eq!(period_ns_to_freq(1_000_000), 1_000);
        assert_eq!(period_ns_to_freq(1_000), 1_000_000);
        assert_eq!(period_ns_to_freq(0), 0);
    }

    #[test]
    fn test_timer_mode() {
        assert_eq!(TimerMode::OneShot as u8, 0);
        assert_eq!(TimerMode::Periodic as u8, 1);
        assert_eq!(TimerMode::Deadline as u8, 2);
    }

    #[test]
    fn test_timer_state() {
        assert_eq!(TimerState::Pending as u8, 0);
        assert_eq!(TimerState::Active as u8, 1);
        assert_eq!(TimerState::Completed as u8, 2);
        assert_eq!(TimerState::Cancelled as u8, 3);
    }

    #[test]
    fn test_sleep_strategy() {
        assert_eq!(SleepStrategy::BusyWait as u8, 0);
        assert_eq!(SleepStrategy::Halt as u8, 1);
        assert_eq!(SleepStrategy::Adaptive as u8, 2);
        assert_eq!(SleepStrategy::Yield as u8, 3);
    }

    #[test]
    fn test_default_tsc_calibration() {
        let cal = TscCalibration::default();
        assert_eq!(cal.frequency_hz, 0);
        assert_eq!(cal.boot_tsc, 0);
        assert_eq!(cal.confidence, 0);
        assert!(!cal.invariant);
        assert!(!cal.has_rdtscp);
        assert!(!cal.deadline_mode);
    }

    #[test]
    fn test_default_hpet_state() {
        let state = HpetState::default();
        assert_eq!(state.base_address, 0);
        assert_eq!(state.period_fs, 0);
        assert_eq!(state.num_timers, 0);
        assert!(!state.is_64bit);
        assert!(!state.legacy_capable);
    }

    #[test]
    fn test_default_pit_state() {
        let state = PitState::default();
        assert_eq!(state.frequency_hz, 0);
        assert_eq!(state.divisor, 0);
        assert_eq!(state.ticks.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_default_per_cpu_timer() {
        let timer = PerCpuTimer::default();
        assert_eq!(timer.cpu_id, 0);
        assert!(!timer.initialized);
        assert_eq!(timer.apic_frequency, 0);
        assert_eq!(timer.tsc_offset, 0);
        assert_eq!(timer.interrupt_count, 0);
    }

    #[test]
    fn test_timer_statistics_default() {
        let stats = TimerStatistics::default();
        assert_eq!(stats.clock_source, ClockSource::None);
        assert_eq!(stats.tsc_frequency, 0);
        assert_eq!(stats.active_timers, 0);
        assert_eq!(stats.timers_created, 0);
        assert!(!stats.hpet_available);
    }
}
