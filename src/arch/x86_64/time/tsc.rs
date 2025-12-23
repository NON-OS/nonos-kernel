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
//
//! x86_64 Time Stamp Counter (TSC) Driver
//!
//! ## Calibration Hierarchy
//! 1. **CPUID.15H** - Direct frequency from CPU (most accurate)
//! 2. **HPET calibration** - Use HPET as reference (high accuracy)
//! 3. **PIT calibration** - Use PIT as reference (fallback)

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicI64, Ordering};
use spin::RwLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of CPUs for per-CPU tracking
const MAX_CPUS: usize = 256;

/// Default calibration duration in milliseconds
const DEFAULT_CALIBRATION_MS: u32 = 50;

/// Number of calibration samples for accuracy
const CALIBRATION_SAMPLES: usize = 5;

/// Minimum acceptable TSC frequency (100 MHz)
const MIN_FREQUENCY: u64 = 100_000_000;

/// Maximum acceptable TSC frequency (10 GHz)
const MAX_FREQUENCY: u64 = 10_000_000_000;

// ============================================================================
// Error Handling
// ============================================================================

/// TSC error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TscError {
    /// TSC not available
    NotAvailable = 0,
    /// TSC not initialized
    NotInitialized = 1,
    /// Already initialized
    AlreadyInitialized = 2,
    /// TSC not calibrated
    NotCalibrated = 3,
    /// Calibration failed
    CalibrationFailed = 4,
    /// Invalid frequency
    InvalidFrequency = 5,
    /// TSC not invariant (unstable)
    NotInvariant = 6,
    /// RDTSCP not available
    RdtscpUnavailable = 7,
    /// Deadline mode not supported
    DeadlineModeUnavailable = 8,
    /// Per-CPU not initialized
    PerCpuNotInit = 9,
    /// Overflow in calculation
    Overflow = 10,
    /// CPUID not available
    CpuidUnavailable = 11,
    /// Reference timer not available
    NoReferenceTimer = 12,
}

impl TscError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotAvailable => "TSC not available",
            Self::NotInitialized => "TSC not initialized",
            Self::AlreadyInitialized => "TSC already initialized",
            Self::NotCalibrated => "TSC not calibrated",
            Self::CalibrationFailed => "TSC calibration failed",
            Self::InvalidFrequency => "Invalid TSC frequency",
            Self::NotInvariant => "TSC not invariant (unstable across P-states)",
            Self::RdtscpUnavailable => "RDTSCP instruction not available",
            Self::DeadlineModeUnavailable => "TSC deadline mode not supported",
            Self::PerCpuNotInit => "Per-CPU TSC not initialized",
            Self::Overflow => "Overflow in time calculation",
            Self::CpuidUnavailable => "CPUID not available",
            Self::NoReferenceTimer => "No reference timer for calibration",
        }
    }
}

/// Result type for TSC operations
pub type TscResult<T> = Result<T, TscError>;

// ============================================================================
// TSC Features
// ============================================================================

/// TSC feature flags
#[derive(Debug, Clone, Copy, Default)]
pub struct TscFeatures {
    /// TSC instruction available
    pub tsc_available: bool,
    /// RDTSCP instruction available
    pub rdtscp_available: bool,
    /// Invariant TSC (constant rate)
    pub invariant_tsc: bool,
    /// TSC deadline mode for APIC timer
    pub deadline_mode: bool,
    /// CPUID.15H frequency enumeration
    pub cpuid_frequency: bool,
    /// Adjust TSC on write supported
    pub tsc_adjust: bool,
    /// Always running timer (ARAT)
    pub always_running: bool,
}

impl TscFeatures {
    /// Check if TSC is reliable for timekeeping
    pub const fn is_reliable(&self) -> bool {
        self.tsc_available && self.invariant_tsc
    }

    /// Check if TSC is available at all
    pub const fn is_available(&self) -> bool {
        self.tsc_available
    }
}

// ============================================================================
// Calibration Source
// ============================================================================

/// TSC calibration source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CalibrationSource {
    /// Not calibrated
    #[default]
    None = 0,
    /// CPUID.15H crystal frequency
    Cpuid = 1,
    /// HPET reference
    Hpet = 2,
    /// PIT reference
    Pit = 3,
    /// Known CPU frequency
    KnownFrequency = 4,
    /// Cross-calibration from another CPU
    CrossCalibration = 5,
}

impl CalibrationSource {
    /// Get source name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Cpuid => "CPUID.15H",
            Self::Hpet => "HPET",
            Self::Pit => "PIT",
            Self::KnownFrequency => "Known Frequency",
            Self::CrossCalibration => "Cross-Calibration",
        }
    }

    /// Get relative accuracy (higher is better)
    pub const fn accuracy_rating(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Pit => 2,
            Self::Hpet => 3,
            Self::KnownFrequency => 4,
            Self::CrossCalibration => 3,
            Self::Cpuid => 5,
        }
    }
}

// ============================================================================
// TSC State
// ============================================================================

/// TSC calibration state
#[derive(Debug, Clone)]
struct TscCalibration {
    /// Measured frequency in Hz
    frequency_hz: u64,
    /// TSC value at boot time
    boot_tsc: u64,
    /// Calibration source used
    source: CalibrationSource,
    /// Calibration confidence (0-100)
    confidence: u8,
    /// Calibration timestamp (TSC value)
    calibration_tsc: u64,
    /// Number of calibration samples taken
    samples: u8,
}

impl Default for TscCalibration {
    fn default() -> Self {
        Self {
            frequency_hz: 0,
            boot_tsc: 0,
            source: CalibrationSource::None,
            confidence: 0,
            calibration_tsc: 0,
            samples: 0,
        }
    }
}

/// Per-CPU TSC state
#[derive(Debug, Clone, Default)]
struct PerCpuTsc {
    /// Is this CPU initialized?
    initialized: bool,
    /// TSC offset from BSP (for synchronization)
    offset: i64,
    /// Last synchronization TSC value
    last_sync_tsc: u64,
    /// Synchronization error estimate (ticks)
    sync_error: u64,
}

/// TSC statistics
#[derive(Debug, Clone, Default)]
pub struct TscStatistics {
    /// TSC features
    pub features: TscFeatures,
    /// Is TSC initialized?
    pub initialized: bool,
    /// Is TSC calibrated?
    pub calibrated: bool,
    /// Measured frequency in Hz
    pub frequency_hz: u64,
    /// Calibration source
    pub calibration_source: CalibrationSource,
    /// Calibration confidence (0-100)
    pub confidence: u8,
    /// Boot TSC value
    pub boot_tsc: u64,
    /// Current TSC value
    pub current_tsc: u64,
    /// Uptime in nanoseconds
    pub uptime_ns: u64,
    /// Number of calibration samples
    pub calibration_samples: u8,
    /// Number of initialized CPUs
    pub initialized_cpus: u32,
    /// Total rdtsc calls
    pub rdtsc_calls: u64,
    /// Total rdtscp calls
    pub rdtscp_calls: u64,
}

// ============================================================================
// Global State
// ============================================================================

/// TSC initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// TSC calibrated state
static CALIBRATED: AtomicBool = AtomicBool::new(false);

/// TSC features
static FEATURES: RwLock<TscFeatures> = RwLock::new(TscFeatures {
    tsc_available: false,
    rdtscp_available: false,
    invariant_tsc: false,
    deadline_mode: false,
    cpuid_frequency: false,
    tsc_adjust: false,
    always_running: false,
});

/// TSC calibration data
static CALIBRATION: RwLock<TscCalibration> = RwLock::new(TscCalibration {
    frequency_hz: 0,
    boot_tsc: 0,
    source: CalibrationSource::None,
    confidence: 0,
    calibration_tsc: 0,
    samples: 0,
});

/// Per-CPU TSC state
static PER_CPU_TSC: RwLock<[PerCpuTsc; MAX_CPUS]> = RwLock::new([const { PerCpuTsc {
    initialized: false,
    offset: 0,
    last_sync_tsc: 0,
    sync_error: 0,
} }; MAX_CPUS]);

/// Statistics counters
static STATS_RDTSC_CALLS: AtomicU64 = AtomicU64::new(0);
static STATS_RDTSCP_CALLS: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Low-Level TSC Operations
// ============================================================================

/// Read Time Stamp Counter with serialization
#[inline(always)]
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
    STATS_RDTSC_CALLS.fetch_add(1, Ordering::Relaxed);
    ((hi as u64) << 32) | (lo as u64)
}

/// Read Time Stamp Counter without serialization (faster, less precise)
#[inline(always)]
pub fn rdtsc_unserialized() -> u64 {
    let hi: u32;
    let lo: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Read Time Stamp Counter and Processor ID (RDTSCP)
#[inline(always)]
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
    STATS_RDTSCP_CALLS.fetch_add(1, Ordering::Relaxed);
    (((hi as u64) << 32) | (lo as u64), aux)
}

/// Read TSC with RDTSCP if available, else RDTSC
#[inline(always)]
pub fn read_tsc() -> u64 {
    if FEATURES.read().rdtscp_available {
        rdtscp().0
    } else {
        rdtsc()
    }
}

/// Read TSC and CPU ID
pub fn read_tsc_cpu() -> (u64, u32) {
    if FEATURES.read().rdtscp_available {
        rdtscp()
    } else {
        // Without RDTSCP, we can't atomically get CPU ID
        (rdtsc(), 0)
    }
}

/// Memory fence for TSC ordering
#[inline(always)]
pub fn tsc_fence() {
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

// ============================================================================
// CPUID Operations
// ============================================================================

/// Execute CPUID instruction
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(preserves_flags)
        );
    }
    (eax, ebx, ecx, edx)
}

/// Get maximum supported CPUID leaf
fn cpuid_max_leaf() -> u32 {
    cpuid(0, 0).0
}

/// Get maximum supported extended CPUID leaf
fn cpuid_max_extended_leaf() -> u32 {
    cpuid(0x80000000, 0).0
}

// ============================================================================
// Feature Detection
// ============================================================================

/// Detect all TSC features
pub fn detect_features() -> TscFeatures {
    let max_leaf = cpuid_max_leaf();
    let max_ext = cpuid_max_extended_leaf();

    // CPUID.01H
    let (_, _, ecx_01, edx_01) = if max_leaf >= 1 {
        cpuid(1, 0)
    } else {
        (0, 0, 0, 0)
    };

    // CPUID.07H
    let (_, ebx_07, _, _) = if max_leaf >= 7 {
        cpuid(7, 0)
    } else {
        (0, 0, 0, 0)
    };

    // CPUID.80000001H
    let (_, _, _, edx_ext1) = if max_ext >= 0x80000001 {
        cpuid(0x80000001, 0)
    } else {
        (0, 0, 0, 0)
    };

    // CPUID.80000007H
    let (_, _, _, edx_ext7) = if max_ext >= 0x80000007 {
        cpuid(0x80000007, 0)
    } else {
        (0, 0, 0, 0)
    };

    // CPUID.06H (Power management)
    let (_, _, _, _edx_06) = if max_leaf >= 6 {
        cpuid(6, 0)
    } else {
        (0, 0, 0, 0)
    };

    TscFeatures {
        // CPUID.01H:EDX[4] = TSC
        tsc_available: (edx_01 & (1 << 4)) != 0,
        // CPUID.80000001H:EDX[27] = RDTSCP
        rdtscp_available: (edx_ext1 & (1 << 27)) != 0,
        // CPUID.80000007H:EDX[8] = Invariant TSC
        invariant_tsc: (edx_ext7 & (1 << 8)) != 0,
        // CPUID.01H:ECX[24] = TSC deadline
        deadline_mode: (ecx_01 & (1 << 24)) != 0,
        // CPUID.15H exists
        cpuid_frequency: max_leaf >= 0x15,
        // CPUID.07H:EBX[1] = TSC_ADJUST
        tsc_adjust: (ebx_07 & (1 << 1)) != 0,
        // CPUID.06H:EAX[2] = ARAT (Always Running APIC Timer)
        // Note: This indicates APIC timer, not TSC, but often correlates
        always_running: (edx_ext7 & (1 << 8)) != 0, // Use invariant as proxy
    }
}

/// Check if TSC is available
pub fn is_tsc_available() -> bool {
    FEATURES.read().tsc_available
}

/// Check if TSC is invariant (reliable)
pub fn is_invariant() -> bool {
    FEATURES.read().invariant_tsc
}

/// Check if RDTSCP is available
pub fn has_rdtscp() -> bool {
    FEATURES.read().rdtscp_available
}

/// Check if TSC deadline mode is available
pub fn has_deadline_mode() -> bool {
    FEATURES.read().deadline_mode
}

/// Get TSC features
pub fn get_features() -> TscFeatures {
    *FEATURES.read()
}

// ============================================================================
// Frequency Detection via CPUID
// ============================================================================

/// Try to get TSC frequency from CPUID.15H
fn get_cpuid_frequency() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x15 {
        return None;
    }

    // CPUID.15H: Time Stamp Counter and Core Crystal Clock Information
    let (eax, ebx, ecx, _) = cpuid(0x15, 0);

    // EAX = denominator, EBX = numerator, ECX = crystal clock frequency
    if eax == 0 || ebx == 0 {
        return None;
    }

    // If ECX is 0, crystal frequency is not enumerated
    // We need to get it from CPUID.16H or use known values
    let crystal_freq = if ecx != 0 {
        ecx as u64
    } else {
        // Try CPUID.16H for processor base frequency
        if max_leaf >= 0x16 {
            let (base_mhz, _, _, _) = cpuid(0x16, 0);
            if base_mhz != 0 {
                // This gives base frequency, not crystal, but can be used
                // as approximation: TSC freq = base_freq * numerator / denominator
                return None;
            }
        }
        return None;
    };

    // TSC frequency = crystal_freq * numerator / denominator
    let tsc_freq = (crystal_freq * ebx as u64) / eax as u64;

    if tsc_freq >= MIN_FREQUENCY && tsc_freq <= MAX_FREQUENCY {
        Some(tsc_freq)
    } else {
        None
    }
}

/// Try to get processor base frequency from CPUID.16H
fn get_cpuid_base_frequency() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x16 {
        return None;
    }

    let (base_mhz, _, _, _) = cpuid(0x16, 0);
    if base_mhz != 0 {
        Some(base_mhz as u64 * 1_000_000)
    } else {
        None
    }
}

// ============================================================================
// Calibration
// ============================================================================

/// Calibrate TSC using PIT
fn calibrate_with_pit() -> TscResult<(u64, u8)> {
    const PIT_FREQUENCY: u64 = 1193182;
    const CALIBRATION_MS: u64 = DEFAULT_CALIBRATION_MS as u64;
    let pit_ticks = ((PIT_FREQUENCY * CALIBRATION_MS) / 1000) as u16;

    let mut samples = [0u64; CALIBRATION_SAMPLES];
    let mut valid_samples = 0;

    for sample in samples.iter_mut() {
        unsafe {
            // Save speaker port state
            let speaker_port = inb(0x61);

            // Configure PIT channel 2 for one-shot mode
            outb(0x43, 0xB0); // Channel 2, lobyte/hibyte, mode 0
            outb(0x42, (pit_ticks & 0xFF) as u8);
            outb(0x42, ((pit_ticks >> 8) & 0xFF) as u8);

            // Gate the timer and wait for start
            outb(0x61, (speaker_port & 0xFC) | 0x01);

            // Wait for output to go high (counter loaded)
            let mut timeout = 100_000u32;
            while (inb(0x61) & 0x20) != 0 && timeout > 0 {
                timeout -= 1;
            }

            // Read start TSC
            let start_tsc = rdtsc_unserialized();

            // Wait for output to go low (countdown complete)
            timeout = 100_000_000;
            while (inb(0x61) & 0x20) == 0 && timeout > 0 {
                timeout -= 1;
                core::hint::spin_loop();
            }

            // Read end TSC
            let end_tsc = rdtsc_unserialized();

            // Restore speaker port
            outb(0x61, speaker_port);

            if timeout > 0 {
                let tsc_ticks = end_tsc.saturating_sub(start_tsc);
                // TSC frequency = ticks * (1000 / CALIBRATION_MS) * PIT_FREQUENCY / pit_ticks
                let freq = (tsc_ticks * PIT_FREQUENCY) / pit_ticks as u64;
                if freq >= MIN_FREQUENCY && freq <= MAX_FREQUENCY {
                    *sample = freq;
                    valid_samples += 1;
                }
            }
        }
    }

    if valid_samples < 3 {
        return Err(TscError::CalibrationFailed);
    }

    // Sort and get median
    samples[..valid_samples].sort_unstable();
    let median = samples[valid_samples / 2];

    // Calculate confidence based on variance
    let mut variance: u64 = 0;
    for &sample in &samples[..valid_samples] {
        let diff = if sample > median { sample - median } else { median - sample };
        variance += diff;
    }
    variance /= valid_samples as u64;

    let variance_pct = (variance * 100) / median;
    let confidence = if variance_pct == 0 {
        95
    } else if variance_pct < 1 {
        90
    } else if variance_pct < 5 {
        75
    } else {
        50
    };

    Ok((median, confidence))
}

/// Calibrate TSC using HPET
fn calibrate_with_hpet(hpet_base: u64) -> TscResult<(u64, u8)> {
    const CALIBRATION_NS: u64 = DEFAULT_CALIBRATION_MS as u64 * 1_000_000;

    unsafe {
        // Read HPET capabilities
        let capabilities = core::ptr::read_volatile(hpet_base as *const u64);
        let period_fs = (capabilities >> 32) as u32;

        if period_fs == 0 || period_fs > 100_000_000 {
            return Err(TscError::NoReferenceTimer);
        }

        // Calculate HPET ticks for calibration period
        let hpet_ticks_needed = (CALIBRATION_NS * 1_000_000) / period_fs as u64;

        let mut samples = [0u64; CALIBRATION_SAMPLES];
        let mut valid_samples = 0;

        let counter_reg = (hpet_base + 0xF0) as *const u64;

        for sample in samples.iter_mut() {
            // Read start values
            let start_hpet = core::ptr::read_volatile(counter_reg);
            let start_tsc = rdtsc_unserialized();

            // Wait for HPET ticks
            let end_hpet = start_hpet.wrapping_add(hpet_ticks_needed);
            let mut timeout = 100_000_000u32;
            while core::ptr::read_volatile(counter_reg) < end_hpet && timeout > 0 {
                timeout -= 1;
                core::hint::spin_loop();
            }

            if timeout == 0 {
                continue;
            }

            // Read end values
            let end_tsc = rdtsc_unserialized();
            let actual_hpet = core::ptr::read_volatile(counter_reg);

            // Calculate actual elapsed time
            let elapsed_hpet = actual_hpet.saturating_sub(start_hpet);
            let elapsed_ns = (elapsed_hpet * period_fs as u64) / 1_000_000;

            if elapsed_ns > 0 {
                let tsc_ticks = end_tsc.saturating_sub(start_tsc);
                let freq = (tsc_ticks * 1_000_000_000) / elapsed_ns;

                if freq >= MIN_FREQUENCY && freq <= MAX_FREQUENCY {
                    *sample = freq;
                    valid_samples += 1;
                }
            }
        }

        if valid_samples < 3 {
            return Err(TscError::CalibrationFailed);
        }

        samples[..valid_samples].sort_unstable();
        let median = samples[valid_samples / 2];

        // HPET calibration is more accurate
        let confidence = 98;

        Ok((median, confidence))
    }
}

/// Main calibration function
pub fn calibrate() -> TscResult<()> {
    if !FEATURES.read().tsc_available {
        return Err(TscError::NotAvailable);
    }

    let boot_tsc = rdtsc();

    // Try CPUID first (most accurate)
    if let Some(freq) = get_cpuid_frequency() {
        let mut cal = CALIBRATION.write();
        cal.frequency_hz = freq;
        cal.boot_tsc = boot_tsc;
        cal.source = CalibrationSource::Cpuid;
        cal.confidence = 100;
        cal.calibration_tsc = rdtsc();
        cal.samples = 1;
        CALIBRATED.store(true, Ordering::SeqCst);
        return Ok(());
    }

    // Try HPET calibration
    // Note: Would need to get HPET base from ACPI or detect
    // For now, try PIT

    // Try PIT calibration
    match calibrate_with_pit() {
        Ok((freq, confidence)) => {
            let mut cal = CALIBRATION.write();
            cal.frequency_hz = freq;
            cal.boot_tsc = boot_tsc;
            cal.source = CalibrationSource::Pit;
            cal.confidence = confidence;
            cal.calibration_tsc = rdtsc();
            cal.samples = CALIBRATION_SAMPLES as u8;
            CALIBRATED.store(true, Ordering::SeqCst);
            return Ok(());
        }
        Err(_) => {}
    }

    Err(TscError::CalibrationFailed)
}

/// Calibrate using HPET at specified base address
pub fn calibrate_with_hpet_base(hpet_base: u64) -> TscResult<()> {
    if !FEATURES.read().tsc_available {
        return Err(TscError::NotAvailable);
    }

    let boot_tsc = rdtsc();

    match calibrate_with_hpet(hpet_base) {
        Ok((freq, confidence)) => {
            let mut cal = CALIBRATION.write();
            cal.frequency_hz = freq;
            cal.boot_tsc = boot_tsc;
            cal.source = CalibrationSource::Hpet;
            cal.confidence = confidence;
            cal.calibration_tsc = rdtsc();
            cal.samples = CALIBRATION_SAMPLES as u8;
            CALIBRATED.store(true, Ordering::SeqCst);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Set known TSC frequency (for testing or known hardware)
pub fn set_frequency(freq_hz: u64) -> TscResult<()> {
    if freq_hz < MIN_FREQUENCY || freq_hz > MAX_FREQUENCY {
        return Err(TscError::InvalidFrequency);
    }

    let boot_tsc = rdtsc();

    let mut cal = CALIBRATION.write();
    cal.frequency_hz = freq_hz;
    cal.boot_tsc = boot_tsc;
    cal.source = CalibrationSource::KnownFrequency;
    cal.confidence = 100;
    cal.calibration_tsc = rdtsc();
    cal.samples = 1;

    CALIBRATED.store(true, Ordering::SeqCst);

    Ok(())
}

// ============================================================================
// Time Conversion Functions
// ============================================================================

/// Get TSC frequency in Hz
pub fn get_frequency() -> u64 {
    CALIBRATION.read().frequency_hz
}

/// Get TSC frequency in MHz
pub fn get_frequency_mhz() -> u64 {
    CALIBRATION.read().frequency_hz / 1_000_000
}

/// Convert TSC ticks to nanoseconds
#[inline]
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    // Use 128-bit math to avoid overflow
    // ns = ticks * 1_000_000_000 / freq
    let (result, overflow) = ticks.overflowing_mul(1_000_000_000);
    if overflow {
        // Use division first for large values
        (ticks / freq) * 1_000_000_000 + ((ticks % freq) * 1_000_000_000) / freq
    } else {
        result / freq
    }
}

/// Convert TSC ticks to microseconds
#[inline]
pub fn ticks_to_us(ticks: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000_000) / freq
}

/// Convert TSC ticks to milliseconds
#[inline]
pub fn ticks_to_ms(ticks: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000) / freq
}

/// Convert nanoseconds to TSC ticks
#[inline]
pub fn ns_to_ticks(ns: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ns * freq) / 1_000_000_000
}

/// Convert microseconds to TSC ticks
#[inline]
pub fn us_to_ticks(us: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (us * freq) / 1_000_000
}

/// Convert milliseconds to TSC ticks
#[inline]
pub fn ms_to_ticks(ms: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ms * freq) / 1_000
}

/// Legacy API: Convert TSC ticks to nanoseconds
pub fn tsc_to_ns(tsc_ticks: u64, tsc_freq: u64) -> u64 {
    if tsc_freq == 0 {
        return 0;
    }
    (tsc_ticks * 1_000_000_000) / tsc_freq
}

/// Legacy API: Convert nanoseconds to TSC ticks
pub fn ns_to_tsc(nanoseconds: u64, tsc_freq: u64) -> u64 {
    if tsc_freq == 0 {
        return 0;
    }
    (nanoseconds * tsc_freq) / 1_000_000_000
}

// ============================================================================
// Time Since Boot
// ============================================================================

/// Get nanoseconds since boot
pub fn elapsed_ns() -> u64 {
    let cal = CALIBRATION.read();
    if cal.frequency_hz == 0 {
        return 0;
    }
    let current = rdtsc();
    let elapsed = current.saturating_sub(cal.boot_tsc);
    ticks_to_ns(elapsed)
}

/// Get microseconds since boot
pub fn elapsed_us() -> u64 {
    let cal = CALIBRATION.read();
    if cal.frequency_hz == 0 {
        return 0;
    }
    let current = rdtsc();
    let elapsed = current.saturating_sub(cal.boot_tsc);
    ticks_to_us(elapsed)
}

/// Get milliseconds since boot
pub fn elapsed_ms() -> u64 {
    let cal = CALIBRATION.read();
    if cal.frequency_hz == 0 {
        return 0;
    }
    let current = rdtsc();
    let elapsed = current.saturating_sub(cal.boot_tsc);
    ticks_to_ms(elapsed)
}

/// Get seconds since boot
pub fn elapsed_secs() -> u64 {
    elapsed_ms() / 1000
}

// ============================================================================
// Delay Functions
// ============================================================================

/// Busy-wait delay in nanoseconds
pub fn delay_ns(ns: u64) {
    if !CALIBRATED.load(Ordering::Relaxed) {
        // Fallback without calibration
        for _ in 0..ns / 10 {
            core::hint::spin_loop();
        }
        return;
    }

    let target_ticks = ns_to_ticks(ns);
    let start = rdtsc_unserialized();
    let end = start.wrapping_add(target_ticks);

    while rdtsc_unserialized() < end {
        core::hint::spin_loop();
    }
}

/// Busy-wait delay in microseconds
pub fn delay_us(us: u64) {
    delay_ns(us * 1000);
}

/// Busy-wait delay in milliseconds
pub fn delay_ms(ms: u64) {
    delay_ns(ms * 1_000_000);
}

/// Precise busy-wait with PAUSE instruction
pub fn delay_precise_ns(ns: u64) {
    if !CALIBRATED.load(Ordering::Relaxed) {
        delay_ns(ns);
        return;
    }

    let target_ticks = ns_to_ticks(ns);
    let start = rdtsc_unserialized();
    let end = start.wrapping_add(target_ticks);

    while rdtsc_unserialized() < end {
        unsafe {
            core::arch::asm!("pause", options(nostack, preserves_flags, nomem));
        }
    }
}

// ============================================================================
// Per-CPU Operations
// ============================================================================

/// Initialize TSC for current CPU
pub fn init_cpu(cpu_id: u32) -> TscResult<()> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(TscError::PerCpuNotInit);
    }

    let current_tsc = rdtsc();

    let mut per_cpu = PER_CPU_TSC.write();
    let cpu_state = &mut per_cpu[cpu_id as usize];

    if cpu_id == 0 {
        // BSP is reference
        cpu_state.offset = 0;
    } else {
        // Calculate offset from BSP
        let boot_tsc = CALIBRATION.read().boot_tsc;
        cpu_state.offset = current_tsc as i64 - boot_tsc as i64;
    }

    cpu_state.initialized = true;
    cpu_state.last_sync_tsc = current_tsc;
    cpu_state.sync_error = 0;

    Ok(())
}

/// Synchronize TSC with BSP
pub fn sync_with_bsp(cpu_id: u32) -> TscResult<()> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(TscError::PerCpuNotInit);
    }

    if cpu_id == 0 {
        // BSP doesn't sync with itself
        return Ok(());
    }

    // Simple synchronization: measure offset from BSP
    // In real implementation, would use IPI handshake
    let current_tsc = rdtsc();
    let boot_tsc = CALIBRATION.read().boot_tsc;

    let mut per_cpu = PER_CPU_TSC.write();
    let cpu_state = &mut per_cpu[cpu_id as usize];

    cpu_state.offset = current_tsc as i64 - boot_tsc as i64;
    cpu_state.last_sync_tsc = current_tsc;

    Ok(())
}

/// Get TSC offset for a CPU
pub fn get_cpu_offset(cpu_id: u32) -> Option<i64> {
    if cpu_id as usize >= MAX_CPUS {
        return None;
    }

    let per_cpu = PER_CPU_TSC.read();
    let cpu_state = &per_cpu[cpu_id as usize];

    if cpu_state.initialized {
        Some(cpu_state.offset)
    } else {
        None
    }
}

/// Read TSC adjusted for CPU offset
pub fn read_synchronized(cpu_id: u32) -> u64 {
    let raw = rdtsc();

    if cpu_id as usize >= MAX_CPUS {
        return raw;
    }

    let per_cpu = PER_CPU_TSC.read();
    let cpu_state = &per_cpu[cpu_id as usize];

    if cpu_state.initialized {
        if cpu_state.offset >= 0 {
            raw.saturating_sub(cpu_state.offset as u64)
        } else {
            raw.saturating_add((-cpu_state.offset) as u64)
        }
    } else {
        raw
    }
}

// ============================================================================
// TSC Deadline Mode
// ============================================================================

/// Write to IA32_TSC_DEADLINE MSR
pub fn write_deadline(deadline: u64) -> TscResult<()> {
    if !FEATURES.read().deadline_mode {
        return Err(TscError::DeadlineModeUnavailable);
    }

    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x6E0u32, // IA32_TSC_DEADLINE
            in("eax") (deadline & 0xFFFFFFFF) as u32,
            in("edx") (deadline >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }

    Ok(())
}

/// Read IA32_TSC_DEADLINE MSR
pub fn read_deadline() -> TscResult<u64> {
    if !FEATURES.read().deadline_mode {
        return Err(TscError::DeadlineModeUnavailable);
    }

    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0x6E0u32, // IA32_TSC_DEADLINE
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
    }

    Ok(((hi as u64) << 32) | (lo as u64))
}

/// Set deadline in nanoseconds from now
pub fn set_deadline_ns(delay_ns: u64) -> TscResult<()> {
    let current = rdtsc();
    let ticks = ns_to_ticks(delay_ns);
    let deadline = current.saturating_add(ticks);
    write_deadline(deadline)
}

/// Clear the TSC deadline
pub fn clear_deadline() -> TscResult<()> {
    write_deadline(0)
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
// Initialization
// ============================================================================

/// Initialize TSC subsystem
pub fn init() -> TscResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TscError::AlreadyInitialized);
    }

    // Detect features
    let features = detect_features();
    *FEATURES.write() = features;

    if !features.tsc_available {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(TscError::NotAvailable);
    }

    // Calibrate TSC
    calibrate()?;

    // Initialize BSP
    init_cpu(0)?;

    Ok(())
}

/// Initialize with HPET for calibration
pub fn init_with_hpet(hpet_base: u64) -> TscResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TscError::AlreadyInitialized);
    }

    // Detect features
    let features = detect_features();
    *FEATURES.write() = features;

    if !features.tsc_available {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(TscError::NotAvailable);
    }

    // Calibrate with HPET
    calibrate_with_hpet_base(hpet_base)?;

    // Initialize BSP
    init_cpu(0)?;

    Ok(())
}

/// Check if TSC is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// Check if TSC is calibrated
pub fn is_calibrated() -> bool {
    CALIBRATED.load(Ordering::Relaxed)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get TSC statistics
pub fn get_statistics() -> TscStatistics {
    let features = *FEATURES.read();
    let cal = CALIBRATION.read();

    // Count initialized CPUs
    let per_cpu = PER_CPU_TSC.read();
    let initialized_cpus = per_cpu.iter().filter(|c| c.initialized).count() as u32;

    let current_tsc = rdtsc();
    let uptime_ns = if cal.frequency_hz > 0 {
        let elapsed = current_tsc.saturating_sub(cal.boot_tsc);
        ticks_to_ns(elapsed)
    } else {
        0
    };

    TscStatistics {
        features,
        initialized: INITIALIZED.load(Ordering::Relaxed),
        calibrated: CALIBRATED.load(Ordering::Relaxed),
        frequency_hz: cal.frequency_hz,
        calibration_source: cal.source,
        confidence: cal.confidence,
        boot_tsc: cal.boot_tsc,
        current_tsc,
        uptime_ns,
        calibration_samples: cal.samples,
        initialized_cpus,
        rdtsc_calls: STATS_RDTSC_CALLS.load(Ordering::Relaxed),
        rdtscp_calls: STATS_RDTSCP_CALLS.load(Ordering::Relaxed),
    }
}

/// Get calibration source
pub fn get_calibration_source() -> CalibrationSource {
    CALIBRATION.read().source
}

/// Get calibration confidence (0-100)
pub fn get_confidence() -> u8 {
    CALIBRATION.read().confidence
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsc_error_messages() {
        assert_eq!(TscError::NotAvailable.as_str(), "TSC not available");
        assert_eq!(TscError::CalibrationFailed.as_str(), "TSC calibration failed");
        assert_eq!(TscError::NotInvariant.as_str(), "TSC not invariant (unstable across P-states)");
    }

    #[test]
    fn test_calibration_source() {
        assert_eq!(CalibrationSource::None.name(), "None");
        assert_eq!(CalibrationSource::Cpuid.name(), "CPUID.15H");
        assert_eq!(CalibrationSource::Hpet.name(), "HPET");
        assert_eq!(CalibrationSource::Pit.name(), "PIT");

        assert!(CalibrationSource::Cpuid.accuracy_rating() > CalibrationSource::Pit.accuracy_rating());
    }

    #[test]
    fn test_tsc_features_reliable() {
        let features = TscFeatures {
            tsc_available: true,
            rdtscp_available: true,
            invariant_tsc: true,
            deadline_mode: true,
            cpuid_frequency: true,
            tsc_adjust: true,
            always_running: true,
        };

        assert!(features.is_reliable());
        assert!(features.is_available());

        let unreliable = TscFeatures {
            tsc_available: true,
            invariant_tsc: false,
            ..Default::default()
        };

        assert!(!unreliable.is_reliable());
        assert!(unreliable.is_available());
    }

    #[test]
    fn test_time_conversion_functions() {
        // With 1 GHz frequency
        let freq: u64 = 1_000_000_000;

        // 1 second = 1 billion ticks
        assert_eq!(tsc_to_ns(freq, freq), 1_000_000_000);

        // 1 millisecond = 1 million ticks
        assert_eq!(tsc_to_ns(1_000_000, freq), 1_000_000);

        // Reverse conversion
        assert_eq!(ns_to_tsc(1_000_000_000, freq), freq);
    }

    #[test]
    fn test_ticks_conversion_zero_freq() {
        assert_eq!(tsc_to_ns(1000, 0), 0);
        assert_eq!(ns_to_tsc(1000, 0), 0);
    }

    #[test]
    fn test_calibration_default() {
        let cal = TscCalibration::default();
        assert_eq!(cal.frequency_hz, 0);
        assert_eq!(cal.source, CalibrationSource::None);
        assert_eq!(cal.confidence, 0);
    }

    #[test]
    fn test_per_cpu_default() {
        let per_cpu = PerCpuTsc::default();
        assert!(!per_cpu.initialized);
        assert_eq!(per_cpu.offset, 0);
    }

    #[test]
    fn test_statistics_default() {
        let stats = TscStatistics::default();
        assert!(!stats.initialized);
        assert!(!stats.calibrated);
        assert_eq!(stats.frequency_hz, 0);
    }

    #[test]
    fn test_frequency_bounds() {
        assert!(MIN_FREQUENCY < MAX_FREQUENCY);
        assert_eq!(MIN_FREQUENCY, 100_000_000); // 100 MHz
        assert_eq!(MAX_FREQUENCY, 10_000_000_000); // 10 GHz
    }
}
