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
//! High Precision Event Timer (HPET) Driver | NØNOS with:
//! **Complete register access**
//! **Timer configuration**
//! **Interrupt routing**
//! **Time conversion**
//! **Calibration**
//! **Thread-safe design**
//!
//! ## HPET Architecture
//!
//! ```text
//! +------------------+
//! | General Registers|
//! |  - Capabilities  |  0x000: Counter clock period, timer count, 64-bit
//! |  - Configuration |  0x010: Enable, legacy replacement
//! |  - Int Status    |  0x020: Timer interrupt status bits
//! |  - Main Counter  |  0x0F0: 64-bit monotonic counter
//! +------------------+
//! | Timer 0 Block    |  0x100-0x11F
//! | Timer 1 Block    |  0x120-0x13F
//! | Timer 2 Block    |  0x140-0x15F
//! | ...              |
//! +------------------+
//! ```

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;

// ============================================================================
// Error Handling
// ============================================================================

/// HPET subsystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpetError {
    /// HPET not initialized
    NotInitialized,
    /// Already initialized
    AlreadyInitialized,
    /// HPET not detected in system
    NotDetected,
    /// Invalid base address
    InvalidBaseAddress,
    /// Invalid timer number
    InvalidTimer,
    /// Timer does not support periodic mode
    PeriodicNotSupported,
    /// Timer does not support FSB interrupts
    FsbNotSupported,
    /// Invalid IRQ routing
    InvalidIrqRouting,
    /// IRQ not available for timer
    IrqNotAvailable,
    /// Counter overflow during operation
    CounterOverflow,
    /// Hardware access failed
    HardwareError,
    /// Invalid period (too small or too large)
    InvalidPeriod,
    /// Calibration failed
    CalibrationFailed,
}

impl HpetError {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "HPET not initialized",
            Self::AlreadyInitialized => "HPET already initialized",
            Self::NotDetected => "HPET not detected",
            Self::InvalidBaseAddress => "invalid HPET base address",
            Self::InvalidTimer => "invalid timer number",
            Self::PeriodicNotSupported => "periodic mode not supported",
            Self::FsbNotSupported => "FSB interrupts not supported",
            Self::InvalidIrqRouting => "invalid IRQ routing",
            Self::IrqNotAvailable => "IRQ not available for this timer",
            Self::CounterOverflow => "counter overflow",
            Self::HardwareError => "hardware access error",
            Self::InvalidPeriod => "invalid period",
            Self::CalibrationFailed => "calibration failed",
        }
    }
}

/// Result type for HPET operations
pub type HpetResult<T> = Result<T, HpetError>;

// ============================================================================
// Constants - Register Offsets
// ============================================================================

/// General Capabilities and ID Register
const REG_CAP_ID: u64 = 0x000;

/// General Configuration Register
const REG_CONFIG: u64 = 0x010;

/// General Interrupt Status Register
const REG_INT_STATUS: u64 = 0x020;

/// Main Counter Value Register
const REG_MAIN_COUNTER: u64 = 0x0F0;

/// Timer N Configuration and Capability Register offset
const fn reg_timer_config(n: u8) -> u64 {
    0x100 + (n as u64) * 0x20
}

/// Timer N Comparator Value Register offset
const fn reg_timer_comparator(n: u8) -> u64 {
    0x108 + (n as u64) * 0x20
}

/// Timer N FSB Interrupt Route Register offset
const fn reg_timer_fsb(n: u8) -> u64 {
    0x110 + (n as u64) * 0x20
}

// ============================================================================
// Constants - Capability Register Bits
// ============================================================================

/// Number of timers minus one (bits 8-12)
const CAP_NUM_TIMERS_MASK: u64 = 0x1F << 8;
const CAP_NUM_TIMERS_SHIFT: u32 = 8;

/// 64-bit counter capable (bit 13)
const CAP_64BIT: u64 = 1 << 13;

/// Legacy replacement route capable (bit 15)
const CAP_LEGACY_ROUTE: u64 = 1 << 15;

/// Vendor ID (bits 16-31)
const CAP_VENDOR_MASK: u64 = 0xFFFF << 16;
const CAP_VENDOR_SHIFT: u32 = 16;

/// Counter clock period in femtoseconds (bits 32-63)
const CAP_PERIOD_SHIFT: u32 = 32;

// ============================================================================
// Constants - Configuration Register Bits
// ============================================================================

/// Overall enable (bit 0)
const CFG_ENABLE: u64 = 1 << 0;

/// Legacy replacement route (bit 1)
const CFG_LEGACY_ROUTE: u64 = 1 << 1;

// ============================================================================
// Constants - Timer Configuration Bits
// ============================================================================

/// Reserved (read-only) (bit 0)
const TIMER_CFG_RESERVED: u64 = 1 << 0;

/// Level triggered interrupt (bit 1)
const TIMER_CFG_LEVEL: u64 = 1 << 1;

/// Interrupt enable (bit 2)
const TIMER_CFG_INT_ENABLE: u64 = 1 << 2;

/// Periodic mode (bit 3)
const TIMER_CFG_PERIODIC: u64 = 1 << 3;

/// Periodic capable (read-only) (bit 4)
const TIMER_CFG_PERIODIC_CAP: u64 = 1 << 4;

/// 64-bit capable (read-only) (bit 5)
const TIMER_CFG_64BIT_CAP: u64 = 1 << 5;

/// Value set (for periodic mode) (bit 6)
const TIMER_CFG_VALUE_SET: u64 = 1 << 6;

/// Force 32-bit mode (bit 8)
const TIMER_CFG_32BIT_MODE: u64 = 1 << 8;

/// Interrupt route (bits 9-13)
const TIMER_CFG_INT_ROUTE_MASK: u64 = 0x1F << 9;
const TIMER_CFG_INT_ROUTE_SHIFT: u32 = 9;

/// FSB interrupt enable (bit 14)
const TIMER_CFG_FSB_ENABLE: u64 = 1 << 14;

/// FSB interrupt delivery capable (read-only) (bit 15)
const TIMER_CFG_FSB_CAP: u64 = 1 << 15;

/// Allowed interrupt routes (bits 32-63, read-only)
const TIMER_CFG_INT_ROUTE_CAP_SHIFT: u32 = 32;

// ============================================================================
// Constants - Common Values
// ============================================================================

/// Default HPET base address
const HPET_DEFAULT_BASE: u64 = 0xFED00000;

/// Common HPET base addresses to scan
const HPET_SCAN_BASES: [u64; 4] = [
    0xFED00000,
    0xFED01000,
    0xFED02000,
    0xFED03000,
];

/// Femtoseconds per second
const FS_PER_SECOND: u128 = 1_000_000_000_000_000;

/// Femtoseconds per millisecond
const FS_PER_MS: u128 = 1_000_000_000_000;

/// Femtoseconds per microsecond
const FS_PER_US: u128 = 1_000_000_000;

/// Femtoseconds per nanosecond
const FS_PER_NS: u128 = 1_000_000;

/// Maximum valid period (100 ns in femtoseconds)
const MAX_VALID_PERIOD: u32 = 100_000_000;

/// Minimum valid period (10 fs)
const MIN_VALID_PERIOD: u32 = 10;

/// Maximum number of HPET timers
const MAX_TIMERS: u8 = 32;

// ============================================================================
// Timer Configuration
// ============================================================================

/// Timer interrupt delivery mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptMode {
    /// Edge-triggered interrupt via I/O APIC
    Edge,
    /// Level-triggered interrupt via I/O APIC
    Level,
    /// Front Side Bus (MSI) interrupt delivery
    Fsb,
}

/// Timer operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    /// One-shot: fires once when counter reaches comparator
    OneShot,
    /// Periodic: fires repeatedly at specified interval
    Periodic,
}

/// Timer configuration
#[derive(Debug, Clone, Copy)]
pub struct TimerConfig {
    /// Timer number (0-31)
    pub timer: u8,
    /// Operating mode
    pub mode: TimerMode,
    /// Interrupt delivery mode
    pub int_mode: InterruptMode,
    /// I/O APIC IRQ (for Edge/Level modes)
    pub irq: u8,
    /// FSB interrupt address (for Fsb mode)
    pub fsb_addr: u32,
    /// FSB interrupt data (for Fsb mode)
    pub fsb_data: u32,
    /// Period/comparator in ticks
    pub ticks: u64,
    /// Force 32-bit mode
    pub force_32bit: bool,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            timer: 0,
            mode: TimerMode::OneShot,
            int_mode: InterruptMode::Edge,
            irq: 0,
            fsb_addr: 0,
            fsb_data: 0,
            ticks: 0,
            force_32bit: false,
        }
    }
}

// ============================================================================
// Timer State
// ============================================================================

/// Timer runtime state
#[derive(Debug, Clone, Copy)]
pub struct TimerState {
    /// Timer is configured
    pub configured: bool,
    /// Timer is enabled
    pub enabled: bool,
    /// Operating mode
    pub mode: TimerMode,
    /// Interrupt mode
    pub int_mode: InterruptMode,
    /// Configured IRQ
    pub irq: u8,
    /// Configured period/comparator
    pub ticks: u64,
    /// Interrupt count
    pub interrupt_count: u64,
}

impl Default for TimerState {
    fn default() -> Self {
        Self {
            configured: false,
            enabled: false,
            mode: TimerMode::OneShot,
            int_mode: InterruptMode::Edge,
            irq: 0,
            ticks: 0,
            interrupt_count: 0,
        }
    }
}

// ============================================================================
// HPET Hardware Information
// ============================================================================

/// HPET hardware capabilities
#[derive(Debug, Clone)]
pub struct HpetInfo {
    /// MMIO base address
    pub base_address: u64,
    /// Counter clock period in femtoseconds
    pub period_fs: u32,
    /// Frequency in Hz
    pub frequency_hz: u64,
    /// 64-bit counter capable
    pub counter_64bit: bool,
    /// Number of timers (1-32)
    pub num_timers: u8,
    /// Legacy replacement route capable
    pub legacy_capable: bool,
    /// Vendor ID
    pub vendor_id: u16,
    /// Revision ID
    pub revision: u8,
    /// Timer capabilities (periodic, FSB, etc.)
    pub timer_caps: [TimerCapabilities; MAX_TIMERS as usize],
}

/// Per-timer capabilities
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerCapabilities {
    /// Timer exists
    pub present: bool,
    /// Supports periodic mode
    pub periodic_capable: bool,
    /// Supports 64-bit comparator
    pub size_64bit: bool,
    /// Supports FSB interrupt delivery
    pub fsb_capable: bool,
    /// Allowed I/O APIC interrupt routes (bitmask)
    pub irq_routing_cap: u32,
}

// ============================================================================
// HPET Statistics
// ============================================================================

/// HPET statistics
#[derive(Debug, Clone, Copy)]
pub struct HpetStats {
    /// Total counter reads
    pub counter_reads: u64,
    /// Total timer configurations
    pub timer_configs: u64,
    /// Total interrupts (all timers)
    pub total_interrupts: u64,
    /// Counter at initialization
    pub init_counter: u64,
    /// Counter at last read
    pub last_counter: u64,
}

impl HpetStats {
    const fn new() -> Self {
        Self {
            counter_reads: 0,
            timer_configs: 0,
            total_interrupts: 0,
            init_counter: 0,
            last_counter: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
static BASE_ADDRESS: AtomicU64 = AtomicU64::new(0);
static PERIOD_FS: AtomicU64 = AtomicU64::new(0);
static FREQUENCY_HZ: AtomicU64 = AtomicU64::new(0);

static INFO: RwLock<Option<HpetInfo>> = RwLock::new(None);
static STATS: RwLock<HpetStats> = RwLock::new(HpetStats::new());
static TIMER_STATES: RwLock<[TimerState; MAX_TIMERS as usize]> =
    RwLock::new([TimerState {
        configured: false,
        enabled: false,
        mode: TimerMode::OneShot,
        int_mode: InterruptMode::Edge,
        irq: 0,
        ticks: 0,
        interrupt_count: 0,
    }; MAX_TIMERS as usize]);

// ============================================================================
// Register Access
// ============================================================================

/// Read a 64-bit HPET register
#[inline]
fn read_reg(base: u64, offset: u64) -> u64 {
    unsafe { ptr::read_volatile((base + offset) as *const u64) }
}

/// Write a 64-bit HPET register
#[inline]
fn write_reg(base: u64, offset: u64, value: u64) {
    unsafe { ptr::write_volatile((base + offset) as *mut u64, value) }
}

/// Read capabilities register
#[inline]
fn read_capabilities(base: u64) -> u64 {
    read_reg(base, REG_CAP_ID)
}

/// Read configuration register
#[inline]
fn read_config(base: u64) -> u64 {
    read_reg(base, REG_CONFIG)
}

/// Write configuration register
#[inline]
fn write_config(base: u64, value: u64) {
    write_reg(base, REG_CONFIG, value)
}

/// Read main counter
#[inline]
fn read_counter_raw(base: u64) -> u64 {
    read_reg(base, REG_MAIN_COUNTER)
}

/// Write main counter
#[inline]
fn write_counter_raw(base: u64, value: u64) {
    write_reg(base, REG_MAIN_COUNTER, value)
}

/// Read interrupt status
#[inline]
fn read_int_status(base: u64) -> u64 {
    read_reg(base, REG_INT_STATUS)
}

/// Write interrupt status (clear by writing 1)
#[inline]
fn write_int_status(base: u64, value: u64) {
    write_reg(base, REG_INT_STATUS, value)
}

/// Read timer configuration
#[inline]
fn read_timer_config(base: u64, timer: u8) -> u64 {
    read_reg(base, reg_timer_config(timer))
}

/// Write timer configuration
#[inline]
fn write_timer_config(base: u64, timer: u8, value: u64) {
    write_reg(base, reg_timer_config(timer), value)
}

/// Read timer comparator
#[inline]
fn read_timer_comparator(base: u64, timer: u8) -> u64 {
    read_reg(base, reg_timer_comparator(timer))
}

/// Write timer comparator
#[inline]
fn write_timer_comparator(base: u64, timer: u8, value: u64) {
    write_reg(base, reg_timer_comparator(timer), value)
}

/// Read timer FSB route
#[inline]
fn read_timer_fsb(base: u64, timer: u8) -> u64 {
    read_reg(base, reg_timer_fsb(timer))
}

/// Write timer FSB route
#[inline]
fn write_timer_fsb(base: u64, timer: u8, value: u64) {
    write_reg(base, reg_timer_fsb(timer), value)
}

// ============================================================================
// Validation
// ============================================================================

/// Check if a base address contains valid HPET hardware
fn is_valid_hpet(base: u64) -> bool {
    // Validate address range
    if base < 0xFED00000 || base >= 0xFF000000 {
        return false;
    }

    // Read capabilities
    let cap = read_capabilities(base);

    // Validate fields
    let revision = (cap & 0xFF) as u8;
    let vendor_id = ((cap >> CAP_VENDOR_SHIFT) & 0xFFFF) as u16;
    let period = (cap >> CAP_PERIOD_SHIFT) as u32;

    // Check validity
    revision > 0
        && vendor_id > 0
        && period >= MIN_VALID_PERIOD
        && period <= MAX_VALID_PERIOD
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize HPET subsystem
pub fn init() -> HpetResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(HpetError::AlreadyInitialized);
    }

    // Try to get HPET base from ACPI
    let base = detect_hpet_base()?;

    // Validate and read capabilities
    if !is_valid_hpet(base) {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(HpetError::InvalidBaseAddress);
    }

    let cap = read_capabilities(base);
    let period_fs = (cap >> CAP_PERIOD_SHIFT) as u32;
    let frequency_hz = (FS_PER_SECOND / period_fs as u128) as u64;

    // Store in atomics for fast access
    BASE_ADDRESS.store(base, Ordering::SeqCst);
    PERIOD_FS.store(period_fs as u64, Ordering::SeqCst);
    FREQUENCY_HZ.store(frequency_hz, Ordering::SeqCst);

    // Build full info structure
    let info = build_hpet_info(base, cap);

    // Store info
    *INFO.write() = Some(info.clone());

    // Initialize stats
    {
        let mut stats = STATS.write();
        stats.init_counter = read_counter_raw(base);
        stats.last_counter = stats.init_counter;
    }

    // Disable all timers initially
    for timer in 0..info.num_timers {
        disable_timer_internal(base, timer);
    }

    // Enable HPET counter (but not legacy mode by default)
    let config = read_config(base);
    write_config(base, config | CFG_ENABLE);
    ENABLED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Detect HPET base address from ACPI or by scanning
fn detect_hpet_base() -> HpetResult<u64> {
    // Try ACPI first
    if let Some(acpi_base) = crate::arch::x86_64::nonos_acpi::devices::get_hpet_base() {
        if is_valid_hpet(acpi_base) {
            return Ok(acpi_base);
        }
    }

    // Scan common locations
    for &base in &HPET_SCAN_BASES {
        if is_valid_hpet(base) {
            return Ok(base);
        }
    }

    Err(HpetError::NotDetected)
}

/// Build HPET info structure from capabilities
fn build_hpet_info(base: u64, cap: u64) -> HpetInfo {
    let num_timers = (((cap & CAP_NUM_TIMERS_MASK) >> CAP_NUM_TIMERS_SHIFT) + 1) as u8;
    let period_fs = (cap >> CAP_PERIOD_SHIFT) as u32;

    let mut timer_caps = [TimerCapabilities::default(); MAX_TIMERS as usize];

    // Read capabilities for each timer
    for i in 0..num_timers.min(MAX_TIMERS) {
        let tcap = read_timer_config(base, i);
        timer_caps[i as usize] = TimerCapabilities {
            present: true,
            periodic_capable: (tcap & TIMER_CFG_PERIODIC_CAP) != 0,
            size_64bit: (tcap & TIMER_CFG_64BIT_CAP) != 0,
            fsb_capable: (tcap & TIMER_CFG_FSB_CAP) != 0,
            irq_routing_cap: (tcap >> TIMER_CFG_INT_ROUTE_CAP_SHIFT) as u32,
        };
    }

    HpetInfo {
        base_address: base,
        period_fs,
        frequency_hz: (FS_PER_SECOND / period_fs as u128) as u64,
        counter_64bit: (cap & CAP_64BIT) != 0,
        num_timers,
        legacy_capable: (cap & CAP_LEGACY_ROUTE) != 0,
        vendor_id: ((cap >> CAP_VENDOR_SHIFT) & 0xFFFF) as u16,
        revision: (cap & 0xFF) as u8,
        timer_caps,
    }
}

/// Disable a timer (internal, no locking)
fn disable_timer_internal(base: u64, timer: u8) {
    let config = read_timer_config(base, timer);
    write_timer_config(base, timer, config & !TIMER_CFG_INT_ENABLE);
}

// ============================================================================
// Public API - Status
// ============================================================================

/// Check if HPET is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Check if HPET counter is enabled
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Get HPET base address
pub fn base_address() -> Option<u64> {
    if is_initialized() {
        Some(BASE_ADDRESS.load(Ordering::Acquire))
    } else {
        None
    }
}

/// Get HPET counter period in femtoseconds
pub fn period_fs() -> Option<u32> {
    if is_initialized() {
        Some(PERIOD_FS.load(Ordering::Acquire) as u32)
    } else {
        None
    }
}

/// Get HPET frequency in Hz
pub fn frequency_hz() -> Option<u64> {
    if is_initialized() {
        Some(FREQUENCY_HZ.load(Ordering::Acquire))
    } else {
        None
    }
}

/// Get HPET hardware information
pub fn info() -> Option<HpetInfo> {
    INFO.read().clone()
}

/// Get HPET statistics
pub fn stats() -> HpetStats {
    *STATS.read()
}

/// Get timer state
pub fn timer_state(timer: u8) -> Option<TimerState> {
    if timer >= MAX_TIMERS {
        return None;
    }
    Some(TIMER_STATES.read()[timer as usize])
}

// ============================================================================
// Public API - Counter
// ============================================================================

/// Read the main counter value
pub fn read_counter() -> HpetResult<u64> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let value = read_counter_raw(base);

    // Update stats
    {
        let mut stats = STATS.write();
        stats.counter_reads += 1;
        stats.last_counter = value;
    }

    Ok(value)
}

/// Reset the main counter to zero
pub fn reset_counter() -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let base = BASE_ADDRESS.load(Ordering::Acquire);

    // Disable counter, reset, re-enable
    let config = read_config(base);
    write_config(base, config & !CFG_ENABLE);
    write_counter_raw(base, 0);
    write_config(base, config | CFG_ENABLE);

    Ok(())
}

/// Enable the HPET counter
pub fn enable() -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let config = read_config(base);
    write_config(base, config | CFG_ENABLE);
    ENABLED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Disable the HPET counter
pub fn disable() -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let config = read_config(base);
    write_config(base, config & !CFG_ENABLE);
    ENABLED.store(false, Ordering::SeqCst);

    Ok(())
}

// ============================================================================
// Public API - Legacy Mode
// ============================================================================

/// Enable legacy replacement routing
/// Routes Timer 0 to IRQ0 (replaces PIT) and Timer 1 to IRQ8 (replaces RTC)
pub fn enable_legacy_mode() -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let info_guard = INFO.read();
    if let Some(ref info) = *info_guard {
        if !info.legacy_capable {
            return Err(HpetError::InvalidIrqRouting);
        }
    }
    drop(info_guard);

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let config = read_config(base);
    write_config(base, config | CFG_LEGACY_ROUTE);

    Ok(())
}

/// Disable legacy replacement routing
pub fn disable_legacy_mode() -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let config = read_config(base);
    write_config(base, config & !CFG_LEGACY_ROUTE);

    Ok(())
}

// ============================================================================
// Public API - Timer Configuration
// ============================================================================

/// Configure a timer
pub fn configure_timer(config: &TimerConfig) -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let info_guard = INFO.read();
    let info = info_guard.as_ref().ok_or(HpetError::NotInitialized)?;

    if config.timer >= info.num_timers {
        return Err(HpetError::InvalidTimer);
    }

    let timer_cap = &info.timer_caps[config.timer as usize];

    // Validate periodic mode
    if config.mode == TimerMode::Periodic && !timer_cap.periodic_capable {
        return Err(HpetError::PeriodicNotSupported);
    }

    // Validate FSB mode
    if config.int_mode == InterruptMode::Fsb && !timer_cap.fsb_capable {
        return Err(HpetError::FsbNotSupported);
    }

    // Validate IRQ routing for non-FSB modes
    if config.int_mode != InterruptMode::Fsb {
        if config.irq >= 32 {
            return Err(HpetError::InvalidIrqRouting);
        }
        if (timer_cap.irq_routing_cap & (1 << config.irq)) == 0 {
            return Err(HpetError::IrqNotAvailable);
        }
    }

    drop(info_guard);

    // Configure the timer
    let base = BASE_ADDRESS.load(Ordering::Acquire);
    configure_timer_hardware(base, config)?;

    // Update state
    {
        let mut states = TIMER_STATES.write();
        states[config.timer as usize] = TimerState {
            configured: true,
            enabled: false,
            mode: config.mode,
            int_mode: config.int_mode,
            irq: config.irq,
            ticks: config.ticks,
            interrupt_count: 0,
        };
    }

    // Update stats
    STATS.write().timer_configs += 1;

    Ok(())
}

/// Configure timer hardware
fn configure_timer_hardware(base: u64, config: &TimerConfig) -> HpetResult<()> {
    let timer = config.timer;

    // Read current configuration
    let mut tcfg = read_timer_config(base, timer);

    // Clear configurable bits
    tcfg &= TIMER_CFG_PERIODIC_CAP | TIMER_CFG_64BIT_CAP | TIMER_CFG_FSB_CAP
        | (0xFFFFFFFF << TIMER_CFG_INT_ROUTE_CAP_SHIFT);

    // Set interrupt mode
    match config.int_mode {
        InterruptMode::Edge => {
            // Edge triggered, IRQ routing
            tcfg |= (config.irq as u64) << TIMER_CFG_INT_ROUTE_SHIFT;
        }
        InterruptMode::Level => {
            // Level triggered, IRQ routing
            tcfg |= TIMER_CFG_LEVEL;
            tcfg |= (config.irq as u64) << TIMER_CFG_INT_ROUTE_SHIFT;
        }
        InterruptMode::Fsb => {
            // FSB interrupt
            tcfg |= TIMER_CFG_FSB_ENABLE;
            // Set FSB route
            let fsb_value = ((config.fsb_addr as u64) << 32) | (config.fsb_data as u64);
            write_timer_fsb(base, timer, fsb_value);
        }
    }

    // Set timer mode
    if config.mode == TimerMode::Periodic {
        tcfg |= TIMER_CFG_PERIODIC | TIMER_CFG_VALUE_SET;
    }

    // Set 32-bit mode if requested
    if config.force_32bit {
        tcfg |= TIMER_CFG_32BIT_MODE;
    }

    // Write configuration (without enabling yet)
    write_timer_config(base, timer, tcfg);

    // Set comparator value
    let counter = read_counter_raw(base);
    write_timer_comparator(base, timer, counter.wrapping_add(config.ticks));

    // For periodic mode, write period
    if config.mode == TimerMode::Periodic {
        write_timer_comparator(base, timer, config.ticks);
    }

    Ok(())
}

/// Enable a timer interrupt
pub fn enable_timer(timer: u8) -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let info_guard = INFO.read();
    let info = info_guard.as_ref().ok_or(HpetError::NotInitialized)?;
    if timer >= info.num_timers {
        return Err(HpetError::InvalidTimer);
    }
    drop(info_guard);

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let tcfg = read_timer_config(base, timer);
    write_timer_config(base, timer, tcfg | TIMER_CFG_INT_ENABLE);

    TIMER_STATES.write()[timer as usize].enabled = true;

    Ok(())
}

/// Disable a timer interrupt
pub fn disable_timer(timer: u8) -> HpetResult<()> {
    if !is_initialized() {
        return Err(HpetError::NotInitialized);
    }

    let info_guard = INFO.read();
    let info = info_guard.as_ref().ok_or(HpetError::NotInitialized)?;
    if timer >= info.num_timers {
        return Err(HpetError::InvalidTimer);
    }
    drop(info_guard);

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    disable_timer_internal(base, timer);

    TIMER_STATES.write()[timer as usize].enabled = false;

    Ok(())
}

/// Handle timer interrupt
pub fn handle_interrupt(timer: u8) {
    if timer >= MAX_TIMERS {
        return;
    }

    if is_initialized() {
        let base = BASE_ADDRESS.load(Ordering::Acquire);

        // Clear interrupt status for level-triggered
        write_int_status(base, 1 << timer);

        // Update stats
        {
            let mut states = TIMER_STATES.write();
            states[timer as usize].interrupt_count += 1;
        }
        STATS.write().total_interrupts += 1;
    }
}

// ============================================================================
// Public API - Time Conversion
// ============================================================================

/// Convert HPET ticks to nanoseconds
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let period = PERIOD_FS.load(Ordering::Acquire);
    if period == 0 {
        return 0;
    }
    ((ticks as u128 * period as u128) / FS_PER_NS) as u64
}

/// Convert HPET ticks to microseconds
pub fn ticks_to_us(ticks: u64) -> u64 {
    let period = PERIOD_FS.load(Ordering::Acquire);
    if period == 0 {
        return 0;
    }
    ((ticks as u128 * period as u128) / FS_PER_US) as u64
}

/// Convert HPET ticks to milliseconds
pub fn ticks_to_ms(ticks: u64) -> u64 {
    let period = PERIOD_FS.load(Ordering::Acquire);
    if period == 0 {
        return 0;
    }
    ((ticks as u128 * period as u128) / FS_PER_MS) as u64
}

/// Convert nanoseconds to HPET ticks
pub fn ns_to_ticks(ns: u64) -> u64 {
    let period = PERIOD_FS.load(Ordering::Acquire);
    if period == 0 {
        return 0;
    }
    ((ns as u128 * FS_PER_NS) / period as u128) as u64
}

/// Convert microseconds to HPET ticks
pub fn us_to_ticks(us: u64) -> u64 {
    let period = PERIOD_FS.load(Ordering::Acquire);
    if period == 0 {
        return 0;
    }
    ((us as u128 * FS_PER_US) / period as u128) as u64
}

/// Convert milliseconds to HPET ticks
pub fn ms_to_ticks(ms: u64) -> u64 {
    let period = PERIOD_FS.load(Ordering::Acquire);
    if period == 0 {
        return 0;
    }
    ((ms as u128 * FS_PER_MS) / period as u128) as u64
}

// ============================================================================
// Public API - Timing Operations
// ============================================================================

/// Spin-wait for a number of nanoseconds using HPET
pub fn spin_wait_ns(ns: u64) -> HpetResult<()> {
    if !is_enabled() {
        return Err(HpetError::NotInitialized);
    }

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let ticks = ns_to_ticks(ns);
    let start = read_counter_raw(base);
    let target = start.wrapping_add(ticks);

    // Handle wrap-around for 64-bit counter
    while read_counter_raw(base).wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }

    Ok(())
}

/// Spin-wait for a number of microseconds using HPET
pub fn spin_wait_us(us: u64) -> HpetResult<()> {
    spin_wait_ns(us * 1000)
}

/// Spin-wait for a number of milliseconds using HPET
pub fn spin_wait_ms(ms: u64) -> HpetResult<()> {
    spin_wait_ns(ms * 1_000_000)
}

/// Get elapsed time since initialization in nanoseconds
pub fn elapsed_ns() -> HpetResult<u64> {
    let counter = read_counter()?;
    let init = STATS.read().init_counter;
    Ok(ticks_to_ns(counter.wrapping_sub(init)))
}

/// Get elapsed time since initialization in microseconds
pub fn elapsed_us() -> HpetResult<u64> {
    let counter = read_counter()?;
    let init = STATS.read().init_counter;
    Ok(ticks_to_us(counter.wrapping_sub(init)))
}

/// Get elapsed time since initialization in milliseconds
pub fn elapsed_ms() -> HpetResult<u64> {
    let counter = read_counter()?;
    let init = STATS.read().init_counter;
    Ok(ticks_to_ms(counter.wrapping_sub(init)))
}

// ============================================================================
// Public API - Calibration
// ============================================================================

/// Calibrate TSC using HPET as reference
/// Returns TSC frequency in Hz
pub fn calibrate_tsc(duration_ms: u32) -> HpetResult<u64> {
    if !is_enabled() {
        return Err(HpetError::NotInitialized);
    }

    let base = BASE_ADDRESS.load(Ordering::Acquire);
    let hpet_ticks = ms_to_ticks(duration_ms as u64);

    // Read start values
    let hpet_start = read_counter_raw(base);
    let tsc_start: u64;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") _, out("edx") _, options(nomem, nostack));
        core::arch::asm!(
            "rdtsc",
            out("eax") tsc_start,
            out("edx") _,
            options(nomem, nostack)
        );
    }
    let tsc_start = read_tsc();

    // Wait for HPET ticks
    while read_counter_raw(base).wrapping_sub(hpet_start) < hpet_ticks {
        core::hint::spin_loop();
    }

    // Read end values
    let tsc_end = read_tsc();
    let hpet_end = read_counter_raw(base);

    // Calculate frequencies
    let tsc_delta = tsc_end.wrapping_sub(tsc_start);
    let hpet_delta = hpet_end.wrapping_sub(hpet_start);

    if hpet_delta == 0 {
        return Err(HpetError::CalibrationFailed);
    }

    // TSC_freq = TSC_delta * HPET_freq / HPET_delta
    let hpet_freq = FREQUENCY_HZ.load(Ordering::Acquire);
    let tsc_freq = (tsc_delta as u128 * hpet_freq as u128 / hpet_delta as u128) as u64;

    Ok(tsc_freq)
}

/// Read TSC
#[inline]
fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

// ============================================================================
// Legacy API (backward compatibility)
// ============================================================================

/// Detect HPET (legacy API)
pub fn detect_hpet() -> Option<u64> {
    if init().is_ok() {
        base_address()
    } else if is_initialized() {
        base_address()
    } else {
        None
    }
}

/// Get HPET info (legacy API)
pub fn get_hpet_info() -> Option<&'static HpetInfo> {
    // Note: This is unsafe and returns a reference to potentially changing data
    // Prefer using info() which returns a clone
    None
}

/// Read HPET counter (legacy API)
pub fn read_hpet_counter(base: u64) -> u64 {
    read_counter_raw(base)
}

/// Enable HPET (legacy API)
pub fn enable_hpet(base: u64) {
    let config = read_config(base);
    write_config(base, config | CFG_ENABLE);
}

/// Disable HPET (legacy API)
pub fn disable_hpet(base: u64) {
    let config = read_config(base);
    write_config(base, config & !CFG_ENABLE);
}

/// Get frequency (legacy API)
pub fn get_frequency() -> u64 {
    frequency_hz().unwrap_or(10_000_000)
}

// ============================================================================
// Timer Submodule (legacy compatibility)
// ============================================================================

/// Timer configuration submodule
pub mod timer {
    use super::*;

    /// Configure one-shot timer
    pub fn configure_oneshot(base: u64, timer: u8, ticks: u64, irq: u8) -> Result<(), &'static str> {
        let config = TimerConfig {
            timer,
            mode: TimerMode::OneShot,
            int_mode: InterruptMode::Edge,
            irq,
            ticks,
            ..Default::default()
        };

        configure_timer(&config).map_err(|e| e.as_str())
    }

    /// Configure periodic timer
    pub fn configure_periodic(base: u64, timer: u8, period_ticks: u64, irq: u8) -> Result<(), &'static str> {
        let config = TimerConfig {
            timer,
            mode: TimerMode::Periodic,
            int_mode: InterruptMode::Edge,
            irq,
            ticks: period_ticks,
            ..Default::default()
        };

        configure_timer(&config).map_err(|e| e.as_str())?;
        enable_timer(timer).map_err(|e| e.as_str())
    }

    /// Disable timer
    pub fn disable(base: u64, timer: u8) {
        let _ = disable_timer(timer);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(HpetError::NotInitialized.as_str(), "HPET not initialized");
        assert_eq!(HpetError::InvalidTimer.as_str(), "invalid timer number");
    }

    #[test]
    fn test_register_offsets() {
        assert_eq!(REG_CAP_ID, 0x000);
        assert_eq!(REG_CONFIG, 0x010);
        assert_eq!(REG_INT_STATUS, 0x020);
        assert_eq!(REG_MAIN_COUNTER, 0x0F0);
    }

    #[test]
    fn test_timer_register_offsets() {
        assert_eq!(reg_timer_config(0), 0x100);
        assert_eq!(reg_timer_comparator(0), 0x108);
        assert_eq!(reg_timer_fsb(0), 0x110);
        assert_eq!(reg_timer_config(1), 0x120);
        assert_eq!(reg_timer_config(2), 0x140);
    }

    #[test]
    fn test_timer_config_default() {
        let config = TimerConfig::default();
        assert_eq!(config.timer, 0);
        assert_eq!(config.mode, TimerMode::OneShot);
        assert_eq!(config.irq, 0);
    }

    #[test]
    fn test_timer_state_default() {
        let state = TimerState::default();
        assert!(!state.configured);
        assert!(!state.enabled);
    }

    #[test]
    fn test_stats_initial() {
        let stats = HpetStats::new();
        assert_eq!(stats.counter_reads, 0);
        assert_eq!(stats.total_interrupts, 0);
    }

    #[test]
    fn test_timer_capabilities_default() {
        let cap = TimerCapabilities::default();
        assert!(!cap.present);
        assert!(!cap.periodic_capable);
        assert!(!cap.fsb_capable);
    }

    #[test]
    fn test_interrupt_mode() {
        assert_ne!(InterruptMode::Edge, InterruptMode::Level);
        assert_ne!(InterruptMode::Level, InterruptMode::Fsb);
    }

    #[test]
    fn test_timer_mode() {
        assert_ne!(TimerMode::OneShot, TimerMode::Periodic);
    }

    #[test]
    fn test_constants() {
        assert_eq!(HPET_DEFAULT_BASE, 0xFED00000);
        assert_eq!(MAX_TIMERS, 32);
    }

    #[test]
    fn test_time_conversion_units() {
        assert_eq!(FS_PER_NS, 1_000_000);
        assert_eq!(FS_PER_US, 1_000_000_000);
        assert_eq!(FS_PER_MS, 1_000_000_000_000);
    }
}
