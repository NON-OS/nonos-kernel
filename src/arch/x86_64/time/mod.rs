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
// NØNOS Operating System
// Time Subsystem Module
//
// This module provides comprehensive time services for the NØNOS kernel:
// - High-resolution timestamps (TSC, HPET)
// - Hardware timers (PIT, HPET, APIC)
// - Real-time clock (RTC/CMOS)
// - Unified timer abstraction
//
// Architecture:
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                         Time Subsystem                                  │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
// │   ┌─────────────────────────────────────────────────────────────────┐   │
// │   │                     nonos_timer (Unified API)                   │   │
// │   │                                                                 │   │
// │   │   now_ns()  delay_ns()  create_timer()  process_expired()       │   │
// │   └───────┬─────────────────────┬─────────────────────┬─────────────┘   │
// │           │                     │                     │                 │
// │           ▼                     ▼                     ▼                 │
// │   ┌───────────────┐     ┌───────────────┐     ┌───────────────┐         │
// │   │      TSC      │     │     HPET      │     │      PIT      │         │
// │   │               │     │               │     │               │         │
// │   │  rdtsc()      │     │  read_main()  │     │  frequency()  │         │
// │   │  calibrate()  │     │  read_timer() │     │  set_mode()   │         │
// │   │  ticks_to_ns()│     │  set_timer()  │     │  calibrate()  │         │
// │   └───────────────┘     └───────────────┘     └───────────────┘         │
// │                                                                         │
// │   ┌───────────────────────────────────────────────────────────────┐     │
// │   │                           RTC                                 │     │
// │   │                                                               │     │
// │   │   read_rtc()  write_rtc()  set_alarm()  wait_for_update()     │     │
// │   └───────────────────────────────────────────────────────────────┘     │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘
//
// Initialization Order:
// 1. TSC - Detect features and check availability
// 2. PIT - Always available as fallback timer
// 3. HPET - Detect via ACPI, use if available
// 4. RTC - Read initial time
// 5. nonos_timer - Initialize unified timer with best available source
//
// Clock Source Selection (automatic):
// - TSC with invariant flag → Primary (highest resolution)
// - HPET available → Secondary/calibration reference
// - PIT → Fallback (lowest resolution but always available)

pub mod hpet;
pub mod nonos_timer;
pub mod pit;
pub mod rtc;
#[cfg(test)]
pub mod test;
pub mod tsc;

// ============================================================================
// HPET Re-exports
// ============================================================================

pub use hpet::HpetError;
pub use hpet::HpetTimer;
pub use hpet::HpetTimerConfig;
pub use hpet::HpetTimerMode;
pub use hpet::HpetCapabilities;
pub use hpet::HpetStats;

// ============================================================================
// Unified Timer Re-exports
// ============================================================================

pub use nonos_timer::TimerError;
pub use nonos_timer::ClockSource;
pub use nonos_timer::TimerMode;
pub use nonos_timer::TimerState;
pub use nonos_timer::SleepStrategy;
pub use nonos_timer::TimerHandle;
pub use nonos_timer::TimerConfig;
pub use nonos_timer::TimerStats;

// ============================================================================
// PIT Re-exports
// ============================================================================

pub use pit::PitError;
pub use pit::Channel as PitChannel;
pub use pit::Mode as PitMode;
pub use pit::AccessMode as PitAccessMode;
pub use pit::PitState;
pub use pit::ChannelState as PitChannelState;
pub use pit::PitStats;
pub use pit::PIT_FREQUENCY;

// ============================================================================
// RTC Re-exports
// ============================================================================

pub use rtc::RtcError;
pub use rtc::Register as RtcRegister;
pub use rtc::RtcTime;
pub use rtc::RtcAlarm;
pub use rtc::PeriodicRate as RtcPeriodicRate;
pub use rtc::RtcConfig;
pub use rtc::RtcStats;

// ============================================================================
// TSC Re-exports
// ============================================================================

pub use tsc::TscError;
pub use tsc::TscFeatures;
pub use tsc::CalibrationSource as TscCalibrationSource;
pub use tsc::TscState;
pub use tsc::TscStats;

// ============================================================================
// Convenience Functions
// ============================================================================

/// Get current time in nanoseconds using best available clock source.
#[inline]
pub fn now_ns() -> u64 {
    nonos_timer::now_ns()
}

/// Delay for specified nanoseconds.
#[inline]
pub fn delay_ns(ns: u64) {
    nonos_timer::delay_ns(ns);
}

/// Delay for specified microseconds.
#[inline]
pub fn delay_us(us: u64) {
    nonos_timer::delay_us(us);
}

/// Delay for specified milliseconds.
#[inline]
pub fn delay_ms(ms: u64) {
    nonos_timer::delay_ms(ms);
}

/// Read raw TSC value.
#[inline]
pub fn rdtsc() -> u64 {
    tsc::rdtsc()
}

/// Read raw TSC value with serialization and processor ID.
#[inline]
pub fn rdtscp() -> (u64, u32) {
    tsc::rdtscp()
}

/// Read current RTC time.
#[inline]
pub fn read_rtc() -> Result<RtcTime, RtcError> {
    rtc::read_rtc()
}

/// Get Unix timestamp from RTC.
#[inline]
pub fn unix_timestamp() -> Result<u64, RtcError> {
    rtc::read_rtc().map(|t| t.to_unix_timestamp())
}

/// Initialize the time subsystem.
///
/// This should be called early in kernel initialization after ACPI parsing.
/// It detects available clock sources and initializes the unified timer.
pub fn init() -> Result<(), TimerError> {
    // Initialize TSC (always attempt - detection handles unavailability)
    let _ = tsc::init();

    // Initialize PIT (always available on x86)
    let _ = pit::init();

    // Initialize RTC
    let _ = rtc::init();

    // Initialize unified timer (selects best clock source)
    nonos_timer::init()
}

/// Initialize the time subsystem with HPET base address.
///
/// Call this variant when HPET address is known from ACPI.
pub fn init_with_hpet(hpet_base: u64) -> Result<(), TimerError> {
    // Initialize TSC
    let _ = tsc::init();

    // Initialize PIT
    let _ = pit::init();

    // Initialize HPET
    let _ = hpet::init(hpet_base);

    // Initialize RTC
    let _ = rtc::init();

    // Initialize unified timer
    nonos_timer::init()
}

/// Get statistics from all time subsystems.
pub fn get_all_stats() -> (Option<TscStats>, Option<HpetStats>, Option<PitStats>, Option<RtcStats>, Option<TimerStats>) {
    (
        tsc::get_stats(),
        hpet::get_stats(),
        pit::get_stats(),
        rtc::get_stats(),
        nonos_timer::get_stats(),
    )
}

/// Check if the time subsystem is initialized.
#[inline]
pub fn is_initialized() -> bool {
    nonos_timer::is_initialized()
}

/// Get the current clock source.
#[inline]
pub fn clock_source() -> ClockSource {
    nonos_timer::clock_source()
}
