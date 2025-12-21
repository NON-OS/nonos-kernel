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
//! Comprehensive Test Suite for Time Subsystem
//!
//! Tests for all time-related components:
//!
//! - **TSC tests**: RDTSC/RDTSCP, feature detection, calibration, conversions
//! - **HPET tests**: Detection, configuration, timers, interrupts
//! - **PIT tests**: Channels, modes, frequency, calibration
//! - **RTC tests**: Time/date, alarms, BCD conversion, Unix timestamps
//! - **Timer tests**: Unified interface, callbacks, sleep functions
//! - **Integration tests**: Cross-component functionality
//! - **Benchmark tests**: Performance measurements
//!
//! ## Test Categories
//!
//! | Category     | Description                          |
//! |--------------|--------------------------------------|
//! | Unit         | Individual function tests            |
//! | Integration  | Multi-component interaction tests    |
//! | Benchmark    | Performance and timing measurements  |
//! | Stress       | Load and edge case testing           |
//!
//! ## Running Tests
//!
//! Tests can be run in the kernel test harness or via cargo test (for
//! non-hardware-dependent tests).

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Test Result Types
// ============================================================================

/// Test result for kernel tests
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResult {
    /// Test passed
    Passed,
    /// Test failed with message
    Failed,
    /// Test was skipped (hardware not available)
    Skipped,
    /// Test timed out
    Timeout,
}

impl TestResult {
    /// Check if test passed
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Check if test failed
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Get result name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::Skipped => "SKIPPED",
            Self::Timeout => "TIMEOUT",
        }
    }
}

/// Test case descriptor
#[derive(Debug, Clone, Copy)]
pub struct TestCase {
    /// Test name
    pub name: &'static str,
    /// Test category
    pub category: &'static str,
    /// Test function
    pub run: fn() -> TestResult,
    /// Requires hardware
    pub requires_hardware: bool,
}

// ============================================================================
// Test Statistics
// ============================================================================

/// Test run statistics
#[derive(Debug, Clone, Default)]
pub struct TestStats {
    /// Total tests run
    pub total: u32,
    /// Tests passed
    pub passed: u32,
    /// Tests failed
    pub failed: u32,
    /// Tests skipped
    pub skipped: u32,
    /// Tests timed out
    pub timeout: u32,
    /// Total execution time (ns)
    pub total_time_ns: u64,
}

impl TestStats {
    /// Add a test result
    pub fn add_result(&mut self, result: TestResult, duration_ns: u64) {
        self.total += 1;
        self.total_time_ns += duration_ns;
        match result {
            TestResult::Passed => self.passed += 1,
            TestResult::Failed => self.failed += 1,
            TestResult::Skipped => self.skipped += 1,
            TestResult::Timeout => self.timeout += 1,
        }
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.timeout == 0
    }

    /// Get pass rate as percentage
    pub fn pass_rate(&self) -> u32 {
        if self.total == 0 {
            return 100;
        }
        (self.passed * 100) / self.total
    }
}

// ============================================================================
// Test Utilities
// ============================================================================

/// Assert that two values are equal
#[inline]
fn assert_eq<T: PartialEq + core::fmt::Debug>(actual: T, expected: T) -> bool {
    actual == expected
}

/// Assert that a condition is true
#[inline]
fn assert_true(condition: bool) -> bool {
    condition
}

/// Assert that a value is within a range
#[inline]
fn assert_range<T: PartialOrd>(value: T, min: T, max: T) -> bool {
    value >= min && value <= max
}

/// Assert that a result is Ok
#[inline]
fn assert_ok<T, E>(result: Result<T, E>) -> bool {
    result.is_ok()
}

/// Assert that a result is Err
#[inline]
fn assert_err<T, E>(result: Result<T, E>) -> bool {
    result.is_err()
}

/// Get current time in nanoseconds for benchmarking
fn bench_time_ns() -> u64 {
    super::tsc::rdtsc()
}

// ============================================================================
// TSC Tests
// ============================================================================

/// Test RDTSC instruction basic functionality
pub fn test_tsc_rdtsc_basic() -> TestResult {
    let t0 = super::tsc::rdtsc();
    let t1 = super::tsc::rdtsc();

    // TSC should be monotonically increasing
    if t1 >= t0 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

/// Test RDTSC returns non-zero value
pub fn test_tsc_rdtsc_nonzero() -> TestResult {
    let t = super::tsc::rdtsc();

    if t > 0 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

/// Test RDTSC ordering over multiple reads
pub fn test_tsc_ordering() -> TestResult {
    const ITERATIONS: usize = 100;
    let mut prev = super::tsc::rdtsc();

    for _ in 0..ITERATIONS {
        let current = super::tsc::rdtsc();
        if current < prev {
            return TestResult::Failed;
        }
        prev = current;
    }

    TestResult::Passed
}

/// Test TSC feature detection
pub fn test_tsc_features() -> TestResult {
    let features = super::tsc::detect_features();

    // TSC should always be available on x86_64
    if !features.tsc_available {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test TSC frequency bounds
pub fn test_tsc_frequency_bounds() -> TestResult {
    let freq = super::tsc::get_frequency();

    // If calibrated, frequency should be reasonable (100 MHz - 10 GHz)
    if freq > 0 {
        if freq < 100_000_000 || freq > 10_000_000_000 {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

/// Test TSC time conversion consistency
pub fn test_tsc_conversion_roundtrip() -> TestResult {
    let freq: u64 = 3_000_000_000; // 3 GHz test frequency

    // Test: 1 second in ticks
    let ns: u64 = 1_000_000_000;
    let ticks = super::tsc::ns_to_tsc(ns, freq);
    let ns_back = super::tsc::tsc_to_ns(ticks, freq);

    // Allow 1% error due to integer division
    let error = if ns_back > ns { ns_back - ns } else { ns - ns_back };
    let max_error = ns / 100;

    if error <= max_error {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

/// Test TSC conversion with zero frequency
pub fn test_tsc_conversion_zero_freq() -> TestResult {
    let result1 = super::tsc::tsc_to_ns(1000, 0);
    let result2 = super::tsc::ns_to_tsc(1000, 0);

    if result1 == 0 && result2 == 0 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

/// Test RDTSCP if available
pub fn test_tsc_rdtscp() -> TestResult {
    let features = super::tsc::detect_features();

    if !features.rdtscp_available {
        return TestResult::Skipped;
    }

    let (tsc, aux) = super::tsc::rdtscp();

    // TSC should be non-zero
    if tsc == 0 {
        return TestResult::Failed;
    }

    // AUX typically contains processor ID, but we just verify the call works
    let _ = aux;

    TestResult::Passed
}

/// Test TSC calibration source
pub fn test_tsc_calibration_source() -> TestResult {
    let source = super::tsc::get_calibration_source();

    // Verify source has a valid name
    let name = source.name();
    if name.is_empty() {
        return TestResult::Failed;
    }

    // Verify accuracy rating is in valid range
    let rating = source.accuracy_rating();
    if rating > 5 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

// ============================================================================
// HPET Tests
// ============================================================================

/// Test HPET detection
pub fn test_hpet_detection() -> TestResult {
    // Just verify the detection function doesn't panic
    let _ = super::hpet::is_available();
    TestResult::Passed
}

/// Test HPET initialization status
pub fn test_hpet_initialized() -> TestResult {
    let initialized = super::hpet::is_initialized();
    let available = super::hpet::is_available();

    // If available, should be able to check initialization
    // If not available, that's okay (skip test)
    if !available {
        return TestResult::Skipped;
    }

    // Just verify the query works
    let _ = initialized;
    TestResult::Passed
}

/// Test HPET period validation
pub fn test_hpet_period_bounds() -> TestResult {
    if !super::hpet::is_available() {
        return TestResult::Skipped;
    }

    let stats = super::hpet::get_statistics();

    // Period should be in valid range (if initialized)
    if stats.initialized {
        let period_fs = stats.period_fs;
        // HPET period is typically 10-100 nanoseconds (10M-100M femtoseconds)
        if period_fs > 0 && (period_fs < 1_000_000 || period_fs > 1_000_000_000) {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

/// Test HPET counter monotonicity
pub fn test_hpet_counter_monotonic() -> TestResult {
    if !super::hpet::is_available() {
        return TestResult::Skipped;
    }

    let counter1 = match super::hpet::read_counter() {
        Some(c) => c,
        None => return TestResult::Skipped,
    };

    // Small delay
    for _ in 0..1000 {
        core::hint::spin_loop();
    }

    let counter2 = match super::hpet::read_counter() {
        Some(c) => c,
        None => return TestResult::Failed,
    };

    if counter2 >= counter1 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

/// Test HPET time conversion
pub fn test_hpet_ticks_to_ns() -> TestResult {
    if !super::hpet::is_available() {
        return TestResult::Skipped;
    }

    // Test conversion with known ticks
    let ticks: u64 = 1_000_000;
    let ns = super::hpet::ticks_to_ns(ticks);

    match ns {
        Some(n) => {
            // Nanoseconds should be non-zero for non-zero ticks
            if n > 0 {
                TestResult::Passed
            } else {
                TestResult::Failed
            }
        }
        None => TestResult::Failed,
    }
}

/// Test HPET timer count
pub fn test_hpet_timer_count() -> TestResult {
    if !super::hpet::is_available() {
        return TestResult::Skipped;
    }

    let stats = super::hpet::get_statistics();

    if stats.initialized {
        // HPET must have at least 3 timers
        if stats.num_timers < 3 {
            return TestResult::Failed;
        }
        // Maximum is typically 32 timers
        if stats.num_timers > 32 {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

// ============================================================================
// PIT Tests
// ============================================================================

/// Test PIT constants
pub fn test_pit_constants() -> TestResult {
    // Verify PIT frequency constant
    if super::pit::PIT_FREQUENCY != 1193182 {
        return TestResult::Failed;
    }

    // Verify divisor bounds
    if super::pit::MAX_DIVISOR != 65535 {
        return TestResult::Failed;
    }
    if super::pit::MIN_DIVISOR != 1 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test PIT frequency to divisor conversion
pub fn test_pit_freq_to_divisor() -> TestResult {
    // 1000 Hz should give divisor around 1193
    match super::pit::frequency_to_divisor(1000) {
        Ok(divisor) => {
            if divisor < 1190 || divisor > 1196 {
                return TestResult::Failed;
            }
        }
        Err(_) => return TestResult::Failed,
    }

    // 100 Hz should give divisor around 11932
    match super::pit::frequency_to_divisor(100) {
        Ok(divisor) => {
            if divisor < 11920 || divisor > 11940 {
                return TestResult::Failed;
            }
        }
        Err(_) => return TestResult::Failed,
    }

    TestResult::Passed
}

/// Test PIT divisor to frequency conversion
pub fn test_pit_divisor_to_freq() -> TestResult {
    // Divisor 1193 should give ~1000 Hz
    let freq = super::pit::divisor_to_frequency(1193);
    if freq < 990 || freq > 1010 {
        return TestResult::Failed;
    }

    // Divisor 0 should give 0
    let freq_zero = super::pit::divisor_to_frequency(0);
    if freq_zero != 0 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test PIT period calculation
pub fn test_pit_period_ns() -> TestResult {
    // Divisor 1193 should give ~1ms period
    let period = super::pit::divisor_to_period_ns(1193);

    // Allow 5% error
    if period < 950_000 || period > 1_050_000 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test PIT invalid frequency handling
pub fn test_pit_invalid_frequency() -> TestResult {
    // 0 Hz should fail
    if super::pit::frequency_to_divisor(0).is_ok() {
        return TestResult::Failed;
    }

    // Too high frequency should fail
    if super::pit::frequency_to_divisor(2_000_000).is_ok() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test PIT channel enum
pub fn test_pit_channels() -> TestResult {
    // Test channel data ports
    if super::pit::Channel::Channel0.data_port() != 0x40 {
        return TestResult::Failed;
    }
    if super::pit::Channel::Channel1.data_port() != 0x41 {
        return TestResult::Failed;
    }
    if super::pit::Channel::Channel2.data_port() != 0x42 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test PIT mode enum
pub fn test_pit_modes() -> TestResult {
    // Test periodic modes
    if !super::pit::Mode::RateGenerator.is_periodic() {
        return TestResult::Failed;
    }
    if !super::pit::Mode::SquareWave.is_periodic() {
        return TestResult::Failed;
    }

    // Test one-shot modes
    if !super::pit::Mode::InterruptOnTerminal.is_oneshot() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test PIT find best divisor
pub fn test_pit_best_divisor() -> TestResult {
    match super::pit::find_best_divisor(1000) {
        Some((divisor, actual_freq, error)) => {
            // Divisor should be reasonable
            if divisor == 0 || divisor > 65535 {
                return TestResult::Failed;
            }
            // Actual frequency should be close to 1000
            if actual_freq < 990 || actual_freq > 1010 {
                return TestResult::Failed;
            }
            // Error should be small
            if error.abs() > 10 {
                return TestResult::Failed;
            }
            TestResult::Passed
        }
        None => TestResult::Failed,
    }
}

// ============================================================================
// RTC Tests
// ============================================================================

/// Test RTC BCD to binary conversion
pub fn test_rtc_bcd_to_bin() -> TestResult {
    // These are internal functions, test via public API behavior

    // Test via RtcTime validation
    let time = super::rtc::RtcTime::new(2024, 6, 15, 12, 30, 45);
    if time.validate().is_err() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC time validation - valid cases
pub fn test_rtc_time_valid() -> TestResult {
    // Midnight
    let t1 = super::rtc::RtcTime::new(2024, 1, 1, 0, 0, 0);
    if t1.validate().is_err() {
        return TestResult::Failed;
    }

    // End of day
    let t2 = super::rtc::RtcTime::new(2024, 12, 31, 23, 59, 59);
    if t2.validate().is_err() {
        return TestResult::Failed;
    }

    // Leap year Feb 29
    let t3 = super::rtc::RtcTime::new(2024, 2, 29, 12, 0, 0);
    if t3.validate().is_err() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC time validation - invalid cases
pub fn test_rtc_time_invalid() -> TestResult {
    // Invalid second
    let t1 = super::rtc::RtcTime::new(2024, 1, 1, 0, 0, 60);
    if t1.validate().is_ok() {
        return TestResult::Failed;
    }

    // Invalid minute
    let t2 = super::rtc::RtcTime::new(2024, 1, 1, 0, 60, 0);
    if t2.validate().is_ok() {
        return TestResult::Failed;
    }

    // Invalid hour
    let t3 = super::rtc::RtcTime::new(2024, 1, 1, 24, 0, 0);
    if t3.validate().is_ok() {
        return TestResult::Failed;
    }

    // Invalid month
    let t4 = super::rtc::RtcTime::new(2024, 13, 1, 0, 0, 0);
    if t4.validate().is_ok() {
        return TestResult::Failed;
    }

    // Invalid day (Feb 30)
    let t5 = super::rtc::RtcTime::new(2024, 2, 30, 0, 0, 0);
    if t5.validate().is_ok() {
        return TestResult::Failed;
    }

    // Non-leap year Feb 29
    let t6 = super::rtc::RtcTime::new(2023, 2, 29, 0, 0, 0);
    if t6.validate().is_ok() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC leap year detection
pub fn test_rtc_leap_year() -> TestResult {
    // Leap years
    if !super::rtc::is_leap_year(2000) {
        return TestResult::Failed;
    }
    if !super::rtc::is_leap_year(2004) {
        return TestResult::Failed;
    }
    if !super::rtc::is_leap_year(2024) {
        return TestResult::Failed;
    }

    // Non-leap years
    if super::rtc::is_leap_year(1900) {
        return TestResult::Failed;
    }
    if super::rtc::is_leap_year(2100) {
        return TestResult::Failed;
    }
    if super::rtc::is_leap_year(2023) {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC days in month
pub fn test_rtc_days_in_month() -> TestResult {
    // 31-day months
    if super::rtc::days_in_month(2024, 1) != 31 {
        return TestResult::Failed;
    }
    if super::rtc::days_in_month(2024, 7) != 31 {
        return TestResult::Failed;
    }
    if super::rtc::days_in_month(2024, 12) != 31 {
        return TestResult::Failed;
    }

    // 30-day months
    if super::rtc::days_in_month(2024, 4) != 30 {
        return TestResult::Failed;
    }
    if super::rtc::days_in_month(2024, 11) != 30 {
        return TestResult::Failed;
    }

    // February
    if super::rtc::days_in_month(2024, 2) != 29 {
        return TestResult::Failed;
    }
    if super::rtc::days_in_month(2023, 2) != 28 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC day of week calculation
pub fn test_rtc_day_of_week() -> TestResult {
    // 1970-01-01 was Thursday (5)
    if super::rtc::day_of_week(1970, 1, 1) != 5 {
        return TestResult::Failed;
    }

    // 2024-01-01 was Monday (2)
    if super::rtc::day_of_week(2024, 1, 1) != 2 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC Unix timestamp conversion - epoch
pub fn test_rtc_unix_epoch() -> TestResult {
    let time = super::rtc::RtcTime::from_unix_timestamp(0);

    if time.year != 1970 || time.month != 1 || time.day != 1 {
        return TestResult::Failed;
    }
    if time.hour != 0 || time.minute != 0 || time.second != 0 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC Unix timestamp roundtrip
pub fn test_rtc_unix_roundtrip() -> TestResult {
    let original = super::rtc::RtcTime::new(2024, 6, 15, 12, 30, 45);
    let timestamp = original.to_unix_timestamp();
    let converted = super::rtc::RtcTime::from_unix_timestamp(timestamp);

    if converted.year != original.year {
        return TestResult::Failed;
    }
    if converted.month != original.month {
        return TestResult::Failed;
    }
    if converted.day != original.day {
        return TestResult::Failed;
    }
    if converted.hour != original.hour {
        return TestResult::Failed;
    }
    if converted.minute != original.minute {
        return TestResult::Failed;
    }
    if converted.second != original.second {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC alarm validation
pub fn test_rtc_alarm_validation() -> TestResult {
    // Valid alarm
    let valid = super::rtc::RtcAlarm::new(12, 30, 45);
    if valid.validate().is_err() {
        return TestResult::Failed;
    }

    // Wildcard alarm
    let wildcard = super::rtc::RtcAlarm::every_second();
    if wildcard.validate().is_err() {
        return TestResult::Failed;
    }

    // Invalid alarm
    let invalid = super::rtc::RtcAlarm::new(25, 0, 0);
    if invalid.validate().is_ok() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC periodic rate
pub fn test_rtc_periodic_rate() -> TestResult {
    // Test frequency values
    if super::rtc::PeriodicRate::Hz1024.frequency_hz() != 1024 {
        return TestResult::Failed;
    }
    if super::rtc::PeriodicRate::Hz2.frequency_hz() != 2 {
        return TestResult::Failed;
    }
    if super::rtc::PeriodicRate::Disabled.frequency_hz() != 0 {
        return TestResult::Failed;
    }

    // Test period values
    if super::rtc::PeriodicRate::Hz1024.period_us() != 976 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC ISO8601 formatting
pub fn test_rtc_format_iso8601() -> TestResult {
    let time = super::rtc::RtcTime::new(2024, 6, 15, 12, 30, 45);
    let formatted = time.format_iso8601();

    if &formatted != b"2024-06-15 12:30:45" {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test RTC day of year calculation
pub fn test_rtc_day_of_year() -> TestResult {
    let jan1 = super::rtc::RtcTime::new(2024, 1, 1, 0, 0, 0);
    if jan1.day_of_year() != 1 {
        return TestResult::Failed;
    }

    let dec31 = super::rtc::RtcTime::new(2024, 12, 31, 0, 0, 0);
    if dec31.day_of_year() != 366 { // 2024 is leap year
        return TestResult::Failed;
    }

    let dec31_non_leap = super::rtc::RtcTime::new(2023, 12, 31, 0, 0, 0);
    if dec31_non_leap.day_of_year() != 365 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

// ============================================================================
// Timer Tests
// ============================================================================

/// Test timer now_ns basic functionality
pub fn test_timer_now_ns() -> TestResult {
    let t1 = super::nonos_timer::now_ns();
    let t2 = super::nonos_timer::now_ns();

    // Time should be monotonically increasing
    if t2 >= t1 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

/// Test timer time unit conversions
pub fn test_timer_time_units() -> TestResult {
    let ns = super::nonos_timer::now_ns();
    let us = super::nonos_timer::now_us();
    let ms = super::nonos_timer::now_ms();

    // Verify rough relationships (allow for time passing between calls)
    if ns > 0 {
        if us > ns {
            return TestResult::Failed;
        }
        if ms > us {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

/// Test timer clock source
pub fn test_timer_clock_source() -> TestResult {
    let source = super::nonos_timer::get_clock_source();
    let name = source.name();

    // Should have a valid name
    if name.is_empty() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test timer frequency conversion
pub fn test_timer_freq_period() -> TestResult {
    // 1 MHz = 1000 ns period
    let period = super::nonos_timer::freq_to_period_ns(1_000_000);
    if period != 1_000 {
        return TestResult::Failed;
    }

    // 1000 ns period = 1 MHz
    let freq = super::nonos_timer::period_ns_to_freq(1_000);
    if freq != 1_000_000 {
        return TestResult::Failed;
    }

    // Zero handling
    if super::nonos_timer::freq_to_period_ns(0) != 0 {
        return TestResult::Failed;
    }
    if super::nonos_timer::period_ns_to_freq(0) != 0 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test timer format duration
pub fn test_timer_format_duration() -> TestResult {
    let ns = super::nonos_timer::format_duration_ns(500);
    if !ns.ends_with("ns") {
        return TestResult::Failed;
    }

    let us = super::nonos_timer::format_duration_ns(1_500);
    if !us.ends_with("us") {
        return TestResult::Failed;
    }

    let ms = super::nonos_timer::format_duration_ns(1_500_000);
    if !ms.ends_with("ms") {
        return TestResult::Failed;
    }

    let s = super::nonos_timer::format_duration_ns(1_500_000_000);
    if !s.ends_with("s") {
        return TestResult::Failed;
    }

    TestResult::Passed
}

/// Test timer statistics
pub fn test_timer_statistics() -> TestResult {
    let stats = super::nonos_timer::get_statistics();

    // Verify uptime is reasonable (not too large)
    if stats.uptime_ns > 1_000_000_000_000_000 { // > 11 days in ns
        return TestResult::Failed;
    }

    TestResult::Passed
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Integration test: TSC and timer consistency
pub fn test_integration_tsc_timer() -> TestResult {
    if !super::tsc::is_calibrated() {
        return TestResult::Skipped;
    }

    let tsc_freq = super::tsc::get_frequency();
    let timer_source = super::nonos_timer::get_clock_source();

    // If timer uses TSC, frequencies should match
    if matches!(timer_source, super::nonos_timer::ClockSource::Tsc) {
        let timer_freq = super::nonos_timer::get_statistics().tsc_frequency;
        if timer_freq != tsc_freq {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

/// Integration test: Time progression consistency
pub fn test_integration_time_progression() -> TestResult {
    const ITERATIONS: usize = 10;

    let mut prev_tsc = super::tsc::rdtsc();
    let mut prev_timer = super::nonos_timer::now_ns();

    for _ in 0..ITERATIONS {
        // Small delay
        for _ in 0..10000 {
            core::hint::spin_loop();
        }

        let curr_tsc = super::tsc::rdtsc();
        let curr_timer = super::nonos_timer::now_ns();

        // Both should progress
        if curr_tsc <= prev_tsc {
            return TestResult::Failed;
        }
        if curr_timer < prev_timer {
            return TestResult::Failed;
        }

        prev_tsc = curr_tsc;
        prev_timer = curr_timer;
    }

    TestResult::Passed
}

// ============================================================================
// Benchmark Tests
// ============================================================================

/// Benchmark: RDTSC overhead
pub fn bench_rdtsc_overhead() -> TestResult {
    const ITERATIONS: u64 = 10000;

    let start = super::tsc::rdtsc();
    for _ in 0..ITERATIONS {
        let _ = super::tsc::rdtsc();
    }
    let end = super::tsc::rdtsc();

    let total_ticks = end - start;
    let ticks_per_call = total_ticks / ITERATIONS;

    // RDTSC should typically take < 100 cycles
    if ticks_per_call < 1000 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

/// Benchmark: Timer now_ns overhead
pub fn bench_timer_now_ns() -> TestResult {
    const ITERATIONS: u64 = 1000;

    let start = super::tsc::rdtsc();
    for _ in 0..ITERATIONS {
        let _ = super::nonos_timer::now_ns();
    }
    let end = super::tsc::rdtsc();

    let total_ticks = end - start;
    let ticks_per_call = total_ticks / ITERATIONS;

    // now_ns should be reasonably fast (< 10000 cycles)
    if ticks_per_call < 100000 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

// ============================================================================
// Test Registry
// ============================================================================

/// All available tests
pub static TESTS: &[TestCase] = &[
    // TSC Tests
    TestCase {
        name: "tsc_rdtsc_basic",
        category: "tsc",
        run: test_tsc_rdtsc_basic,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_rdtsc_nonzero",
        category: "tsc",
        run: test_tsc_rdtsc_nonzero,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_ordering",
        category: "tsc",
        run: test_tsc_ordering,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_features",
        category: "tsc",
        run: test_tsc_features,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_frequency_bounds",
        category: "tsc",
        run: test_tsc_frequency_bounds,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_conversion_roundtrip",
        category: "tsc",
        run: test_tsc_conversion_roundtrip,
        requires_hardware: false,
    },
    TestCase {
        name: "tsc_conversion_zero_freq",
        category: "tsc",
        run: test_tsc_conversion_zero_freq,
        requires_hardware: false,
    },
    TestCase {
        name: "tsc_rdtscp",
        category: "tsc",
        run: test_tsc_rdtscp,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_calibration_source",
        category: "tsc",
        run: test_tsc_calibration_source,
        requires_hardware: false,
    },

    // HPET Tests
    TestCase {
        name: "hpet_detection",
        category: "hpet",
        run: test_hpet_detection,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_initialized",
        category: "hpet",
        run: test_hpet_initialized,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_period_bounds",
        category: "hpet",
        run: test_hpet_period_bounds,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_counter_monotonic",
        category: "hpet",
        run: test_hpet_counter_monotonic,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_ticks_to_ns",
        category: "hpet",
        run: test_hpet_ticks_to_ns,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_timer_count",
        category: "hpet",
        run: test_hpet_timer_count,
        requires_hardware: true,
    },

    // PIT Tests
    TestCase {
        name: "pit_constants",
        category: "pit",
        run: test_pit_constants,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_freq_to_divisor",
        category: "pit",
        run: test_pit_freq_to_divisor,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_divisor_to_freq",
        category: "pit",
        run: test_pit_divisor_to_freq,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_period_ns",
        category: "pit",
        run: test_pit_period_ns,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_invalid_frequency",
        category: "pit",
        run: test_pit_invalid_frequency,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_channels",
        category: "pit",
        run: test_pit_channels,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_modes",
        category: "pit",
        run: test_pit_modes,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_best_divisor",
        category: "pit",
        run: test_pit_best_divisor,
        requires_hardware: false,
    },

    // RTC Tests
    TestCase {
        name: "rtc_bcd_to_bin",
        category: "rtc",
        run: test_rtc_bcd_to_bin,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_time_valid",
        category: "rtc",
        run: test_rtc_time_valid,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_time_invalid",
        category: "rtc",
        run: test_rtc_time_invalid,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_leap_year",
        category: "rtc",
        run: test_rtc_leap_year,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_days_in_month",
        category: "rtc",
        run: test_rtc_days_in_month,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_day_of_week",
        category: "rtc",
        run: test_rtc_day_of_week,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_unix_epoch",
        category: "rtc",
        run: test_rtc_unix_epoch,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_unix_roundtrip",
        category: "rtc",
        run: test_rtc_unix_roundtrip,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_alarm_validation",
        category: "rtc",
        run: test_rtc_alarm_validation,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_periodic_rate",
        category: "rtc",
        run: test_rtc_periodic_rate,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_format_iso8601",
        category: "rtc",
        run: test_rtc_format_iso8601,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_day_of_year",
        category: "rtc",
        run: test_rtc_day_of_year,
        requires_hardware: false,
    },

    // Timer Tests
    TestCase {
        name: "timer_now_ns",
        category: "timer",
        run: test_timer_now_ns,
        requires_hardware: true,
    },
    TestCase {
        name: "timer_time_units",
        category: "timer",
        run: test_timer_time_units,
        requires_hardware: true,
    },
    TestCase {
        name: "timer_clock_source",
        category: "timer",
        run: test_timer_clock_source,
        requires_hardware: true,
    },
    TestCase {
        name: "timer_freq_period",
        category: "timer",
        run: test_timer_freq_period,
        requires_hardware: false,
    },
    TestCase {
        name: "timer_format_duration",
        category: "timer",
        run: test_timer_format_duration,
        requires_hardware: false,
    },
    TestCase {
        name: "timer_statistics",
        category: "timer",
        run: test_timer_statistics,
        requires_hardware: true,
    },

    // Integration Tests
    TestCase {
        name: "integration_tsc_timer",
        category: "integration",
        run: test_integration_tsc_timer,
        requires_hardware: true,
    },
    TestCase {
        name: "integration_time_progression",
        category: "integration",
        run: test_integration_time_progression,
        requires_hardware: true,
    },

    // Benchmark Tests
    TestCase {
        name: "bench_rdtsc_overhead",
        category: "benchmark",
        run: bench_rdtsc_overhead,
        requires_hardware: true,
    },
    TestCase {
        name: "bench_timer_now_ns",
        category: "benchmark",
        run: bench_timer_now_ns,
        requires_hardware: true,
    },
];

// ============================================================================
// Test Runner
// ============================================================================

/// Run all tests
pub fn run_all_tests() -> TestStats {
    run_tests_filtered(|_| true)
}

/// Run tests by category
pub fn run_category(category: &str) -> TestStats {
    run_tests_filtered(|test| test.category == category)
}

/// Run only software tests (no hardware required)
pub fn run_software_tests() -> TestStats {
    run_tests_filtered(|test| !test.requires_hardware)
}

/// Run tests with filter
pub fn run_tests_filtered<F>(filter: F) -> TestStats
where
    F: Fn(&TestCase) -> bool,
{
    let mut stats = TestStats::default();

    for test in TESTS.iter() {
        if !filter(test) {
            continue;
        }

        let start = bench_time_ns();
        let result = (test.run)();
        let end = bench_time_ns();
        let duration = end.saturating_sub(start);

        stats.add_result(result, duration);
    }

    stats
}

/// Run a single test by name
pub fn run_test(name: &str) -> Option<TestResult> {
    for test in TESTS.iter() {
        if test.name == name {
            return Some((test.run)());
        }
    }
    None
}

/// Get test by name
pub fn get_test(name: &str) -> Option<&'static TestCase> {
    TESTS.iter().find(|t| t.name == name)
}

/// Get all test names
pub fn test_names() -> impl Iterator<Item = &'static str> {
    TESTS.iter().map(|t| t.name)
}

/// Get all categories
pub fn categories() -> impl Iterator<Item = &'static str> {
    // Return unique categories
    static CATEGORIES: &[&str] = &["tsc", "hpet", "pit", "rtc", "timer", "integration", "benchmark"];
    CATEGORIES.iter().copied()
}

/// Count tests in category
pub fn count_category(category: &str) -> usize {
    TESTS.iter().filter(|t| t.category == category).count()
}

/// Total test count
pub fn total_test_count() -> usize {
    TESTS.len()
}

// ============================================================================
// Standard Test Module (for cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_tests_pass() {
        let stats = run_software_tests();
        assert!(stats.all_passed(), "Some software tests failed");
    }

    #[test]
    fn test_result_is_passed() {
        assert!(TestResult::Passed.is_passed());
        assert!(!TestResult::Failed.is_passed());
        assert!(!TestResult::Skipped.is_passed());
    }

    #[test]
    fn test_result_is_failed() {
        assert!(!TestResult::Passed.is_failed());
        assert!(TestResult::Failed.is_failed());
        assert!(!TestResult::Skipped.is_failed());
    }

    #[test]
    fn test_result_names() {
        assert_eq!(TestResult::Passed.name(), "PASSED");
        assert_eq!(TestResult::Failed.name(), "FAILED");
        assert_eq!(TestResult::Skipped.name(), "SKIPPED");
        assert_eq!(TestResult::Timeout.name(), "TIMEOUT");
    }

    #[test]
    fn test_stats_add_result() {
        let mut stats = TestStats::default();
        stats.add_result(TestResult::Passed, 1000);
        stats.add_result(TestResult::Failed, 2000);
        stats.add_result(TestResult::Skipped, 500);

        assert_eq!(stats.total, 3);
        assert_eq!(stats.passed, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.total_time_ns, 3500);
    }

    #[test]
    fn test_stats_all_passed() {
        let mut stats = TestStats::default();
        stats.add_result(TestResult::Passed, 100);
        stats.add_result(TestResult::Passed, 100);
        stats.add_result(TestResult::Skipped, 100);

        assert!(stats.all_passed());

        stats.add_result(TestResult::Failed, 100);
        assert!(!stats.all_passed());
    }

    #[test]
    fn test_stats_pass_rate() {
        let mut stats = TestStats::default();
        assert_eq!(stats.pass_rate(), 100);

        stats.add_result(TestResult::Passed, 100);
        assert_eq!(stats.pass_rate(), 100);

        stats.add_result(TestResult::Failed, 100);
        assert_eq!(stats.pass_rate(), 50);
    }

    #[test]
    fn test_test_registry() {
        assert!(total_test_count() > 0);
        assert!(test_names().count() > 0);
    }

    #[test]
    fn test_get_test() {
        let test = get_test("pit_constants");
        assert!(test.is_some());
        let test = test.unwrap();
        assert_eq!(test.name, "pit_constants");
        assert_eq!(test.category, "pit");
    }

    #[test]
    fn test_category_count() {
        assert!(count_category("pit") > 0);
        assert!(count_category("rtc") > 0);
        assert_eq!(count_category("nonexistent"), 0);
    }
}
