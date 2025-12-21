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
//! MC146818 Real-Time Clock (RTC) 
//!
//! RTC/CMOS NØNOS with:
//! **Complete time support**
//! **Alarm functionality**
//! **Interrupt support**
//! **Unix timestamp**
//! **CMOS RAM access**
//! **BCD/Binary modes**
//! **12/24 hour modes**
//! **Thread-safe design**
//!
//! ## MC146818 Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    RTC/CMOS Block Diagram                       │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  I/O Ports:                                                     │
//! │    0x70 - CMOS Address Register (+ NMI disable bit 7)           │
//! │    0x71 - CMOS Data Register                                    │
//! │                                                                 │
//! │  Time Registers (0x00-0x09):                                    │
//! │    0x00 - Seconds           0x04 - Hours                        │
//! │    0x02 - Minutes           0x06 - Day of Week                  │
//! │    0x07 - Day of Month      0x08 - Month                        │
//! │    0x09 - Year              0x32 - Century (if available)       │
//! │                                                                 │
//! │  Alarm Registers (0x01, 0x03, 0x05):                            │
//! │    Seconds, Minutes, Hours alarm values                         │
//! │                                                                 │
//! │  Status Registers:                                              │
//! │    0x0A - Status A (update in progress, divider, rate)          │
//! │    0x0B - Status B (interrupts, modes, DSE)                     │
//! │    0x0C - Status C (interrupt flags, read-only)                 │
//! │    0x0D - Status D (battery status)                             │
//! │                                                                 │
//! │  CMOS RAM: 0x10-0x7F (114 bytes of battery-backed storage)      │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Interrupt Sources (IRQ 8)
//!
//! | Type              | Status B Bit | Description                    |
//! |-------------------|--------------|--------------------------------|
//! | Update-Ended      | UIE (bit 4)  | Fires after each second update |
//! | Alarm             | AIE (bit 5)  | Fires when time matches alarm  |
//! | Periodic          | PIE (bit 6)  | Fires at programmed rate       |

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicI32, Ordering};
use spin::RwLock;

// ============================================================================
// Constants
// ============================================================================

/// Unix epoch year
const UNIX_EPOCH_YEAR: u16 = 1970;

/// Days per month (non-leap year)
const DAYS_PER_MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Seconds per minute
const SECS_PER_MIN: u64 = 60;

/// Seconds per hour
const SECS_PER_HOUR: u64 = 3600;

/// Seconds per day
const SECS_PER_DAY: u64 = 86400;

/// Days from year 0 to Unix epoch (1970)
const DAYS_TO_EPOCH: u64 = 719468;

// ============================================================================
// I/O Ports
// ============================================================================

mod ports {
    /// CMOS address register (bit 7 = NMI disable)
    pub const CMOS_ADDR: u16 = 0x70;
    /// CMOS data register
    pub const CMOS_DATA: u16 = 0x71;
}

// ============================================================================
// Register Addresses
// ============================================================================

/// RTC/CMOS register addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Register {
    /// Seconds (0-59)
    Seconds = 0x00,
    /// Seconds alarm
    SecondsAlarm = 0x01,
    /// Minutes (0-59)
    Minutes = 0x02,
    /// Minutes alarm
    MinutesAlarm = 0x03,
    /// Hours (0-23 or 1-12 + AM/PM)
    Hours = 0x04,
    /// Hours alarm
    HoursAlarm = 0x05,
    /// Day of week (1-7, Sunday = 1)
    DayOfWeek = 0x06,
    /// Day of month (1-31)
    DayOfMonth = 0x07,
    /// Month (1-12)
    Month = 0x08,
    /// Year (0-99)
    Year = 0x09,
    /// Status register A
    StatusA = 0x0A,
    /// Status register B
    StatusB = 0x0B,
    /// Status register C (read-only, clears on read)
    StatusC = 0x0C,
    /// Status register D (battery status)
    StatusD = 0x0D,
    /// Century register (non-standard, may not exist)
    Century = 0x32,
    /// Floppy drive types
    FloppyTypes = 0x10,
    /// Hard disk types
    HardDiskTypes = 0x12,
    /// Equipment byte
    Equipment = 0x14,
    /// Base memory low byte
    BaseMemoryLow = 0x15,
    /// Base memory high byte
    BaseMemoryHigh = 0x16,
    /// Extended memory low byte
    ExtendedMemoryLow = 0x17,
    /// Extended memory high byte
    ExtendedMemoryHigh = 0x18,
    /// CMOS checksum high
    ChecksumHigh = 0x2E,
    /// CMOS checksum low
    ChecksumLow = 0x2F,
    /// POST status
    PostStatus = 0x0E,
    /// Shutdown status
    ShutdownStatus = 0x0F,
}

// ============================================================================
// Status Register Bits
// ============================================================================

/// Status Register A bits
mod status_a {
    /// Update in progress (read-only)
    pub const UIP: u8 = 0x80;
    /// Divider bits (bits 4-6)
    pub const DIVIDER_MASK: u8 = 0x70;
    /// Rate selection bits (bits 0-3)
    pub const RATE_MASK: u8 = 0x0F;
    /// Normal operation divider (32.768 kHz)
    pub const DIVIDER_NORMAL: u8 = 0x20;
}

/// Status Register B bits
mod status_b {
    /// Daylight Saving Enable
    pub const DSE: u8 = 0x01;
    /// 24/12 hour mode (1 = 24-hour)
    pub const HOUR_24: u8 = 0x02;
    /// Data mode (1 = binary, 0 = BCD)
    pub const DM: u8 = 0x04;
    /// Square wave enable
    pub const SQWE: u8 = 0x08;
    /// Update-ended interrupt enable
    pub const UIE: u8 = 0x10;
    /// Alarm interrupt enable
    pub const AIE: u8 = 0x20;
    /// Periodic interrupt enable
    pub const PIE: u8 = 0x40;
    /// Update cycle inhibit (SET)
    pub const SET: u8 = 0x80;
}

/// Status Register C bits (interrupt flags, cleared on read)
mod status_c {
    /// Update-ended interrupt flag
    pub const UF: u8 = 0x10;
    /// Alarm interrupt flag
    pub const AF: u8 = 0x20;
    /// Periodic interrupt flag
    pub const PF: u8 = 0x40;
    /// Interrupt request flag
    pub const IRQF: u8 = 0x80;
}

/// Status Register D bits
mod status_d {
    /// Valid RAM and time (battery good)
    pub const VRT: u8 = 0x80;
}

// ============================================================================
// Error Handling
// ============================================================================

/// RTC error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RtcError {
    /// RTC not initialized
    NotInitialized = 0,
    /// Already initialized
    AlreadyInitialized = 1,
    /// Invalid time value
    InvalidTime = 2,
    /// Invalid date value
    InvalidDate = 3,
    /// Invalid alarm value
    InvalidAlarm = 4,
    /// Update in progress (timeout)
    UpdateInProgress = 5,
    /// Battery failure
    BatteryFailure = 6,
    /// Invalid register address
    InvalidRegister = 7,
    /// Invalid CMOS checksum
    InvalidChecksum = 8,
    /// Hardware access error
    HardwareError = 9,
    /// Timeout waiting for RTC
    Timeout = 10,
    /// Century register not available
    NoCenturyRegister = 11,
}

impl RtcError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "RTC not initialized",
            Self::AlreadyInitialized => "RTC already initialized",
            Self::InvalidTime => "Invalid time value",
            Self::InvalidDate => "Invalid date value",
            Self::InvalidAlarm => "Invalid alarm value",
            Self::UpdateInProgress => "Update in progress timeout",
            Self::BatteryFailure => "RTC battery failure",
            Self::InvalidRegister => "Invalid register address",
            Self::InvalidChecksum => "Invalid CMOS checksum",
            Self::HardwareError => "Hardware access error",
            Self::Timeout => "Timeout waiting for RTC",
            Self::NoCenturyRegister => "Century register not available",
        }
    }
}

/// Result type for RTC operations
pub type RtcResult<T> = Result<T, RtcError>;

// ============================================================================
// Time Structures
// ============================================================================

/// RTC time and date
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcTime {
    /// Year (1970-2099)
    pub year: u16,
    /// Month (1-12)
    pub month: u8,
    /// Day of month (1-31)
    pub day: u8,
    /// Hour (0-23)
    pub hour: u8,
    /// Minute (0-59)
    pub minute: u8,
    /// Second (0-59)
    pub second: u8,
    /// Day of week (1-7, Sunday = 1)
    pub day_of_week: u8,
}

impl RtcTime {
    /// Create a new RtcTime
    pub const fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            day_of_week: 0,
        }
    }

    /// Validate the time values
    pub fn validate(&self) -> RtcResult<()> {
        // Validate time
        if self.second > 59 {
            return Err(RtcError::InvalidTime);
        }
        if self.minute > 59 {
            return Err(RtcError::InvalidTime);
        }
        if self.hour > 23 {
            return Err(RtcError::InvalidTime);
        }

        // Validate date
        if self.month < 1 || self.month > 12 {
            return Err(RtcError::InvalidDate);
        }
        if self.day < 1 {
            return Err(RtcError::InvalidDate);
        }

        let max_day = days_in_month(self.year, self.month);
        if self.day > max_day {
            return Err(RtcError::InvalidDate);
        }

        if self.year < 1970 || self.year > 2099 {
            return Err(RtcError::InvalidDate);
        }

        Ok(())
    }

    /// Convert to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
    pub fn to_unix_timestamp(&self) -> u64 {
        datetime_to_unix(self.year, self.month, self.day, self.hour, self.minute, self.second)
    }

    /// Create from Unix timestamp
    pub fn from_unix_timestamp(timestamp: u64) -> Self {
        unix_to_datetime(timestamp)
    }

    /// Calculate day of week (1 = Sunday, 7 = Saturday)
    pub fn calculate_day_of_week(&self) -> u8 {
        day_of_week(self.year, self.month, self.day)
    }

    /// Get with calculated day of week
    pub fn with_day_of_week(mut self) -> Self {
        self.day_of_week = self.calculate_day_of_week();
        self
    }

    /// Check if this is a leap year
    pub fn is_leap_year(&self) -> bool {
        is_leap_year(self.year)
    }

    /// Get day of year (1-366)
    pub fn day_of_year(&self) -> u16 {
        let mut day = self.day as u16;
        for m in 1..self.month {
            day += days_in_month(self.year, m) as u16;
        }
        day
    }

    /// Format as ISO 8601 string (YYYY-MM-DD HH:MM:SS)
    pub fn format_iso8601(&self) -> [u8; 19] {
        let mut buf = [0u8; 19];

        // Year
        buf[0] = b'0' + ((self.year / 1000) % 10) as u8;
        buf[1] = b'0' + ((self.year / 100) % 10) as u8;
        buf[2] = b'0' + ((self.year / 10) % 10) as u8;
        buf[3] = b'0' + (self.year % 10) as u8;
        buf[4] = b'-';

        // Month
        buf[5] = b'0' + (self.month / 10);
        buf[6] = b'0' + (self.month % 10);
        buf[7] = b'-';

        // Day
        buf[8] = b'0' + (self.day / 10);
        buf[9] = b'0' + (self.day % 10);
        buf[10] = b' ';

        // Hour
        buf[11] = b'0' + (self.hour / 10);
        buf[12] = b'0' + (self.hour % 10);
        buf[13] = b':';

        // Minute
        buf[14] = b'0' + (self.minute / 10);
        buf[15] = b'0' + (self.minute % 10);
        buf[16] = b':';

        // Second
        buf[17] = b'0' + (self.second / 10);
        buf[18] = b'0' + (self.second % 10);

        buf
    }
}

/// RTC alarm configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcAlarm {
    /// Alarm hour (0-23, or 0xFF for "don't care")
    pub hour: u8,
    /// Alarm minute (0-59, or 0xFF for "don't care")
    pub minute: u8,
    /// Alarm second (0-59, or 0xFF for "don't care")
    pub second: u8,
}

impl RtcAlarm {
    /// Create a new alarm
    pub const fn new(hour: u8, minute: u8, second: u8) -> Self {
        Self { hour, minute, second }
    }

    /// Create an alarm that fires every second
    pub const fn every_second() -> Self {
        Self {
            hour: 0xFF,
            minute: 0xFF,
            second: 0xFF,
        }
    }

    /// Create an alarm that fires every minute (at second 0)
    pub const fn every_minute() -> Self {
        Self {
            hour: 0xFF,
            minute: 0xFF,
            second: 0,
        }
    }

    /// Create an alarm that fires every hour (at minute:second 00:00)
    pub const fn every_hour() -> Self {
        Self {
            hour: 0xFF,
            minute: 0,
            second: 0,
        }
    }

    /// Validate alarm values
    pub fn validate(&self) -> RtcResult<()> {
        if self.second != 0xFF && self.second > 59 {
            return Err(RtcError::InvalidAlarm);
        }
        if self.minute != 0xFF && self.minute > 59 {
            return Err(RtcError::InvalidAlarm);
        }
        if self.hour != 0xFF && self.hour > 23 {
            return Err(RtcError::InvalidAlarm);
        }
        Ok(())
    }
}

/// Periodic interrupt rate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeriodicRate {
    /// Disabled
    Disabled = 0,
    /// 3.90625 ms (256 Hz)
    Hz256 = 1,
    /// 7.8125 ms (128 Hz)
    Hz128 = 2,
    /// 122.070 us (8192 Hz)
    Hz8192 = 3,
    /// 244.141 us (4096 Hz)
    Hz4096 = 4,
    /// 488.281 us (2048 Hz)
    Hz2048 = 5,
    /// 976.5625 us (1024 Hz)
    Hz1024 = 6,
    /// 1.953125 ms (512 Hz)
    Hz512 = 7,
    /// 3.90625 ms (256 Hz)
    Hz256_2 = 8,
    /// 7.8125 ms (128 Hz)
    Hz128_2 = 9,
    /// 15.625 ms (64 Hz)
    Hz64 = 10,
    /// 31.25 ms (32 Hz)
    Hz32 = 11,
    /// 62.5 ms (16 Hz)
    Hz16 = 12,
    /// 125 ms (8 Hz)
    Hz8 = 13,
    /// 250 ms (4 Hz)
    Hz4 = 14,
    /// 500 ms (2 Hz)
    Hz2 = 15,
}

impl PeriodicRate {
    /// Get the rate register value
    pub const fn value(&self) -> u8 {
        *self as u8
    }

    /// Get frequency in Hz
    pub const fn frequency_hz(&self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Hz256 | Self::Hz256_2 => 256,
            Self::Hz128 | Self::Hz128_2 => 128,
            Self::Hz8192 => 8192,
            Self::Hz4096 => 4096,
            Self::Hz2048 => 2048,
            Self::Hz1024 => 1024,
            Self::Hz512 => 512,
            Self::Hz64 => 64,
            Self::Hz32 => 32,
            Self::Hz16 => 16,
            Self::Hz8 => 8,
            Self::Hz4 => 4,
            Self::Hz2 => 2,
        }
    }

    /// Get period in microseconds
    pub const fn period_us(&self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Hz256 | Self::Hz256_2 => 3906,
            Self::Hz128 | Self::Hz128_2 => 7812,
            Self::Hz8192 => 122,
            Self::Hz4096 => 244,
            Self::Hz2048 => 488,
            Self::Hz1024 => 976,
            Self::Hz512 => 1953,
            Self::Hz64 => 15625,
            Self::Hz32 => 31250,
            Self::Hz16 => 62500,
            Self::Hz8 => 125000,
            Self::Hz4 => 250000,
            Self::Hz2 => 500000,
        }
    }
}

// ============================================================================
// RTC State
// ============================================================================

/// RTC configuration state
struct RtcState {
    /// Is binary mode (vs BCD)?
    binary_mode: bool,
    /// Is 24-hour mode (vs 12-hour)?
    hour_24_mode: bool,
    /// Is century register available?
    has_century: bool,
    /// Current timezone offset in seconds (from UTC)
    timezone_offset: i32,
    /// Alarm enabled?
    alarm_enabled: bool,
    /// Periodic interrupt enabled?
    periodic_enabled: bool,
    /// Update interrupt enabled?
    update_enabled: bool,
    /// Current periodic rate
    periodic_rate: PeriodicRate,
}

impl Default for RtcState {
    fn default() -> Self {
        Self {
            binary_mode: false,
            hour_24_mode: true,
            has_century: false,
            timezone_offset: 0,
            alarm_enabled: false,
            periodic_enabled: false,
            update_enabled: false,
            periodic_rate: PeriodicRate::Disabled,
        }
    }
}

/// RTC statistics
#[derive(Debug, Clone, Default)]
pub struct RtcStatistics {
    /// Is RTC initialized?
    pub initialized: bool,
    /// Is battery good?
    pub battery_good: bool,
    /// Is binary mode?
    pub binary_mode: bool,
    /// Is 24-hour mode?
    pub hour_24_mode: bool,
    /// Has century register?
    pub has_century: bool,
    /// Timezone offset in seconds
    pub timezone_offset: i32,
    /// Total reads performed
    pub reads: u64,
    /// Total writes performed
    pub writes: u64,
    /// Total alarm interrupts
    pub alarm_interrupts: u64,
    /// Total periodic interrupts
    pub periodic_interrupts: u64,
    /// Total update interrupts
    pub update_interrupts: u64,
    /// Last read Unix timestamp
    pub last_timestamp: u64,
}

// ============================================================================
// Global State
// ============================================================================

/// RTC initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// RTC state
static RTC_STATE: RwLock<RtcState> = RwLock::new(RtcState {
    binary_mode: false,
    hour_24_mode: true,
    has_century: false,
    timezone_offset: 0,
    alarm_enabled: false,
    periodic_enabled: false,
    update_enabled: false,
    periodic_rate: PeriodicRate::Disabled,
});

/// Statistics counters
static STATS_READS: AtomicU64 = AtomicU64::new(0);
static STATS_WRITES: AtomicU64 = AtomicU64::new(0);
static STATS_ALARM_INTS: AtomicU64 = AtomicU64::new(0);
static STATS_PERIODIC_INTS: AtomicU64 = AtomicU64::new(0);
static STATS_UPDATE_INTS: AtomicU64 = AtomicU64::new(0);
static STATS_LAST_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Port I/O
// ============================================================================

/// Read byte from I/O port
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

/// Write byte to I/O port
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
// Low-Level CMOS Access
// ============================================================================

/// Read a CMOS register
#[inline]
fn cmos_read(register: u8) -> u8 {
    unsafe {
        // Set address with NMI disabled (bit 7 set)
        outb(ports::CMOS_ADDR, register | 0x80);
        // Small delay for CMOS timing
        inb(0x80);
        // Read data
        inb(ports::CMOS_DATA)
    }
}

/// Write a CMOS register
#[inline]
fn cmos_write(register: u8, value: u8) {
    unsafe {
        // Set address with NMI disabled (bit 7 set)
        outb(ports::CMOS_ADDR, register | 0x80);
        // Small delay for CMOS timing
        inb(0x80);
        // Write data
        outb(ports::CMOS_DATA, value);
    }
}

/// Read a CMOS register (public, with register enum)
pub fn read_register(register: Register) -> u8 {
    cmos_read(register as u8)
}

/// Write a CMOS register (public, with register enum)
pub fn write_register(register: Register, value: u8) {
    cmos_write(register as u8, value);
    STATS_WRITES.fetch_add(1, Ordering::Relaxed);
}

/// Read raw CMOS address
pub fn read_cmos(address: u8) -> u8 {
    if address > 0x7F {
        return 0;
    }
    cmos_read(address)
}

/// Write raw CMOS address
pub fn write_cmos(address: u8, value: u8) {
    if address > 0x7F {
        return;
    }
    cmos_write(address, value);
    STATS_WRITES.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// BCD Conversion
// ============================================================================

/// Convert BCD to binary
#[inline]
const fn bcd_to_bin(bcd: u8) -> u8 {
    ((bcd >> 4) * 10) + (bcd & 0x0F)
}

/// Convert binary to BCD
#[inline]
const fn bin_to_bcd(bin: u8) -> u8 {
    ((bin / 10) << 4) | (bin % 10)
}

// ============================================================================
// Date/Time Calculations
// ============================================================================

/// Check if year is a leap year
pub const fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get days in a month
pub const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 => 31,
        2 => if is_leap_year(year) { 29 } else { 28 },
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 0,
    }
}

/// Calculate day of week using Zeller's congruence
/// Returns 1 = Sunday, 2 = Monday, ..., 7 = Saturday
pub fn day_of_week(year: u16, month: u8, day: u8) -> u8 {
    let mut y = year as i32;
    let mut m = month as i32;

    // Adjust for Zeller's formula (Jan/Feb are months 13/14 of previous year)
    if m < 3 {
        m += 12;
        y -= 1;
    }

    let q = day as i32;
    let k = y % 100;
    let j = y / 100;

    let h = (q + (13 * (m + 1)) / 5 + k + k / 4 + j / 4 - 2 * j) % 7;

    // Convert from Zeller (0=Sat, 1=Sun, ..., 6=Fri) to (1=Sun, ..., 7=Sat)
    let dow = ((h + 6) % 7) + 1;
    dow as u8
}

/// Get day name
pub const fn day_name(day_of_week: u8) -> &'static str {
    match day_of_week {
        1 => "Sunday",
        2 => "Monday",
        3 => "Tuesday",
        4 => "Wednesday",
        5 => "Thursday",
        6 => "Friday",
        7 => "Saturday",
        _ => "Unknown",
    }
}

/// Get month name
pub const fn month_name(month: u8) -> &'static str {
    match month {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => "Unknown",
    }
}

/// Convert datetime to Unix timestamp
pub fn datetime_to_unix(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> u64 {
    // Days since year 0
    let mut days = 0u64;

    // Add days for years
    for y in UNIX_EPOCH_YEAR..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for months
    for m in 1..month {
        days += days_in_month(year, m) as u64;
    }

    // Add days
    days += (day - 1) as u64;

    // Convert to seconds and add time
    days * SECS_PER_DAY + (hour as u64) * SECS_PER_HOUR + (minute as u64) * SECS_PER_MIN + second as u64
}

/// Convert Unix timestamp to datetime
pub fn unix_to_datetime(timestamp: u64) -> RtcTime {
    let mut remaining = timestamp;

    // Extract time of day
    let second = (remaining % 60) as u8;
    remaining /= 60;
    let minute = (remaining % 60) as u8;
    remaining /= 60;
    let hour = (remaining % 24) as u8;
    remaining /= 24;

    // remaining is now days since epoch
    let mut year = UNIX_EPOCH_YEAR;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year as u64 {
            break;
        }
        remaining -= days_in_year as u64;
        year += 1;
    }

    // Find month
    let mut month = 1u8;
    loop {
        let days = days_in_month(year, month) as u64;
        if remaining < days {
            break;
        }
        remaining -= days;
        month += 1;
    }

    let day = remaining as u8 + 1;
    let day_of_week = day_of_week(year, month, day);

    RtcTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        day_of_week,
    }
}

// ============================================================================
// RTC Reading
// ============================================================================

/// Wait until RTC update is not in progress
fn wait_for_update() -> RtcResult<()> {
    let mut timeout = 10000u32;
    while (cmos_read(Register::StatusA as u8) & status_a::UIP) != 0 && timeout > 0 {
        timeout -= 1;
        core::hint::spin_loop();
    }
    if timeout == 0 {
        Err(RtcError::UpdateInProgress)
    } else {
        Ok(())
    }
}

/// Read RTC time (internal, handles BCD/binary and 12/24 hour modes)
fn read_rtc_internal() -> RtcResult<RtcTime> {
    wait_for_update()?;

    // Read all time registers
    let second_raw = cmos_read(Register::Seconds as u8);
    let minute_raw = cmos_read(Register::Minutes as u8);
    let hour_raw = cmos_read(Register::Hours as u8);
    let day_raw = cmos_read(Register::DayOfMonth as u8);
    let month_raw = cmos_read(Register::Month as u8);
    let year_raw = cmos_read(Register::Year as u8);
    let dow_raw = cmos_read(Register::DayOfWeek as u8);

    // Read status register B to determine mode
    let status_b = cmos_read(Register::StatusB as u8);
    let is_binary = (status_b & status_b::DM) != 0;
    let is_24_hour = (status_b & status_b::HOUR_24) != 0;

    // Convert values
    let second = if is_binary { second_raw } else { bcd_to_bin(second_raw) };
    let minute = if is_binary { minute_raw } else { bcd_to_bin(minute_raw) };
    let day = if is_binary { day_raw } else { bcd_to_bin(day_raw) };
    let month = if is_binary { month_raw } else { bcd_to_bin(month_raw) };
    let year_2digit = if is_binary { year_raw } else { bcd_to_bin(year_raw) };
    let day_of_week = if is_binary { dow_raw } else { bcd_to_bin(dow_raw) };

    // Handle hours (12/24 hour mode and PM flag)
    let hour = if is_24_hour {
        if is_binary { hour_raw } else { bcd_to_bin(hour_raw) }
    } else {
        let pm = (hour_raw & 0x80) != 0;
        let h = if is_binary {
            hour_raw & 0x7F
        } else {
            bcd_to_bin(hour_raw & 0x7F)
        };
        // Convert 12-hour to 24-hour
        match (h, pm) {
            (12, false) => 0,  // 12 AM = 00:00
            (12, true) => 12,  // 12 PM = 12:00
            (h, false) => h,   // AM hours stay same
            (h, true) => h + 12, // PM hours add 12
        }
    };

    // Try to read century register
    let state = RTC_STATE.read();
    let year = if state.has_century {
        let century_raw = cmos_read(Register::Century as u8);
        let century = if is_binary { century_raw } else { bcd_to_bin(century_raw) };
        (century as u16) * 100 + (year_2digit as u16)
    } else {
        // Assume 20xx for years < 70, 19xx for 70-99
        if year_2digit < 70 {
            2000 + (year_2digit as u16)
        } else {
            1900 + (year_2digit as u16)
        }
    };

    STATS_READS.fetch_add(1, Ordering::Relaxed);

    Ok(RtcTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        day_of_week,
    })
}

/// Read current RTC time
pub fn read_rtc() -> RtcTime {
    read_rtc_internal().unwrap_or_default()
}

/// Read current RTC time with result
pub fn read_rtc_checked() -> RtcResult<RtcTime> {
    read_rtc_internal()
}

/// Read current time as Unix timestamp
pub fn read_unix_timestamp() -> u64 {
    let time = read_rtc();
    let ts = time.to_unix_timestamp();
    STATS_LAST_TIMESTAMP.store(ts, Ordering::Relaxed);
    ts
}

// ============================================================================
// RTC Writing
// ============================================================================

/// Write RTC time
pub fn write_rtc(time: &RtcTime) -> RtcResult<()> {
    time.validate()?;

    let state = RTC_STATE.read();
    let is_binary = state.binary_mode;
    let is_24_hour = state.hour_24_mode;

    // Inhibit updates
    let status_b = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b | status_b::SET);

    // Convert and write values
    let second = if is_binary { time.second } else { bin_to_bcd(time.second) };
    let minute = if is_binary { time.minute } else { bin_to_bcd(time.minute) };
    let day = if is_binary { time.day } else { bin_to_bcd(time.day) };
    let month = if is_binary { time.month } else { bin_to_bcd(time.month) };
    let year_2digit = (time.year % 100) as u8;
    let year = if is_binary { year_2digit } else { bin_to_bcd(year_2digit) };

    // Handle hours
    let hour = if is_24_hour {
        if is_binary { time.hour } else { bin_to_bcd(time.hour) }
    } else {
        // Convert 24-hour to 12-hour with PM flag
        let (h12, pm) = match time.hour {
            0 => (12, false),      // 00:00 = 12 AM
            1..=11 => (time.hour, false),
            12 => (12, true),      // 12:00 = 12 PM
            13..=23 => (time.hour - 12, true),
            _ => (12, false),
        };
        let h = if is_binary { h12 } else { bin_to_bcd(h12) };
        if pm { h | 0x80 } else { h }
    };

    // Calculate day of week
    let dow = day_of_week(time.year, time.month, time.day);
    let day_of_week = if is_binary { dow } else { bin_to_bcd(dow) };

    // Write time registers
    cmos_write(Register::Seconds as u8, second);
    cmos_write(Register::Minutes as u8, minute);
    cmos_write(Register::Hours as u8, hour);
    cmos_write(Register::DayOfWeek as u8, day_of_week);
    cmos_write(Register::DayOfMonth as u8, day);
    cmos_write(Register::Month as u8, month);
    cmos_write(Register::Year as u8, year);

    // Write century if available
    if state.has_century {
        let century = (time.year / 100) as u8;
        let cent = if is_binary { century } else { bin_to_bcd(century) };
        cmos_write(Register::Century as u8, cent);
    }

    // Resume updates
    cmos_write(Register::StatusB as u8, status_b & !status_b::SET);

    STATS_WRITES.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Set RTC from Unix timestamp
pub fn set_unix_timestamp(timestamp: u64) -> RtcResult<()> {
    let time = RtcTime::from_unix_timestamp(timestamp);
    write_rtc(&time)
}

// ============================================================================
// Alarm Functions
// ============================================================================

/// Set RTC alarm
pub fn set_alarm(alarm: &RtcAlarm) -> RtcResult<()> {
    alarm.validate()?;

    let state = RTC_STATE.read();
    let is_binary = state.binary_mode;

    // Convert alarm values (0xFF means "don't care")
    let second = if alarm.second == 0xFF {
        0xFF
    } else if is_binary {
        alarm.second
    } else {
        bin_to_bcd(alarm.second)
    };

    let minute = if alarm.minute == 0xFF {
        0xFF
    } else if is_binary {
        alarm.minute
    } else {
        bin_to_bcd(alarm.minute)
    };

    let hour = if alarm.hour == 0xFF {
        0xFF
    } else if is_binary {
        alarm.hour
    } else {
        bin_to_bcd(alarm.hour)
    };

    // Write alarm registers
    cmos_write(Register::SecondsAlarm as u8, second);
    cmos_write(Register::MinutesAlarm as u8, minute);
    cmos_write(Register::HoursAlarm as u8, hour);

    Ok(())
}

/// Enable alarm interrupt
pub fn enable_alarm() -> RtcResult<()> {
    let status_b = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b | status_b::AIE);

    let mut state = RTC_STATE.write();
    state.alarm_enabled = true;

    Ok(())
}

/// Disable alarm interrupt
pub fn disable_alarm() {
    let status_b = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b & !status_b::AIE);

    let mut state = RTC_STATE.write();
    state.alarm_enabled = false;
}

/// Check if alarm is enabled
pub fn is_alarm_enabled() -> bool {
    RTC_STATE.read().alarm_enabled
}

// ============================================================================
// Periodic Interrupt Functions
// ============================================================================

/// Set periodic interrupt rate
pub fn set_periodic_rate(rate: PeriodicRate) -> RtcResult<()> {
    let status_a = cmos_read(Register::StatusA as u8);
    let new_status_a = (status_a & !status_a::RATE_MASK) | rate.value();
    cmos_write(Register::StatusA as u8, new_status_a);

    let mut state = RTC_STATE.write();
    state.periodic_rate = rate;

    Ok(())
}

/// Enable periodic interrupt
pub fn enable_periodic() -> RtcResult<()> {
    let status_b = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b | status_b::PIE);

    let mut state = RTC_STATE.write();
    state.periodic_enabled = true;

    Ok(())
}

/// Disable periodic interrupt
pub fn disable_periodic() {
    let status_b = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b & !status_b::PIE);

    let mut state = RTC_STATE.write();
    state.periodic_enabled = false;
}

/// Check if periodic interrupt is enabled
pub fn is_periodic_enabled() -> bool {
    RTC_STATE.read().periodic_enabled
}

/// Get current periodic rate
pub fn get_periodic_rate() -> PeriodicRate {
    RTC_STATE.read().periodic_rate
}

// ============================================================================
// Update Interrupt Functions
// ============================================================================

/// Enable update-ended interrupt (fires every second)
pub fn enable_update_interrupt() -> RtcResult<()> {
    let status_b = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b | status_b::UIE);

    let mut state = RTC_STATE.write();
    state.update_enabled = true;

    Ok(())
}

/// Disable update-ended interrupt
pub fn disable_update_interrupt() {
    let status_b = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b & !status_b::UIE);

    let mut state = RTC_STATE.write();
    state.update_enabled = false;
}

/// Check if update interrupt is enabled
pub fn is_update_interrupt_enabled() -> bool {
    RTC_STATE.read().update_enabled
}

// ============================================================================
// Interrupt Handler
// ============================================================================

/// Handle RTC interrupt (IRQ 8)
/// Returns the interrupt flags that were set
pub fn handle_interrupt() -> u8 {
    // Read status C to clear interrupt flags
    let status_c = cmos_read(Register::StatusC as u8);

    if (status_c & status_c::UF) != 0 {
        STATS_UPDATE_INTS.fetch_add(1, Ordering::Relaxed);
    }

    if (status_c & status_c::AF) != 0 {
        STATS_ALARM_INTS.fetch_add(1, Ordering::Relaxed);
    }

    if (status_c & status_c::PF) != 0 {
        STATS_PERIODIC_INTS.fetch_add(1, Ordering::Relaxed);
    }

    status_c
}

/// Check which interrupt occurred
pub fn check_interrupt_source() -> (bool, bool, bool) {
    let status_c = cmos_read(Register::StatusC as u8);
    (
        (status_c & status_c::UF) != 0,  // Update
        (status_c & status_c::AF) != 0,  // Alarm
        (status_c & status_c::PF) != 0,  // Periodic
    )
}

// ============================================================================
// Battery and Status
// ============================================================================

/// Check if RTC battery is good
pub fn is_battery_good() -> bool {
    (cmos_read(Register::StatusD as u8) & status_d::VRT) != 0
}

/// Check if RTC is updating
pub fn is_updating() -> bool {
    (cmos_read(Register::StatusA as u8) & status_a::UIP) != 0
}

// ============================================================================
// Timezone Support
// ============================================================================

/// Set timezone offset from UTC (in seconds)
pub fn set_timezone_offset(offset_seconds: i32) {
    let mut state = RTC_STATE.write();
    state.timezone_offset = offset_seconds;
}

/// Get timezone offset from UTC (in seconds)
pub fn get_timezone_offset() -> i32 {
    RTC_STATE.read().timezone_offset
}

/// Read RTC time adjusted for timezone
pub fn read_local_time() -> RtcTime {
    let utc = read_rtc();
    let offset = get_timezone_offset();

    if offset == 0 {
        return utc;
    }

    let utc_ts = utc.to_unix_timestamp();
    let local_ts = if offset >= 0 {
        utc_ts + offset as u64
    } else {
        utc_ts.saturating_sub((-offset) as u64)
    };

    RtcTime::from_unix_timestamp(local_ts)
}

// ============================================================================
// CMOS Checksum
// ============================================================================

/// Calculate CMOS checksum (sum of bytes 0x10-0x2D)
pub fn calculate_checksum() -> u16 {
    let mut sum: u16 = 0;
    for addr in 0x10..=0x2D {
        sum = sum.wrapping_add(cmos_read(addr) as u16);
    }
    sum
}

/// Read stored CMOS checksum
pub fn read_checksum() -> u16 {
    let high = cmos_read(Register::ChecksumHigh as u8) as u16;
    let low = cmos_read(Register::ChecksumLow as u8) as u16;
    (high << 8) | low
}

/// Write CMOS checksum
pub fn write_checksum(checksum: u16) {
    cmos_write(Register::ChecksumHigh as u8, (checksum >> 8) as u8);
    cmos_write(Register::ChecksumLow as u8, (checksum & 0xFF) as u8);
}

/// Verify CMOS checksum
pub fn verify_checksum() -> bool {
    calculate_checksum() == read_checksum()
}

/// Update CMOS checksum
pub fn update_checksum() {
    let checksum = calculate_checksum();
    write_checksum(checksum);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize RTC
pub fn init() -> RtcResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(RtcError::AlreadyInitialized);
    }

    // Check battery status
    if !is_battery_good() {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(RtcError::BatteryFailure);
    }

    // Read status register B to determine modes
    let status_b = cmos_read(Register::StatusB as u8);
    let binary_mode = (status_b & status_b::DM) != 0;
    let hour_24_mode = (status_b & status_b::HOUR_24) != 0;

    // Check if century register is available
    let century_raw = cmos_read(Register::Century as u8);
    let century = if binary_mode { century_raw } else { bcd_to_bin(century_raw) };
    let has_century = century >= 19 && century <= 21;

    // Update state
    {
        let mut state = RTC_STATE.write();
        state.binary_mode = binary_mode;
        state.hour_24_mode = hour_24_mode;
        state.has_century = has_century;
    }

    // Clear any pending interrupts
    let _ = cmos_read(Register::StatusC as u8);

    Ok(())
}

/// Check if RTC is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get RTC statistics
pub fn get_statistics() -> RtcStatistics {
    let state = RTC_STATE.read();

    RtcStatistics {
        initialized: INITIALIZED.load(Ordering::Relaxed),
        battery_good: is_battery_good(),
        binary_mode: state.binary_mode,
        hour_24_mode: state.hour_24_mode,
        has_century: state.has_century,
        timezone_offset: state.timezone_offset,
        reads: STATS_READS.load(Ordering::Relaxed),
        writes: STATS_WRITES.load(Ordering::Relaxed),
        alarm_interrupts: STATS_ALARM_INTS.load(Ordering::Relaxed),
        periodic_interrupts: STATS_PERIODIC_INTS.load(Ordering::Relaxed),
        update_interrupts: STATS_UPDATE_INTS.load(Ordering::Relaxed),
        last_timestamp: STATS_LAST_TIMESTAMP.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Legacy API
// ============================================================================

/// Read RTC register (legacy)
fn rtc_read_reg(reg: u8) -> u8 {
    cmos_read(reg)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtc_error_messages() {
        assert_eq!(RtcError::NotInitialized.as_str(), "RTC not initialized");
        assert_eq!(RtcError::InvalidTime.as_str(), "Invalid time value");
        assert_eq!(RtcError::BatteryFailure.as_str(), "RTC battery failure");
    }

    #[test]
    fn test_bcd_conversion() {
        assert_eq!(bcd_to_bin(0x00), 0);
        assert_eq!(bcd_to_bin(0x09), 9);
        assert_eq!(bcd_to_bin(0x10), 10);
        assert_eq!(bcd_to_bin(0x59), 59);
        assert_eq!(bcd_to_bin(0x99), 99);

        assert_eq!(bin_to_bcd(0), 0x00);
        assert_eq!(bin_to_bcd(9), 0x09);
        assert_eq!(bin_to_bcd(10), 0x10);
        assert_eq!(bin_to_bcd(59), 0x59);
        assert_eq!(bin_to_bcd(99), 0x99);
    }

    #[test]
    fn test_leap_year() {
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2004));
        assert!(!is_leap_year(2100));
        assert!(is_leap_year(2024));
    }

    #[test]
    fn test_days_in_month() {
        assert_eq!(days_in_month(2024, 1), 31);
        assert_eq!(days_in_month(2024, 2), 29); // Leap year
        assert_eq!(days_in_month(2023, 2), 28); // Non-leap year
        assert_eq!(days_in_month(2024, 4), 30);
        assert_eq!(days_in_month(2024, 12), 31);
    }

    #[test]
    fn test_day_of_week() {
        // 2024-01-01 was Monday (2)
        assert_eq!(day_of_week(2024, 1, 1), 2);
        // 2024-12-25 is Wednesday (4)
        assert_eq!(day_of_week(2024, 12, 25), 4);
        // 1970-01-01 was Thursday (5)
        assert_eq!(day_of_week(1970, 1, 1), 5);
    }

    #[test]
    fn test_unix_timestamp_conversion() {
        // Unix epoch
        let time = RtcTime::from_unix_timestamp(0);
        assert_eq!(time.year, 1970);
        assert_eq!(time.month, 1);
        assert_eq!(time.day, 1);
        assert_eq!(time.hour, 0);
        assert_eq!(time.minute, 0);
        assert_eq!(time.second, 0);

        // Round-trip test
        let original = RtcTime::new(2024, 6, 15, 12, 30, 45);
        let timestamp = original.to_unix_timestamp();
        let converted = RtcTime::from_unix_timestamp(timestamp);
        assert_eq!(converted.year, original.year);
        assert_eq!(converted.month, original.month);
        assert_eq!(converted.day, original.day);
        assert_eq!(converted.hour, original.hour);
        assert_eq!(converted.minute, original.minute);
        assert_eq!(converted.second, original.second);
    }

    #[test]
    fn test_rtc_time_validation() {
        let valid = RtcTime::new(2024, 6, 15, 12, 30, 45);
        assert!(valid.validate().is_ok());

        let invalid_second = RtcTime::new(2024, 6, 15, 12, 30, 60);
        assert!(invalid_second.validate().is_err());

        let invalid_month = RtcTime::new(2024, 13, 15, 12, 30, 45);
        assert!(invalid_month.validate().is_err());

        let invalid_day = RtcTime::new(2024, 2, 30, 12, 30, 45);
        assert!(invalid_day.validate().is_err());
    }

    #[test]
    fn test_rtc_alarm_validation() {
        let valid = RtcAlarm::new(12, 30, 45);
        assert!(valid.validate().is_ok());

        let wildcard = RtcAlarm::every_second();
        assert!(wildcard.validate().is_ok());

        let invalid = RtcAlarm::new(25, 30, 45);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_periodic_rate() {
        assert_eq!(PeriodicRate::Hz1024.frequency_hz(), 1024);
        assert_eq!(PeriodicRate::Hz2.frequency_hz(), 2);
        assert_eq!(PeriodicRate::Disabled.frequency_hz(), 0);

        assert_eq!(PeriodicRate::Hz1024.period_us(), 976);
        assert_eq!(PeriodicRate::Hz2.period_us(), 500000);
    }

    #[test]
    fn test_day_name() {
        assert_eq!(day_name(1), "Sunday");
        assert_eq!(day_name(2), "Monday");
        assert_eq!(day_name(7), "Saturday");
    }

    #[test]
    fn test_month_name() {
        assert_eq!(month_name(1), "January");
        assert_eq!(month_name(6), "June");
        assert_eq!(month_name(12), "December");
    }

    #[test]
    fn test_format_iso8601() {
        let time = RtcTime::new(2024, 6, 15, 12, 30, 45);
        let formatted = time.format_iso8601();
        assert_eq!(&formatted, b"2024-06-15 12:30:45");
    }

    #[test]
    fn test_day_of_year() {
        let jan1 = RtcTime::new(2024, 1, 1, 0, 0, 0);
        assert_eq!(jan1.day_of_year(), 1);

        let dec31 = RtcTime::new(2024, 12, 31, 0, 0, 0);
        assert_eq!(dec31.day_of_year(), 366); // Leap year
    }

    #[test]
    fn test_register_values() {
        assert_eq!(Register::Seconds as u8, 0x00);
        assert_eq!(Register::StatusA as u8, 0x0A);
        assert_eq!(Register::StatusB as u8, 0x0B);
        assert_eq!(Register::Century as u8, 0x32);
    }

    #[test]
    fn test_statistics_default() {
        let stats = RtcStatistics::default();
        assert!(!stats.initialized);
        assert_eq!(stats.reads, 0);
        assert_eq!(stats.writes, 0);
    }
}
