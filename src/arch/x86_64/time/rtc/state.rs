// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;
use super::constants::{Register, status_a, status_b, status_d};
use super::error::{RtcError, RtcResult};
use super::types::{PeriodicRate, RtcStatistics};
use super::cmos::cmos_read;
use super::conversion::bcd_to_bin;

pub struct RtcState {
    pub binary_mode: bool,
    pub hour_24_mode: bool,
    pub has_century: bool,
    pub timezone_offset: i32,
    pub alarm_enabled: bool,
    pub periodic_enabled: bool,
    pub update_enabled: bool,
    pub periodic_rate: PeriodicRate,
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

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub static RTC_STATE: RwLock<RtcState> = RwLock::new(RtcState {
    binary_mode: false,
    hour_24_mode: true,
    has_century: false,
    timezone_offset: 0,
    alarm_enabled: false,
    periodic_enabled: false,
    update_enabled: false,
    periodic_rate: PeriodicRate::Disabled,
});

pub static STATS_READS: AtomicU64 = AtomicU64::new(0);
pub static STATS_WRITES: AtomicU64 = AtomicU64::new(0);
pub static STATS_ALARM_INTS: AtomicU64 = AtomicU64::new(0);
pub static STATS_PERIODIC_INTS: AtomicU64 = AtomicU64::new(0);
pub static STATS_UPDATE_INTS: AtomicU64 = AtomicU64::new(0);
pub static STATS_LAST_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

pub fn is_battery_good() -> bool {
    (cmos_read(Register::StatusD as u8) & status_d::VRT) != 0
}

pub fn is_updating() -> bool {
    (cmos_read(Register::StatusA as u8) & status_a::UIP) != 0
}

pub fn set_timezone_offset(offset_seconds: i32) {
    let mut state = RTC_STATE.write();
    state.timezone_offset = offset_seconds;
}

pub fn get_timezone_offset() -> i32 {
    RTC_STATE.read().timezone_offset
}

pub fn init() -> RtcResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(RtcError::AlreadyInitialized);
    }

    if !is_battery_good() {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(RtcError::BatteryFailure);
    }

    let status_b_val = cmos_read(Register::StatusB as u8);
    let binary_mode = (status_b_val & status_b::DM) != 0;
    let hour_24_mode = (status_b_val & status_b::HOUR_24) != 0;

    let century_raw = cmos_read(Register::Century as u8);
    let century = if binary_mode { century_raw } else { bcd_to_bin(century_raw) };
    let has_century = century >= 19 && century <= 21;

    {
        let mut state = RTC_STATE.write();
        state.binary_mode = binary_mode;
        state.hour_24_mode = hour_24_mode;
        state.has_century = has_century;
    }

    let _ = cmos_read(Register::StatusC as u8);

    Ok(())
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

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
