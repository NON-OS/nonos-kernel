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

mod alarm;
pub mod bcd;
pub mod calendar;
mod checksum;
pub mod cmos;
pub mod constants;
pub mod conversion;
mod error;
mod interrupt;
mod ops;
mod periodic;
mod read;
pub mod state;
mod types;
mod unix;
mod write;

pub use alarm::{disable_alarm, enable_alarm, is_alarm_enabled, set_alarm};
pub use bcd::is_valid_bcd;
pub use calendar::day_of_year;
pub use checksum::{
    calculate_checksum, read_checksum, update_checksum, verify_checksum, write_checksum,
};
pub use cmos::{
    cmos_read, cmos_write, inb, outb, read_cmos, read_register, write_cmos, write_register,
};
pub use constants::Register;
pub use conversion::{
    bcd_to_bin, bin_to_bcd, datetime_to_unix, day_name, day_of_week, days_in_month, is_leap_year,
    month_name, unix_to_datetime,
};
pub use error::{RtcError, RtcResult};
pub use interrupt::{
    check_interrupt_source, disable_update_interrupt, enable_update_interrupt, handle_interrupt,
    is_update_interrupt_enabled,
};
pub use ops::{
    read_local_time, read_rtc, read_rtc_checked, read_rtc_time, read_unix_timestamp,
    set_unix_timestamp, write_rtc,
};
pub use periodic::{
    disable_periodic, enable_periodic, get_periodic_rate, is_periodic_enabled, set_periodic_rate,
};
pub use state::{
    get_statistics, get_timezone_offset, init, is_battery_good, is_initialized, is_updating,
    set_timezone_offset, RtcState, INITIALIZED, RTC_STATE, STATS_ALARM_INTS, STATS_LAST_TIMESTAMP,
    STATS_PERIODIC_INTS, STATS_READS, STATS_UPDATE_INTS, STATS_WRITES,
};
pub use types::{PeriodicRate, RtcAlarm, RtcStatistics, RtcTime};
