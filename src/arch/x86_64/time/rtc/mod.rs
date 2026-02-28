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

pub mod alarm;
pub mod checksum;
pub mod cmos;
pub mod constants;
pub mod conversion;
pub mod error;
pub mod interrupt;
pub mod ops;
pub mod periodic;
pub mod state;
pub mod types;

pub use constants::Register;
pub use error::{RtcError, RtcResult};
pub use types::{RtcTime, RtcAlarm, PeriodicRate, RtcStatistics};

pub use cmos::{read_register, write_register, read_cmos, write_cmos};
pub use conversion::{is_leap_year, days_in_month, day_of_week, day_name, month_name, datetime_to_unix, unix_to_datetime};
pub use ops::{read_rtc, read_rtc_checked, read_unix_timestamp, write_rtc, set_unix_timestamp, read_local_time, read_rtc_time};
pub use alarm::{set_alarm, enable_alarm, disable_alarm, is_alarm_enabled};
pub use periodic::{set_periodic_rate, enable_periodic, disable_periodic, is_periodic_enabled, get_periodic_rate};
pub use interrupt::{enable_update_interrupt, disable_update_interrupt, is_update_interrupt_enabled, handle_interrupt, check_interrupt_source};
pub use checksum::{calculate_checksum, read_checksum, write_checksum, verify_checksum, update_checksum};
pub use state::{init, is_initialized, get_statistics, is_battery_good, is_updating, set_timezone_offset, get_timezone_offset};
