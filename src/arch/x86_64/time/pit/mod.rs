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

mod constants;
mod ports;
mod command;
mod system_control;
mod types;
mod state;
mod io;
mod conversion;
mod timer;
mod speaker;
mod oneshot;
mod calibrate;
mod sleep;
mod init;
mod query;

pub use constants::{PIT_FREQUENCY, MAX_DIVISOR, MIN_DIVISOR, MAX_TIMER_FREQUENCY, MIN_TIMER_FREQUENCY, DEFAULT_FREQUENCY};
pub use types::{PitError, PitResult, Channel, Mode, AccessMode, PitStatistics};
pub use conversion::{frequency_to_divisor, divisor_to_frequency, period_us_to_divisor, divisor_to_period_ns, frequency_error};
pub use timer::{init_system_timer, init_system_timer_with_divisor, system_timer_tick, get_system_timer_ticks, get_system_timer_frequency, elapsed_ns, elapsed_ms};
pub use speaker::{beep, start_tone, stop_tone};
pub use oneshot::{start_oneshot, wait_oneshot, oneshot_delay_us};
pub use calibrate::{calibrate_tsc, calibrate_tsc_with_duration, calibrate_tsc_accurate};
pub use sleep::{pit_sleep_ticks, pit_sleep_ms, pit_sleep_us, pit_sleep};
pub use init::{init, init_with_frequency, init_pit, is_initialized, reset};
pub use query::{get_channel_config, read_count, read_status, is_output_high, get_statistics, find_best_divisor, max_frequency, min_frequency, oscillator_frequency};
