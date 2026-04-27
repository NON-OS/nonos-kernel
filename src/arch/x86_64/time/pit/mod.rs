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

mod access;
mod calibrate;
mod channel;
mod channel_state;
mod command;
mod constants;
mod conversion;
mod error;
mod init;
mod io;
mod mode;
mod oneshot;
mod ports;
mod query;
mod sleep;
mod speaker;
mod state;
mod stats;
mod system_control;
mod timer;
mod types;

pub use calibrate::{calibrate_tsc, calibrate_tsc_accurate, calibrate_tsc_with_duration};
pub use constants::{
    DEFAULT_FREQUENCY, MAX_DIVISOR, MAX_TIMER_FREQUENCY, MIN_DIVISOR, MIN_TIMER_FREQUENCY,
    PIT_FREQUENCY,
};
pub use conversion::{
    divisor_to_frequency, divisor_to_period_ns, frequency_error, frequency_to_divisor,
    period_us_to_divisor,
};
pub use init::{init, init_pit, init_with_frequency, is_initialized, reset};
pub use oneshot::{oneshot_delay_us, start_oneshot, wait_oneshot};
pub use query::{
    find_best_divisor, get_channel_config, get_statistics, is_output_high, max_frequency,
    min_frequency, oscillator_frequency, read_count, read_status,
};
pub use sleep::{pit_sleep, pit_sleep_ms, pit_sleep_ticks, pit_sleep_us};
pub use speaker::{beep, start_tone, stop_tone};
pub use timer::{
    elapsed_ms, elapsed_ns, get_system_timer_frequency, get_system_timer_ticks, init_system_timer,
    init_system_timer_with_divisor, system_timer_tick,
};
pub use types::{AccessMode, Channel, Mode, PitError, PitResult, PitStatistics};
