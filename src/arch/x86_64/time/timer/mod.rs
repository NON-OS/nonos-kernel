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

mod hpet;
mod hrtimer;
mod init;
mod sleep;
mod state;
mod stats;
mod time;
mod tsc;

pub use hpet::{get_hpet_counter, hpet_to_ns, is_valid_hpet_base};
pub use hrtimer::{cancel_timer, get_active_timer_count, hrtimer_after_ns, tick};
pub use init::{init, init_boot_time, init_with_freq};
pub use sleep::{busy_sleep_ns, delay_ms, delay_precise_ns, delay_us, sleep_long_ns};
pub use state::BOOT_TIME;
pub use stats::{get_timer_stats, TimerStats};
pub use time::{
    get_timestamp_ms, is_deadline_mode, is_initialized, now_ms, now_ns, now_ns_checked,
};
pub use tsc::{get_tsc_frequency, ns_to_tsc, rdtscp, tsc_to_ns};
