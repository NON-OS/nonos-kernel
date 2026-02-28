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

mod state;
mod time;
mod init;
mod hpet;
mod sleep;
mod hrtimer;
mod tsc;
mod stats;

pub use time::{now_ns, is_initialized, now_ns_checked, now_ms, is_deadline_mode, get_timestamp_ms};
pub use init::{init, init_with_freq};
pub use hpet::{is_valid_hpet_base, get_hpet_counter, hpet_to_ns};
pub use sleep::{sleep_long_ns, busy_sleep_ns, delay_precise_ns, delay_us, delay_ms};
pub use hrtimer::{hrtimer_after_ns, cancel_timer, get_active_timer_count, tick};
pub use tsc::{rdtscp, get_tsc_frequency, tsc_to_ns, ns_to_tsc};
pub use stats::{TimerStats, get_timer_stats};
