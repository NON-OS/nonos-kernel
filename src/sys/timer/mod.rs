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

mod tsc;
mod uptime;
mod delay;
mod stopwatch;
mod callback;
mod util;

pub use tsc::{rdtsc, init, init_default, tsc_frequency, ticks_to_ns, ticks_to_us, ticks_to_ms, us_to_ticks, ms_to_ticks};
pub use uptime::{uptime_ms, uptime_us, uptime_seconds, unix_timestamp_ms, unix_timestamp};
pub use delay::{delay_us, delay_ms, short_delay};
pub use stopwatch::Stopwatch;
pub use callback::{TimerCallback, register_callback, unregister_callback, process_callbacks};
pub use util::{is_init, stats, format_uptime};
