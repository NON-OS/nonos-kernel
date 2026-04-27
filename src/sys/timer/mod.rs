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

pub mod callback;
pub mod delay;
pub mod stopwatch;
pub mod tsc;
pub mod uptime;
pub mod util;

pub use callback::{process_callbacks, register_callback, unregister_callback, TimerCallback};
pub use delay::{delay_ms, delay_us, short_delay};
pub use stopwatch::Stopwatch;
pub use tsc::{
    init, init_default, ms_to_ticks, rdtsc, ticks_to_ms, ticks_to_ns, ticks_to_us, tsc_frequency,
    us_to_ticks,
};
pub use uptime::{unix_timestamp, unix_timestamp_ms, uptime_ms, uptime_seconds, uptime_us};
pub use util::{format_uptime, is_init, stats};
