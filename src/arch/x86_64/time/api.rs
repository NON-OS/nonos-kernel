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

pub use super::api_time::{now_ns, is_initialized, delay_ns, delay_us, delay_ms, timestamp_millis, timestamp_micros, uptime_nanos, timestamp_secs, current_time_ns, get_kernel_time_ns, current_ticks, sleep_ms, sleep_us, yield_now};
pub use super::api_init::{rdtsc, tsc_now, rdtscp, read_rtc, read_rtc_checked, unix_timestamp, init, init_with_hpet, get_all_stats};

#[inline]
pub fn monotonic_ns() -> u64 { now_ns() }
