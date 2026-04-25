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

pub use super::api_init::{
    get_all_stats, init, init_with_hpet, rdtsc, rdtscp, read_rtc, read_rtc_checked, tsc_now,
    unix_timestamp,
};
pub use super::api_time::{
    current_ticks, current_time_ns, delay_ms, delay_ns, delay_us, get_kernel_time_ns,
    is_initialized, now_ns, sleep_ms, sleep_us, timestamp_micros, timestamp_millis, timestamp_secs,
    uptime_nanos, yield_now,
};

#[inline]
pub fn monotonic_ns() -> u64 {
    now_ns()
}
