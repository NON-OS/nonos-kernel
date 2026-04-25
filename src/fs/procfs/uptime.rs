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

extern crate alloc;

use alloc::format;
use alloc::string::String;

pub fn read_uptime() -> String {
    let uptime_ns = crate::sys::clock::uptime_ns();
    let uptime_secs = uptime_ns / 1_000_000_000;
    let uptime_frac = (uptime_ns % 1_000_000_000) / 10_000_000;
    let idle_ns = get_total_idle_time();
    let idle_secs = idle_ns / 1_000_000_000;
    let idle_frac = (idle_ns % 1_000_000_000) / 10_000_000;
    format!("{}.{:02} {}.{:02}\n", uptime_secs, uptime_frac, idle_secs, idle_frac)
}

fn get_total_idle_time() -> u64 {
    let num_cpus = crate::smp::cpu_count() as u64;
    let stats = crate::sched::get_cpu_stats();
    stats.total_idle_ns() * num_cpus
}

pub fn get_uptime_seconds() -> u64 {
    crate::sys::clock::uptime_ns() / 1_000_000_000
}

pub fn get_uptime_jiffies() -> u64 {
    crate::sys::clock::uptime_ns() / 10_000_000
}
