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

use super::timer;

pub fn now_ns() -> u64 {
    timer::now_ns()
}
pub fn current_uptime() -> u64 {
    now_ns() / 1_000_000_000
}
pub fn get_uptime_ns() -> u64 {
    now_ns()
}
pub fn timestamp_millis() -> u64 {
    now_ns() / 1_000_000
}
pub fn timestamp_nanos() -> u64 {
    now_ns()
}
pub fn get_timestamp() -> u64 {
    timestamp_millis()
}
pub fn get_kernel_time_ns() -> u64 {
    now_ns()
}
pub fn current_ticks() -> u64 {
    now_ns() / 1_000_000
}
pub fn current_time_ns() -> u64 {
    now_ns()
}

pub fn yield_now() {
    unsafe {
        x86_64::instructions::hlt();
    }
}

pub fn current_timestamp() -> u64 {
    let base_ns = now_ns();
    let boot_time_estimate = 1640995200000u64;
    let uptime_ms = base_ns / 1_000_000;
    boot_time_estimate + uptime_ms
}

pub fn is_off_hours() -> bool {
    let current_ms = current_timestamp();
    let seconds_since_unix = current_ms / 1000;
    let day_offset = seconds_since_unix % 86400;
    let hours = day_offset / 3600;
    hours < 6 || hours >= 22
}

pub fn init() {
    timer::init();
}
pub fn is_initialized() -> bool {
    timer::is_initialized()
}
pub fn sleep_long_ns<F: Fn()>(ns: u64, callback: F) {
    timer::sleep_long_ns(ns, callback);
}
pub fn handle_rtc_interrupt() {
    super::rtc::handle_interrupt();
}
