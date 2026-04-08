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

use super::timer as nonos_timer;

#[inline(always)]
pub fn now_ns() -> u64 { nonos_timer::now_ns() }

#[inline(always)]
pub fn is_initialized() -> bool { nonos_timer::is_initialized() }

#[inline(always)]
pub fn delay_ns(ns: u64) { nonos_timer::delay_precise_ns(ns); }

#[inline(always)]
pub fn delay_us(us: u64) { nonos_timer::delay_us(us); }

#[inline(always)]
pub fn delay_ms(ms: u64) { nonos_timer::delay_ms(ms); }

#[inline(always)]
pub fn timestamp_millis() -> u64 { now_ns() / 1_000_000 }

#[inline(always)]
pub fn timestamp_micros() -> u64 { now_ns() / 1_000 }

#[inline(always)]
pub fn uptime_nanos() -> u64 { now_ns() }

#[inline(always)]
pub fn timestamp_secs() -> u64 { now_ns() / 1_000_000_000 }

#[inline(always)]
pub fn current_time_ns() -> u64 { now_ns() }

#[inline(always)]
pub fn get_kernel_time_ns() -> u64 { now_ns() }

#[inline(always)]
pub fn current_ticks() -> u64 { timestamp_millis() }

#[inline(always)]
pub fn sleep_ms(ms: u64) { delay_ms(ms); }

#[inline(always)]
pub fn sleep_us(us: u64) { delay_us(us); }

#[inline(always)]
pub fn yield_now() {
    x86_64::instructions::interrupts::enable();
    for _ in 0..20 { core::hint::spin_loop(); }
    x86_64::instructions::interrupts::disable();
}
