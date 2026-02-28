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

use super::{timer as nonos_timer, tsc, rtc, pit, hpet};
use super::{RtcTime, RtcError, TscStatistics, PitStatistics, RtcStatistics, TimerStats};

#[inline]
pub fn now_ns() -> u64 {
    nonos_timer::now_ns()
}

#[inline]
pub fn is_initialized() -> bool {
    nonos_timer::is_initialized()
}

#[inline]
pub fn delay_ns(ns: u64) {
    nonos_timer::delay_precise_ns(ns);
}

#[inline]
pub fn delay_us(us: u64) {
    nonos_timer::delay_us(us);
}

#[inline]
pub fn delay_ms(ms: u64) {
    nonos_timer::delay_ms(ms);
}

#[inline]
pub fn rdtsc() -> u64 {
    tsc::rdtsc()
}

#[inline]
pub fn tsc_now() -> u64 {
    tsc::rdtsc()
}

#[inline]
pub fn rdtscp() -> (u64, u32) {
    tsc::rdtscp()
}

#[inline]
pub fn read_rtc() -> RtcTime {
    rtc::read_rtc()
}

#[inline]
pub fn read_rtc_checked() -> Result<RtcTime, RtcError> {
    rtc::read_rtc_checked()
}

#[inline]
pub fn unix_timestamp() -> u64 {
    rtc::read_unix_timestamp()
}

pub fn init() {
    let _ = tsc::init();
    let _ = pit::init();
    let _ = rtc::init();
    nonos_timer::init();
}

pub fn init_with_hpet(hpet_base: u64) {
    let _ = tsc::init();
    let _ = pit::init();

    if hpet_base != 0 {
        if let Some(base) = hpet::detect_hpet() {
            crate::log::info!("HPET detected at {:#x}", base);
        }
    }

    let _ = rtc::init();
    nonos_timer::init();
}

pub fn get_all_stats() -> (TscStatistics, PitStatistics, RtcStatistics, TimerStats) {
    (
        tsc::get_statistics(),
        pit::get_statistics(),
        rtc::get_statistics(),
        nonos_timer::get_timer_stats(),
    )
}

#[inline]
pub fn timestamp_millis() -> u64 {
    now_ns() / 1_000_000
}

#[inline]
pub fn timestamp_micros() -> u64 {
    now_ns() / 1_000
}

#[inline]
pub fn uptime_nanos() -> u64 {
    now_ns()
}

#[inline]
pub fn timestamp_secs() -> u64 {
    now_ns() / 1_000_000_000
}

#[inline]
pub fn current_time_ns() -> u64 {
    now_ns()
}

#[inline]
pub fn get_kernel_time_ns() -> u64 {
    now_ns()
}

#[inline]
pub fn current_ticks() -> u64 {
    timestamp_millis()
}

#[inline]
pub fn sleep_ms(ms: u64) {
    delay_ms(ms);
}

#[inline]
pub fn sleep_us(us: u64) {
    delay_us(us);
}

#[inline]
pub fn yield_now() {
    // Enable interrupts briefly
    x86_64::instructions::interrupts::enable();
    for _ in 0..20 { core::hint::spin_loop(); }
    x86_64::instructions::interrupts::disable();
}
