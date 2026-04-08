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

#[inline(always)]
pub fn rdtsc() -> u64 { tsc::rdtsc() }

#[inline(always)]
pub fn tsc_now() -> u64 { tsc::rdtsc() }

#[inline(always)]
pub fn rdtscp() -> (u64, u32) { tsc::rdtscp() }

#[inline(always)]
pub fn read_rtc() -> RtcTime { rtc::read_rtc() }

#[inline(always)]
pub fn read_rtc_checked() -> Result<RtcTime, RtcError> { rtc::read_rtc_checked() }

#[inline(always)]
pub fn unix_timestamp() -> u64 { rtc::read_unix_timestamp() }

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
        if let Some(_) = hpet::detect_hpet() { crate::log::info!("HPET detected and initialized"); }
    }
    let _ = rtc::init();
    nonos_timer::init();
}

pub fn get_all_stats() -> (TscStatistics, PitStatistics, RtcStatistics, TimerStats) {
    (tsc::get_statistics(), pit::get_statistics(), rtc::get_statistics(), nonos_timer::get_timer_stats())
}
