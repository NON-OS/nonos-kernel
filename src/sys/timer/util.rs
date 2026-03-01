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

use core::sync::atomic::Ordering;
use super::tsc::{TIMER_INIT, TSC_FREQ_HZ};
use super::uptime::uptime_seconds;
use super::callback::CALLBACK_COUNT;
use super::uptime::uptime_ms;

pub fn is_init() -> bool {
    TIMER_INIT.load(Ordering::Relaxed)
}

pub fn stats() -> (u64, u64, u64) {
    (
        TSC_FREQ_HZ.load(Ordering::Relaxed),
        uptime_ms(),
        CALLBACK_COUNT.load(Ordering::Relaxed),
    )
}

pub fn format_uptime(buf: &mut [u8; 8]) {
    let total_seconds = uptime_seconds();
    let hours = (total_seconds / 3600) % 100;
    let minutes = (total_seconds / 60) % 60;
    let seconds = total_seconds % 60;

    buf[0] = b'0' + (hours / 10) as u8;
    buf[1] = b'0' + (hours % 10) as u8;
    buf[2] = b':';
    buf[3] = b'0' + (minutes / 10) as u8;
    buf[4] = b'0' + (minutes % 10) as u8;
    buf[5] = b':';
    buf[6] = b'0' + (seconds / 10) as u8;
    buf[7] = b'0' + (seconds % 10) as u8;
}
