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

use super::state::{BOOT_TIME, TSC_FREQUENCY, TIMER_INITIALIZED};
use super::tsc::rdtsc;

pub fn now_ns() -> u64 {
    if !TIMER_INITIALIZED.load(Ordering::Relaxed) {
        return 0;
    }
    let current_tsc = rdtsc();
    let boot_tsc = BOOT_TIME.load(Ordering::Relaxed);
    let tsc_freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if tsc_freq == 0 {
        return 0;
    }
    let tsc_diff = current_tsc.saturating_sub(boot_tsc);
    (tsc_diff * 1_000_000_000) / tsc_freq
}

pub fn is_initialized() -> bool {
    TIMER_INITIALIZED.load(Ordering::Relaxed)
}

pub fn now_ns_checked() -> Option<u64> {
    if is_initialized() {
        Some(now_ns())
    } else {
        None
    }
}

pub fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

pub fn is_deadline_mode() -> bool {
    false
}

pub fn get_timestamp_ms() -> Option<u64> {
    now_ns_checked().map(|ns| ns / 1_000_000)
}
