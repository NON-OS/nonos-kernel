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
use super::tsc::{rdtsc, ticks_to_ms, ticks_to_us, BOOT_TSC, BOOT_EPOCH_MS};

pub fn uptime_ms() -> u64 {
    let boot_tsc = BOOT_TSC.load(Ordering::Relaxed);
    let current_tsc = rdtsc();
    let elapsed_ticks = current_tsc.saturating_sub(boot_tsc);
    ticks_to_ms(elapsed_ticks)
}

pub fn uptime_us() -> u64 {
    let boot_tsc = BOOT_TSC.load(Ordering::Relaxed);
    let current_tsc = rdtsc();
    let elapsed_ticks = current_tsc.saturating_sub(boot_tsc);
    ticks_to_us(elapsed_ticks)
}

pub fn uptime_seconds() -> u64 {
    uptime_ms() / 1000
}

pub fn unix_timestamp_ms() -> u64 {
    let boot_epoch = BOOT_EPOCH_MS.load(Ordering::Relaxed);
    if boot_epoch == 0 {
        return 0;
    }
    boot_epoch + uptime_ms()
}

pub fn unix_timestamp() -> u64 {
    unix_timestamp_ms() / 1000
}
