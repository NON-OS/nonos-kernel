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

pub fn sys_time_millis() -> i64 {
    if !clock_ready() {
        return -61;
    }
    let now = crate::sys::clock::unix_ms();
    now.min(i64::MAX as u64) as i64
}

fn clock_ready() -> bool {
    crate::sys::clock::TSC_HZ.load(Ordering::Relaxed) != 0
        && crate::sys::clock::BOOT_UNIX_MS.load(Ordering::Relaxed) != 0
}
