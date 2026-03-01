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

use super::types::{FutexStats, FUTEX_WAITS, FUTEX_WAKES, FUTEX_TIMEOUTS, FUTEX_WAITER_MAP, PI_OWNERS, ROBUST_LISTS};

pub fn get_futex_stats() -> FutexStats {
    FutexStats {
        total_waits: FUTEX_WAITS.load(Ordering::Relaxed),
        total_wakes: FUTEX_WAKES.load(Ordering::Relaxed),
        total_timeouts: FUTEX_TIMEOUTS.load(Ordering::Relaxed),
        active_waiters: FUTEX_WAITER_MAP.lock().values().map(|v| v.len()).sum(),
        active_pi_locks: PI_OWNERS.lock().len(),
        robust_lists_registered: ROBUST_LISTS.lock().len(),
    }
}
