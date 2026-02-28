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
use super::super::state::{PANIC_MODE, VGA_LOCK};

pub fn acquire_lock() -> bool {
    if PANIC_MODE.load(Ordering::Relaxed) {
        return true;
    }

    let mut attempts = 0;
    while VGA_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        attempts += 1;
        if attempts > 1000 {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

pub fn release_lock() {
    if !PANIC_MODE.load(Ordering::Relaxed) {
        VGA_LOCK.store(false, Ordering::Release);
    }
}
