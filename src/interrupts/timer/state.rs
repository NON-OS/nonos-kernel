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

use core::sync::atomic::{AtomicU64, Ordering};

pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

#[inline]
pub fn increment_ticks() {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn reset_ticks() {
    TICK_COUNT.store(0, Ordering::Relaxed);
}
