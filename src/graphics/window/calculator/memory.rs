// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};

static MEMORY_VALUE: AtomicI64 = AtomicI64::new(0);
static MEMORY_SET: AtomicBool = AtomicBool::new(false);

pub fn memory_clear() {
    MEMORY_VALUE.store(0, Ordering::Relaxed);
    MEMORY_SET.store(false, Ordering::Relaxed);
}

pub fn memory_recall() -> i64 {
    MEMORY_VALUE.load(Ordering::Relaxed)
}

pub fn memory_store(value: i64) {
    MEMORY_VALUE.store(value, Ordering::Relaxed);
    MEMORY_SET.store(true, Ordering::Relaxed);
}

pub fn memory_add(value: i64) {
    let current = MEMORY_VALUE.load(Ordering::Relaxed);
    MEMORY_VALUE.store(current.saturating_add(value), Ordering::Relaxed);
    MEMORY_SET.store(true, Ordering::Relaxed);
}

pub fn memory_subtract(value: i64) {
    let current = MEMORY_VALUE.load(Ordering::Relaxed);
    MEMORY_VALUE.store(current.saturating_sub(value), Ordering::Relaxed);
    MEMORY_SET.store(true, Ordering::Relaxed);
}

pub fn has_memory() -> bool {
    MEMORY_SET.load(Ordering::Relaxed)
}
pub fn get_memory() -> i64 {
    MEMORY_VALUE.load(Ordering::Relaxed)
}
