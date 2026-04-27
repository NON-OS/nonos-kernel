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

static USED_BYTES: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn init(total: u64) {
    TOTAL_BYTES.store(total, Ordering::SeqCst);
}

pub fn add_used(bytes: u64) {
    USED_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn sub_used(bytes: u64) {
    USED_BYTES.fetch_sub(bytes, Ordering::Relaxed);
}

pub fn used_bytes() -> u64 {
    USED_BYTES.load(Ordering::Relaxed)
}

pub fn total_bytes() -> u64 {
    TOTAL_BYTES.load(Ordering::Relaxed)
}

pub fn used_mb() -> u64 {
    used_bytes() / (1024 * 1024)
}

pub fn total_mb() -> u64 {
    total_bytes() / (1024 * 1024)
}

pub fn free_mb() -> u64 {
    total_mb().saturating_sub(used_mb())
}

pub fn usage_percent() -> u8 {
    let total = total_bytes();
    if total == 0 {
        return 0;
    }
    ((used_bytes() * 100) / total) as u8
}
