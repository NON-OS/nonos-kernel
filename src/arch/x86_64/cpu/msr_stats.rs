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

static MSR_READS: AtomicU64 = AtomicU64::new(0);
static MSR_WRITES: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn increment_reads() {
    MSR_READS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_writes() {
    MSR_WRITES.fetch_add(1, Ordering::Relaxed);
}

pub fn msr_reads() -> u64 {
    MSR_READS.load(Ordering::Relaxed)
}

pub fn msr_writes() -> u64 {
    MSR_WRITES.load(Ordering::Relaxed)
}
