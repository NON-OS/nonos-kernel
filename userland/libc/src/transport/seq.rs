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

//! Per-capsule monotonic request-id counter. Each capsule owns one
//! `Counter` and threads it through every `round_trip` so an outbound
//! request can be matched against the right response. Zero is
//! reserved for "no request in flight" by convention; the counter
//! skips it on rollover.

use core::sync::atomic::{AtomicU32, Ordering};

pub struct Counter {
    next: AtomicU32,
}

impl Counter {
    pub const fn new() -> Self {
        Self { next: AtomicU32::new(1) }
    }

    pub fn fetch(&self) -> u32 {
        let v = self.next.fetch_add(1, Ordering::Relaxed);
        if v == 0 {
            self.next.fetch_add(1, Ordering::Relaxed)
        } else {
            v
        }
    }
}
