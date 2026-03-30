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

use core::sync::atomic::{AtomicU64, AtomicUsize};

pub struct AllocationStatistics {
    pub(super) total_allocated: AtomicU64,
    pub(super) peak_allocated: AtomicU64,
    pub(super) allocation_count: AtomicUsize,
    pub(super) free_count: AtomicUsize,
}

impl AllocationStatistics {
    pub const fn new() -> Self {
        Self {
            total_allocated: AtomicU64::new(0),
            peak_allocated: AtomicU64::new(0),
            allocation_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
        }
    }
}
