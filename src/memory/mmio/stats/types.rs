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

pub struct MmioStats {
    pub(super) total_regions: AtomicUsize,
    pub(super) total_mapped_size: AtomicU64,
    pub(super) read_operations: AtomicU64,
    pub(super) write_operations: AtomicU64,
    pub(super) next_region_id: AtomicU64,
}

impl MmioStats {
    pub const fn new() -> Self {
        Self {
            total_regions: AtomicUsize::new(0),
            total_mapped_size: AtomicU64::new(0),
            read_operations: AtomicU64::new(0),
            write_operations: AtomicU64::new(0),
            next_region_id: AtomicU64::new(1),
        }
    }
}
