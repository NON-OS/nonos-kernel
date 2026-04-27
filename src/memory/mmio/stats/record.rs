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

use super::types::MmioStats;
use core::sync::atomic::Ordering;

impl MmioStats {
    pub fn next_id(&self) -> u64 {
        self.next_region_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn record_mapping(&self, size: usize) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn record_unmapping(&self, size: usize) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_sub(size as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_read(&self) {
        self.read_operations.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_write(&self) {
        self.write_operations.fetch_add(1, Ordering::Relaxed);
    }
}
