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

use super::super::types::MmioStatsSnapshot;
use super::types::MmioStats;
use core::sync::atomic::Ordering;

impl MmioStats {
    #[inline]
    pub fn total_regions(&self) -> usize {
        self.total_regions.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn total_mapped_size(&self) -> u64 {
        self.total_mapped_size.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn read_operations(&self) -> u64 {
        self.read_operations.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn write_operations(&self) -> u64 {
        self.write_operations.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> MmioStatsSnapshot {
        MmioStatsSnapshot {
            total_regions: self.total_regions(),
            total_mapped_size: self.total_mapped_size(),
            read_operations: self.read_operations(),
            write_operations: self.write_operations(),
        }
    }
}
