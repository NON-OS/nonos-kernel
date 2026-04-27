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

use super::state::PagingStatistics;
use crate::memory::paging::types::PagingStats;
use core::sync::atomic::Ordering;

impl PagingStatistics {
    pub fn snapshot(&self, mappings_count: usize, address_spaces_count: usize) -> PagingStats {
        PagingStats {
            total_mappings: mappings_count,
            address_spaces: address_spaces_count,
            page_faults: self.page_faults.load(Ordering::Relaxed),
            tlb_flushes: self.tlb_flushes.load(Ordering::Relaxed),
            cow_faults: self.cow_faults.load(Ordering::Relaxed),
            demand_loads: self.demand_loads.load(Ordering::Relaxed),
            huge_pages: self.huge_pages.load(Ordering::Relaxed),
            user_pages: self.user_pages.load(Ordering::Relaxed),
            kernel_pages: self.kernel_pages.load(Ordering::Relaxed),
            page_modifications: self.page_modifications.load(Ordering::Relaxed),
        }
    }

    pub fn total_mappings(&self) -> usize {
        self.total_mappings.load(Ordering::Relaxed)
    }
    pub fn page_faults(&self) -> u64 {
        self.page_faults.load(Ordering::Relaxed)
    }
    pub fn tlb_flushes(&self) -> u64 {
        self.tlb_flushes.load(Ordering::Relaxed)
    }
}
