// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use super::types::{PagePermissions, PageSize, PagingStats};
pub struct PagingStatistics {
    pub(crate) total_mappings: AtomicUsize,
    pub(crate) page_faults: AtomicU64,
    pub(crate) tlb_flushes: AtomicU64,
    pub(crate) cow_faults: AtomicU64,
    pub(crate) demand_loads: AtomicU64,
    pub(crate) huge_pages: AtomicUsize,
    pub(crate) user_pages: AtomicUsize,
    pub(crate) kernel_pages: AtomicUsize,
    pub(crate) page_modifications: AtomicU64,
}

impl PagingStatistics {
    pub const fn new() -> Self {
        Self {
            total_mappings: AtomicUsize::new(0),
            page_faults: AtomicU64::new(0),
            tlb_flushes: AtomicU64::new(0),
            cow_faults: AtomicU64::new(0),
            demand_loads: AtomicU64::new(0),
            huge_pages: AtomicUsize::new(0),
            user_pages: AtomicUsize::new(0),
            kernel_pages: AtomicUsize::new(0),
            page_modifications: AtomicU64::new(0),
        }
    }

    pub fn record_mapping(&self, permissions: PagePermissions, size: PageSize) {
        self.total_mappings.fetch_add(1, Ordering::Relaxed);

        if permissions.contains(PagePermissions::USER) {
            self.user_pages.fetch_add(1, Ordering::Relaxed);
        } else {
            self.kernel_pages.fetch_add(1, Ordering::Relaxed);
        }

        if matches!(size, PageSize::Size2MiB | PageSize::Size1GiB) {
            self.huge_pages.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_unmapping(&self, permissions: PagePermissions, size: PageSize) {
        self.total_mappings.fetch_sub(1, Ordering::Relaxed);

        if permissions.contains(PagePermissions::USER) {
            self.user_pages.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.kernel_pages.fetch_sub(1, Ordering::Relaxed);
        }

        if matches!(size, PageSize::Size2MiB | PageSize::Size1GiB) {
            self.huge_pages.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn record_page_fault(&self) {
        self.page_faults.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_tlb_flush(&self) {
        self.tlb_flushes.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_cow_fault(&self) {
        self.cow_faults.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_demand_load(&self) {
        self.demand_loads.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_modification(&self) {
        self.page_modifications.fetch_add(1, Ordering::Relaxed);
    }

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

impl Default for PagingStatistics {
    fn default() -> Self {
        Self::new()
    }
}
