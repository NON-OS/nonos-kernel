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
}

impl Default for PagingStatistics {
    fn default() -> Self {
        Self::new()
    }
}
