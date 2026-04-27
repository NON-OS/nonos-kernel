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

use super::super::constants::PAGE_SIZE;
use super::types::VmStats;
use core::sync::atomic::Ordering;

impl VmStats {
    pub fn record_mapping(&self, size: usize) {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        self.mapped_pages.fetch_add(pages, Ordering::Relaxed);
        self.mapped_memory.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn record_unmapping(&self, size: usize) {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        self.mapped_pages.fetch_sub(pages, Ordering::Relaxed);
        self.mapped_memory.fetch_sub(size as u64, Ordering::Relaxed);
    }

    pub fn record_page_fault(&self) {
        self.page_faults.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tlb_flush(&self) {
        self.tlb_flushes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_wx_violation(&self) {
        self.wx_violations.fetch_add(1, Ordering::Relaxed);
    }
}
