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
use super::constants::PAGE_SIZE;
use super::types::VmStatsSnapshot;
// ============================================================================
// GLOBAL STATISTICS
// ============================================================================
pub static VM_STATS: VmStats = VmStats::new();
// ============================================================================
// STATISTICS TRACKER
// ============================================================================
pub struct VmStats {
    mapped_pages: AtomicUsize,
    mapped_memory: AtomicU64,
    page_faults: AtomicU64,
    tlb_flushes: AtomicU64,
    wx_violations: AtomicU64,
}

impl VmStats {
    pub const fn new() -> Self {
        Self {
            mapped_pages: AtomicUsize::new(0),
            mapped_memory: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            tlb_flushes: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
        }
    }

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

    #[inline]
    pub fn mapped_pages(&self) -> usize {
        self.mapped_pages.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn mapped_memory(&self) -> u64 {
        self.mapped_memory.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn page_faults(&self) -> u64 {
        self.page_faults.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn tlb_flushes(&self) -> u64 {
        self.tlb_flushes.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn wx_violations(&self) -> u64 {
        self.wx_violations.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> VmStatsSnapshot {
        VmStatsSnapshot {
            mapped_pages: self.mapped_pages(),
            mapped_memory: self.mapped_memory(),
            page_faults: self.page_faults(),
            tlb_flushes: self.tlb_flushes(),
            wx_violations: self.wx_violations(),
        }
    }
}
