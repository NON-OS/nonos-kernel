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

//! Memory Hardening Statistics (Lock-Free)
use core::sync::atomic::{AtomicU64, Ordering};
pub struct HardeningStats {
    pub guard_page_violations: AtomicU64,
    pub wx_violations: AtomicU64,
    pub stack_overflows_detected: AtomicU64,
    pub heap_corruptions_detected: AtomicU64,
    pub double_frees_prevented: AtomicU64,
    pub use_after_free_detected: AtomicU64,
    pub mapped_file_pages: AtomicU64,
    pub total_mapped_size: AtomicU64,
    pub kernel_mappings: AtomicU64,
}

impl HardeningStats {
    pub const fn new() -> Self {
        Self {
            guard_page_violations: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
            stack_overflows_detected: AtomicU64::new(0),
            heap_corruptions_detected: AtomicU64::new(0),
            double_frees_prevented: AtomicU64::new(0),
            use_after_free_detected: AtomicU64::new(0),
            mapped_file_pages: AtomicU64::new(0),
            total_mapped_size: AtomicU64::new(0),
            kernel_mappings: AtomicU64::new(0),
        }
    }

    pub fn increment_guard_violations(&self) {
        self.guard_page_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_wx_violations(&self) {
        self.wx_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_stack_overflows(&self) {
        self.stack_overflows_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_heap_corruptions(&self) {
        self.heap_corruptions_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_double_frees(&self) {
        self.double_frees_prevented.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_use_after_free(&self) {
        self.use_after_free_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn guard_violations(&self) -> u64 {
        self.guard_page_violations.load(Ordering::Relaxed)
    }

    pub fn wx_violations(&self) -> u64 {
        self.wx_violations.load(Ordering::Relaxed)
    }

    pub fn stack_overflows(&self) -> u64 {
        self.stack_overflows_detected.load(Ordering::Relaxed)
    }

    pub fn heap_corruptions(&self) -> u64 {
        self.heap_corruptions_detected.load(Ordering::Relaxed)
    }

    pub fn double_frees(&self) -> u64 {
        self.double_frees_prevented.load(Ordering::Relaxed)
    }

    pub fn use_after_free(&self) -> u64 {
        self.use_after_free_detected.load(Ordering::Relaxed)
    }
}

impl Default for HardeningStats {
    fn default() -> Self {
        Self::new()
    }
}
