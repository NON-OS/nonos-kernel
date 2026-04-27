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

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub struct PageStats {
    pub total_pages: AtomicUsize,
    pub mapped_pages: AtomicUsize,
    pub dirty_pages: AtomicUsize,
    pub locked_pages: AtomicUsize,
    pub page_accesses: AtomicU64,
}

impl PageStats {
    pub const fn new() -> Self {
        Self {
            total_pages: AtomicUsize::new(0),
            mapped_pages: AtomicUsize::new(0),
            dirty_pages: AtomicUsize::new(0),
            locked_pages: AtomicUsize::new(0),
            page_accesses: AtomicU64::new(0),
        }
    }

    pub fn increment_total(&self) {
        self.total_pages.fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_total(&self) {
        self.total_pages.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn increment_mapped(&self) {
        self.mapped_pages.fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_mapped(&self) {
        self.mapped_pages.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn increment_dirty(&self) {
        self.dirty_pages.fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_dirty(&self) {
        self.dirty_pages.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn increment_locked(&self) {
        self.locked_pages.fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_locked(&self) {
        self.locked_pages.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn record_access(&self) {
        self.page_accesses.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PageStatsSnapshot {
    pub total_pages: usize,
    pub mapped_pages: usize,
    pub dirty_pages: usize,
    pub locked_pages: usize,
    pub page_accesses: u64,
}
