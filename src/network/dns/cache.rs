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

//! DNS cache and statistics

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::types::{DnsCacheEntry, DnsQueryRecord, PendingQuery};

/// DNS resolver cache and history
pub struct DnsCache {
    pub entries: VecDeque<DnsCacheEntry>,
    pub query_history: VecDeque<DnsQueryRecord>,
    pub pending_queries: Vec<PendingQuery>,
}

impl DnsCache {
    /// Create new empty cache
    pub const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            query_history: VecDeque::new(),
            pending_queries: Vec::new(),
        }
    }
}

/// DNS statistics
pub struct DnsStats {
    pub queries_total: AtomicU64,
    pub queries_cached: AtomicU64,
    pub queries_failed: AtomicU64,
}

impl DnsStats {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_cached: AtomicU64::new(0),
            queries_failed: AtomicU64::new(0),
        }
    }

    /// Increment total queries
    pub fn inc_total(&self) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment cached hits
    pub fn inc_cached(&self) {
        self.queries_cached.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed queries
    pub fn inc_failed(&self) {
        self.queries_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get statistics tuple (total, cached, failed)
    pub fn get(&self) -> (u64, u64, u64) {
        (
            self.queries_total.load(Ordering::Relaxed),
            self.queries_cached.load(Ordering::Relaxed),
            self.queries_failed.load(Ordering::Relaxed),
        )
    }
}

/// Global DNS cache
pub static DNS_CACHE: Mutex<DnsCache> = Mutex::new(DnsCache::new());

/// Global DNS statistics
pub static DNS_STATS: DnsStats = DnsStats::new();
