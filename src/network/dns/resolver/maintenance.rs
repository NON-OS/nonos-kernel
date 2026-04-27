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

use super::super::cache::{DNS_CACHE, DNS_STATS};
use super::super::types::DnsQueryRecord;
use alloc::string::String;
use alloc::vec::Vec;

pub fn check_dns_timeouts() {
    let now = crate::time::timestamp_millis();
    let mut cache = DNS_CACHE.lock();
    cache.entries.retain(|e| now < e.timestamp_ms + e.ttl_ms);
    let timed_out: Vec<_> = cache
        .pending_queries
        .iter()
        .filter(|q| now > q.start_ms + q.timeout_ms)
        .map(|q| q.hostname.clone())
        .collect();
    for hostname in timed_out {
        cache.pending_queries.retain(|q| q.hostname != hostname);
        cache.query_history.push_back(DnsQueryRecord {
            hostname,
            timestamp_ms: now,
            success: false,
        });
        DNS_STATS.inc_failed();
    }
}

pub fn get_recent_queries() -> Vec<String> {
    let cache = DNS_CACHE.lock();
    cache.query_history.iter().rev().take(20).map(|q| q.hostname.clone()).collect()
}

pub fn get_stats() -> (u64, u64, u64) {
    DNS_STATS.get()
}

pub fn clear_cache() {
    DNS_CACHE.lock().entries.clear();
}

pub fn init() -> Result<(), &'static str> {
    crate::log::info!("DNS resolver initialized");
    Ok(())
}
