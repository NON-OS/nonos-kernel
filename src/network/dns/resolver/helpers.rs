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
use super::super::types::{DnsQueryRecord, MAX_QUERY_CACHE};
use alloc::string::String;

pub(super) fn record_success(hostname: &str) {
    let now = crate::time::timestamp_millis();
    let mut cache = DNS_CACHE.lock();
    cache.query_history.push_back(DnsQueryRecord {
        hostname: String::from(hostname),
        timestamp_ms: now,
        success: true,
    });
    if cache.query_history.len() > MAX_QUERY_CACHE {
        cache.query_history.pop_front();
    }
}

pub(super) fn record_failure(hostname: &str) {
    DNS_STATS.inc_failed();
    let mut cache = DNS_CACHE.lock();
    cache.query_history.push_back(DnsQueryRecord {
        hostname: String::from(hostname),
        timestamp_ms: crate::time::timestamp_millis(),
        success: false,
    });
    if cache.query_history.len() > MAX_QUERY_CACHE {
        cache.query_history.pop_front();
    }
}
