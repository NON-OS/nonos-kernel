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

extern crate alloc;

use alloc::{string::{String, ToString}, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

#[derive(Debug, Clone)]
pub struct DnsPrivacyFinding {
    pub timestamp: u64,
    pub domain: String,
    pub query_type: String,
    pub leaked_data: Option<String>,
    pub severity: u8,
}

#[derive(Debug, Clone)]
pub struct DnsPrivacyScanResult {
    pub timestamp: u64,
    pub findings: Vec<DnsPrivacyFinding>,
    pub violation_score: u8,
}

static LAST_SCAN: Mutex<Option<DnsPrivacyScanResult>> = Mutex::new(None);
static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn scan_dns_queries() -> DnsPrivacyScanResult {
    let mut findings = Vec::new();

    let queries = crate::network::get_recent_dns_queries();
    if !queries.is_empty() {
        for query in queries {
            if is_privacy_leaking_query(&query) {
                findings.push(DnsPrivacyFinding {
                    timestamp: crate::time::timestamp_millis(),
                    domain: query.clone(),
                    query_type: "A".to_string(),
                    leaked_data: Some("hostname".to_string()),
                    severity: 3,
                });
            }
        }
    }

    let violation_score = if findings.is_empty() { 0 } else { 10 * findings.len().min(10) as u8 };

    let result = DnsPrivacyScanResult {
        timestamp: crate::time::timestamp_millis(),
        findings,
        violation_score,
    };

    {
        let mut lock = LAST_SCAN.lock();
        *lock = Some(result.clone());
    }
    SCAN_COUNTER.fetch_add(1, Ordering::Relaxed);
    result
}

pub fn is_privacy_leaking_query(domain: &str) -> bool {
    domain.ends_with(".internal") ||
    domain.ends_with(".corp") ||
    domain.ends_with(".private") ||
    domain.contains("user") ||
    domain.contains("ssn") ||
    domain.contains("account") ||
    domain.contains("personal")
}

pub fn get_last_scan() -> Option<DnsPrivacyScanResult> {
    LAST_SCAN.lock().clone()
}
