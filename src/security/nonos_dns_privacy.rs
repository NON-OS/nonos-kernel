#![no_std]

extern crate alloc;

use alloc::{string::{String, ToString}, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// DNS privacy violation finding
#[derive(Debug, Clone)]
pub struct DnsPrivacyFinding {
    pub timestamp: u64,
    pub domain: String,
    pub query_type: String,
    pub leaked_data: Option<String>,
    pub severity: u8, // 1=low, 2=medium, 3=high, 4=critical
}

/// DNS privacy scan result
#[derive(Debug, Clone)]
pub struct NonosDnsPrivacyScanResult {
    pub timestamp: u64,
    pub findings: Vec<DnsPrivacyFinding>,
    pub violation_score: u8,
}

static LAST_SCAN: Mutex<Option<NonosDnsPrivacyScanResult>> = Mutex::new(None);
static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Scan DNS queries for privacy leaks 
pub fn scan_dns_queries() -> NonosDnsPrivacyScanResult {
    let mut findings = Vec::new();

    let queries = crate::network::get_recent_dns_queries();
    if !queries.is_empty() {
        for query in queries {
            // Personally identifiable info or known privacy-leaking domains
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

    let result = NonosDnsPrivacyScanResult {
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

/// Heuristic for privacy-leaking DNS queries
pub fn is_privacy_leaking_query(domain: &str) -> bool {
    domain.ends_with(".internal") ||
    domain.ends_with(".corp") ||
    domain.ends_with(".private") ||
    domain.contains("user") ||
    domain.contains("ssn") ||
    domain.contains("account") ||
    domain.contains("personal")
}

/// Get last DNS privacy scan
pub fn get_last_scan() -> Option<NonosDnsPrivacyScanResult> {
    LAST_SCAN.lock().clone()
}
