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

use alloc::{string::String, vec::Vec, collections::BTreeSet};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

#[derive(Debug, Clone)]
pub struct LeakScanResult {
    pub timestamp: u64,
    pub leaks_found: Vec<LeakFinding>,
    pub leak_score: u8,
}

#[derive(Debug, Clone)]
pub struct LeakFinding {
    pub location: LeakLocation,
    pub description: String,
    pub bytes_leaked: u64,
    pub severity: u8,
    pub pattern: Option<String>,
    pub sample: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum LeakLocation {
    MemoryRegion(u64, u64),
    File(String),
    Network(String),
    Process(u64),
    Device(String),
    Unknown,
}

static LAST_LEAK_SCAN: Mutex<Option<LeakScanResult>> = Mutex::new(None);
static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

static SENSITIVE_PATTERNS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

pub fn add_sensitive_pattern(pattern: &str) {
    SENSITIVE_PATTERNS.lock().insert(pattern.into());
}

pub fn list_sensitive_patterns() -> Vec<String> {
    SENSITIVE_PATTERNS.lock().iter().cloned().collect()
}

pub fn scan_memory() -> LeakScanResult {
    let mut leaks = Vec::new();

    let regions = crate::memory::get_all_process_regions();
    if !regions.is_empty() {
        for region in regions {
            leaks.extend(scan_region_for_leaks(region.0.as_u64(), region.1 as u64));
        }
    }

    let leak_score = compute_leak_score(&leaks);
    let result = LeakScanResult {
        timestamp: crate::time::timestamp_millis(),
        leaks_found: leaks,
        leak_score,
    };
    {
        let mut lock = LAST_LEAK_SCAN.lock();
        *lock = Some(result.clone());
    }
    SCAN_COUNTER.fetch_add(1, Ordering::Relaxed);
    result
}

fn scan_region_for_leaks(start: u64, end: u64) -> Vec<LeakFinding> {
    let mut findings = Vec::new();
    let region_size = end.saturating_sub(start);

    if region_size < 4096 {
        return findings;
    }

    let patterns = SENSITIVE_PATTERNS.lock().clone();

    if let Ok(slice) = crate::memory::read_bytes(start as usize, region_size as usize) {
        let entropy = estimate_entropy(&slice);
        if entropy > 7.0 {
            findings.push(LeakFinding {
                location: LeakLocation::MemoryRegion(start, end),
                description: format!("High entropy memory region (entropy {:.2})", entropy),
                bytes_leaked: region_size,
                severity: 3,
                pattern: Some("high_entropy".into()),
                sample: Some(slice[..slice.len().min(32)].to_vec()),
            });
        }
        for pat in patterns.iter() {
            if let Some(pos) = find_pattern(&slice, pat.as_bytes()) {
                findings.push(LeakFinding {
                    location: LeakLocation::MemoryRegion(start + pos as u64, end),
                    description: format!("Sensitive pattern '{}' found in memory", pat),
                    bytes_leaked: region_size,
                    severity: 4,
                    pattern: Some(pat.clone()),
                    sample: Some(slice[pos..pos + pat.len().min(32)].to_vec()),
                });
            }
        }
    }
    findings
}

fn estimate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * 3.321928;
        }
    }
    entropy
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn scan_filesystem() -> Vec<LeakFinding> {
    let mut findings = Vec::new();
    let files = crate::filesystem::scan_for_sensitive_files("/");
    if !files.is_empty() {
        for f in files {
            if let Ok(data) = crate::filesystem::read_file_bytes(&f) {
                let entropy = estimate_entropy(&data);
                if entropy > 7.0 {
                    findings.push(LeakFinding {
                        location: LeakLocation::File(f.clone()),
                        description: format!("High entropy file"),
                        bytes_leaked: data.len() as u64,
                        severity: 3,
                        pattern: Some("high_entropy".into()),
                        sample: Some(data[..data.len().min(32)].to_vec()),
                    });
                }
                let patterns = SENSITIVE_PATTERNS.lock().clone();
                for pat in patterns.iter() {
                    if let Some(pos) = find_pattern(&data, pat.as_bytes()) {
                        findings.push(LeakFinding {
                            location: LeakLocation::File(f.clone()),
                            description: format!("Sensitive pattern '{}' found in file", pat),
                            bytes_leaked: data.len() as u64,
                            severity: 4,
                            pattern: Some(pat.clone()),
                            sample: Some(data[pos..pos + pat.len().min(32)].to_vec()),
                        });
                    }
                }
            }
        }
    }
    findings
}

pub fn scan_network() -> Vec<LeakFinding> {
    let mut findings = Vec::new();
    let flows = crate::network::get_suspicious_flows();
    if !flows.is_empty() {
        for (flow_id, _flow_type) in flows {
            if let Ok(data) = crate::network::read_flow_bytes(&flow_id) {
                let entropy = estimate_entropy(&data);
                if entropy > 7.0 {
                    findings.push(LeakFinding {
                        location: LeakLocation::Network(flow_id.clone()),
                        description: format!("High entropy network flow"),
                        bytes_leaked: data.len() as u64,
                        severity: 3,
                        pattern: Some("high_entropy".into()),
                        sample: Some(data[..data.len().min(32)].to_vec()),
                    });
                }
                let patterns = SENSITIVE_PATTERNS.lock().clone();
                for pat in patterns.iter() {
                    if let Some(pos) = find_pattern(&data, pat.as_bytes()) {
                        findings.push(LeakFinding {
                            location: LeakLocation::Network(flow_id.clone()),
                            description: format!("Sensitive pattern '{}' found in network flow", pat),
                            bytes_leaked: data.len() as u64,
                            severity: 4,
                            pattern: Some(pat.clone()),
                            sample: Some(data[pos..pos + pat.len().min(32)].to_vec()),
                        });
                    }
                }
            }
        }
    }
    findings
}

fn compute_leak_score(findings: &[LeakFinding]) -> u8 {
    findings.iter().map(|f| f.severity).max().unwrap_or(0) * findings.len().min(10) as u8
}

pub fn get_last_scan() -> Option<LeakScanResult> {
    LAST_LEAK_SCAN.lock().clone()
}
