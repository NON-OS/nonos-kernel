#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec, collections::BTreeSet};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Result of a data leak scan
#[derive(Debug, Clone)]
pub struct NonosDataLeakScanResult {
    pub timestamp: u64,
    pub leaks_found: Vec<DataLeakFinding>,
    pub leak_score: u8, // 0=none, 100=critical
}

#[derive(Debug, Clone)]
pub struct DataLeakFinding {
    pub location: LeakLocation,
    pub description: String,
    pub bytes_leaked: u64,
    pub severity: u8, // 1=low, 2=medium, 3=high, 4=critical
    pub pattern: Option<String>,
    pub sample: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum LeakLocation {
    MemoryRegion(u64, u64), // start, end
    File(String),
    Network(String), // IP/port
    Process(u64),
    Device(String),
    Unknown,
}

static LAST_LEAK_SCAN: Mutex<Option<NonosDataLeakScanResult>> = Mutex::new(None);
static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Configurable list of sensitive patterns 
static SENSITIVE_PATTERNS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Add a sensitive pattern for leak scanning
pub fn add_sensitive_pattern(pattern: &str) {
    SENSITIVE_PATTERNS.lock().insert(pattern.into());
}

/// List all active sensitive patterns
pub fn list_sensitive_patterns() -> Vec<String> {
    SENSITIVE_PATTERNS.lock().iter().cloned().collect()
}

/// Scan all memory for sensitive data leaks
pub fn scan_memory() -> NonosDataLeakScanResult {
    let mut leaks = Vec::new();

    let regions = crate::memory::get_all_process_regions();
    if !regions.is_empty() {
        for region in regions {
            leaks.extend(scan_region_for_leaks(region.0.as_u64(), region.1 as u64));
        }
    }

    let leak_score = compute_leak_score(&leaks);
    let result = NonosDataLeakScanResult {
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

/// Scan a region for sensitive data leaks using pattern matching and entropy checks
fn scan_region_for_leaks(start: u64, end: u64) -> Vec<DataLeakFinding> {
    let mut findings = Vec::new();
    let region_size = end.saturating_sub(start);

    // Only scan if region is nontrivial
    if region_size < 4096 {
        return findings;
    }

    let patterns = SENSITIVE_PATTERNS.lock().clone();

    unsafe {
        // Read memory region safely
        if let Ok(slice) = crate::memory::read_bytes(start as usize, region_size as usize) {
            // Simple entropy check
            let entropy = estimate_entropy(&slice);
            if entropy > 7.0 {
                findings.push(DataLeakFinding {
                    location: LeakLocation::MemoryRegion(start, end),
                    description: format!("High entropy memory region (entropy {:.2})", entropy),
                    bytes_leaked: region_size,
                    severity: 3,
                    pattern: Some("high_entropy".into()),
                    sample: Some(slice[..slice.len().min(32)].to_vec()),
                });
            }
            // Pattern scan (substring search for each sensitive pattern)
            for pat in patterns.iter() {
                if let Some(pos) = find_pattern(&slice, pat.as_bytes()) {
                    findings.push(DataLeakFinding {
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
    }
    findings
}

/// Naive entropy estimator (Shannon entropy per byte)
fn estimate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            // log2(x) = ln(x) / ln(2) (no_std doesn't have log2)
            entropy -= p * 3.321928;
        }
    }
    entropy
}

/// Find a pattern in a byte slice, return offset if found
fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Scan filesystem for leaks (pattern and entropy analysis)
pub fn scan_filesystem() -> Vec<DataLeakFinding> {
    let mut findings = Vec::new();
    let files = crate::filesystem::scan_for_sensitive_files("/");
    if !files.is_empty() {
        for f in files {
            if let Ok(data) = crate::filesystem::read_file_bytes(&f) {
                let entropy = estimate_entropy(&data);
                if entropy > 7.0 {
                    findings.push(DataLeakFinding {
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
                        findings.push(DataLeakFinding {
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

/// Scan network flows for leaks (pattern and entropy analysis)
pub fn scan_network() -> Vec<DataLeakFinding> {
    let mut findings = Vec::new();
    let flows = crate::network::get_suspicious_flows();
    if !flows.is_empty() {
        for (flow_id, _flow_type) in flows {
            if let Ok(data) = crate::network::read_flow_bytes(&flow_id) {
                let entropy = estimate_entropy(&data);
                if entropy > 7.0 {
                    findings.push(DataLeakFinding {
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
                        findings.push(DataLeakFinding {
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

/// Compute leak score based on severity and findings
fn compute_leak_score(findings: &[DataLeakFinding]) -> u8 {
    findings.iter().map(|f| f.severity).max().unwrap_or(0) * findings.len().min(10) as u8
}

/// Get last leak scan result
pub fn get_last_scan() -> Option<NonosDataLeakScanResult> {
    LAST_LEAK_SCAN.lock().clone()
}
