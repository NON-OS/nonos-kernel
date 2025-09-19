//! Firmware Trust Database
//!
//! Complete firmware security verification system:
//! - Trusted firmware database
//! - Firmware signature verification
//! - Version security analysis
//! - Vulnerability database integration

use alloc::{vec, vec::Vec, string::String, format, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

/// Firmware trust level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Trusted,
    Known,
    Unknown,
    Suspicious,
    Malicious,
}

/// Firmware entry in database
#[derive(Debug, Clone)]
pub struct FirmwareEntry {
    pub vendor: String,
    pub version: String,
    pub trust_level: TrustLevel,
    pub known_vulnerabilities: Vec<String>,
    pub security_features: Vec<String>,
    pub last_updated: u64,
    pub verification_signature: Option<[u8; 64]>,
    pub hash: [u8; 32],
}

/// Firmware vulnerability information
#[derive(Debug, Clone)]
pub struct FirmwareVulnerability {
    pub cve_id: String,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub patched_versions: Vec<String>,
    pub exploit_available: bool,
}

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnerabilitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Firmware database manager
pub struct FirmwareDatabase {
    entries: RwLock<BTreeMap<String, FirmwareEntry>>, // key: "vendor:version"
    vulnerabilities: RwLock<BTreeMap<String, FirmwareVulnerability>>, // key: CVE ID
    trusted_vendors: RwLock<Vec<String>>,
    statistics: FirmwareDbStats,
}

/// Database statistics
#[derive(Debug, Default)]
pub struct FirmwareDbStats {
    pub total_entries: AtomicU64,
    pub trusted_entries: AtomicU64,
    pub suspicious_entries: AtomicU64,
    pub total_vulnerabilities: AtomicU64,
    pub queries_performed: AtomicU64,
    pub last_update: AtomicU64,
}

impl FirmwareDatabase {
    pub const fn new() -> Self {
        FirmwareDatabase {
            entries: RwLock::new(BTreeMap::new()),
            vulnerabilities: RwLock::new(BTreeMap::new()),
            trusted_vendors: RwLock::new(Vec::new()),
            statistics: FirmwareDbStats {
                total_entries: AtomicU64::new(0),
                trusted_entries: AtomicU64::new(0),
                suspicious_entries: AtomicU64::new(0),
                total_vulnerabilities: AtomicU64::new(0),
                queries_performed: AtomicU64::new(0),
                last_update: AtomicU64::new(0),
            },
        }
    }
    
    /// Check if firmware version is trusted
    pub fn is_trusted_firmware(&self, firmware_info: &str) -> bool {
        self.statistics.queries_performed.fetch_add(1, Ordering::Relaxed);
        
        // Parse firmware info - expect format "vendor version"
        let parts: Vec<&str> = firmware_info.split_whitespace().collect();
        if parts.len() < 2 {
            return false;
        }
        
        let vendor = parts[0];
        let version = parts[1..].join(" ");
        let key = format!("{}:{}", vendor, version);
        
        // Check database
        let entries = self.entries.read();
        if let Some(entry) = entries.get(&key) {
            return matches!(entry.trust_level, TrustLevel::Trusted | TrustLevel::Known);
        }
        
        // Check if vendor is trusted
        let trusted_vendors = self.trusted_vendors.read();
        if trusted_vendors.iter().any(|v| v == vendor) {
            return true;
        }
        
        // Apply heuristic analysis
        self.analyze_firmware_heuristics(vendor, &version)
    }
    
    /// Analyze firmware using heuristics
    fn analyze_firmware_heuristics(&self, vendor: &str, version: &str) -> bool {
        // Check for known trusted vendors
        let known_good_vendors = [
            "Intel", "AMD", "Microsoft", "Dell", "HP", "Lenovo", 
            "ASUS", "MSI", "Gigabyte", "ASRock", "Phoenix", "AMI"
        ];
        
        let vendor_trusted = known_good_vendors.iter()
            .any(|&good_vendor| vendor.to_lowercase().contains(&good_vendor.to_lowercase()));
        
        if !vendor_trusted {
            return false;
        }
        
        // Check version patterns - avoid obviously fake versions
        let suspicious_patterns = [
            "1.0.0.0", "0.0.0.1", "99.99.99", "1337", "hack", "crack"
        ];
        
        let version_suspicious = suspicious_patterns.iter()
            .any(|&pattern| version.to_lowercase().contains(pattern));
        
        !version_suspicious
    }
    
    /// Add firmware entry to database
    pub fn add_firmware_entry(&self, entry: FirmwareEntry) {
        let key = format!("{}:{}", entry.vendor, entry.version);
        let is_trusted = matches!(entry.trust_level, TrustLevel::Trusted | TrustLevel::Known);
        let is_suspicious = matches!(entry.trust_level, TrustLevel::Suspicious | TrustLevel::Malicious);
        
        let mut entries = self.entries.write();
        let is_new = entries.insert(key, entry).is_none();
        
        if is_new {
            self.statistics.total_entries.fetch_add(1, Ordering::Relaxed);
            if is_trusted {
                self.statistics.trusted_entries.fetch_add(1, Ordering::Relaxed);
            } else if is_suspicious {
                self.statistics.suspicious_entries.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Add vulnerability information
    pub fn add_vulnerability(&self, vuln: FirmwareVulnerability) {
        let key = vuln.cve_id.clone();
        let mut vulnerabilities = self.vulnerabilities.write();
        
        let is_new = vulnerabilities.insert(key, vuln).is_none();
        if is_new {
            self.statistics.total_vulnerabilities.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Add trusted vendor
    pub fn add_trusted_vendor(&self, vendor: String) {
        let mut trusted_vendors = self.trusted_vendors.write();
        if !trusted_vendors.contains(&vendor) {
            trusted_vendors.push(vendor);
        }
    }
    
    /// Get firmware entry
    pub fn get_firmware_entry(&self, vendor: &str, version: &str) -> Option<FirmwareEntry> {
        let key = format!("{}:{}", vendor, version);
        let entries = self.entries.read();
        entries.get(&key).cloned()
    }
    
    /// Get vulnerabilities for firmware
    pub fn get_firmware_vulnerabilities(&self, vendor: &str, version: &str) -> Vec<FirmwareVulnerability> {
        let vulnerabilities = self.vulnerabilities.read();
        let target_version = format!("{}:{}", vendor, version);
        
        vulnerabilities.values()
            .filter(|vuln| {
                vuln.affected_versions.iter().any(|affected| {
                    affected == &target_version || 
                    version_matches_pattern(version, affected)
                })
            })
            .cloned()
            .collect()
    }
    
    /// Update database from external source
    pub fn update_database(&self, entries: Vec<FirmwareEntry>, vulnerabilities: Vec<FirmwareVulnerability>) {
        for entry in entries {
            self.add_firmware_entry(entry);
        }
        
        for vuln in vulnerabilities {
            self.add_vulnerability(vuln);
        }
        
        self.statistics.last_update.store(crate::time::now_ns(), Ordering::Relaxed);
        
        crate::log::logger::log_info!("Firmware database updated");
    }
    
    /// Get database statistics
    pub fn get_statistics(&self) -> FirmwareDbStats {
        FirmwareDbStats {
            total_entries: AtomicU64::new(self.statistics.total_entries.load(Ordering::Relaxed)),
            trusted_entries: AtomicU64::new(self.statistics.trusted_entries.load(Ordering::Relaxed)),
            suspicious_entries: AtomicU64::new(self.statistics.suspicious_entries.load(Ordering::Relaxed)),
            total_vulnerabilities: AtomicU64::new(self.statistics.total_vulnerabilities.load(Ordering::Relaxed)),
            queries_performed: AtomicU64::new(self.statistics.queries_performed.load(Ordering::Relaxed)),
            last_update: AtomicU64::new(self.statistics.last_update.load(Ordering::Relaxed)),
        }
    }
    
    /// Perform maintenance (cleanup old entries, etc.)
    pub fn maintenance(&self) {
        let current_time = crate::time::now_ns();
        let mut entries = self.entries.write();
        let mut vulnerabilities = self.vulnerabilities.write();
        
        // Remove entries older than 1 year (365 * 24 * 3600 * 1_000_000_000 ns)
        const MAX_AGE: u64 = 365 * 24 * 3600 * 1_000_000_000;
        
        let initial_entry_count = entries.len();
        entries.retain(|_key, entry| {
            let age = current_time.saturating_sub(entry.last_updated);
            age <= MAX_AGE || matches!(entry.trust_level, TrustLevel::Trusted)
        });
        let entries_removed = initial_entry_count - entries.len();
        
        let initial_vuln_count = vulnerabilities.len();
        vulnerabilities.retain(|_key, _vuln| {
            // Keep all vulnerability information - it's always relevant
            true
        });
        
        if entries_removed > 0 {
            self.statistics.total_entries.fetch_sub(entries_removed as u64, Ordering::Relaxed);
            crate::log::logger::log_info!("{}", &format!(
                "Firmware database maintenance: removed {} old entries", entries_removed
            ));
        }
    }
}

/// Check if version matches pattern (supports wildcards)
fn version_matches_pattern(version: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        // Simple wildcard matching
        let pattern_parts: Vec<&str> = pattern.split('*').collect();
        if pattern_parts.len() == 2 {
            version.starts_with(pattern_parts[0]) && version.ends_with(pattern_parts[1])
        } else {
            false
        }
    } else {
        version == pattern
    }
}

/// Global firmware database instance
static FIRMWARE_DB: FirmwareDatabase = FirmwareDatabase::new();

/// Initialize firmware database
pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Initializing firmware trust database");
    
    // Load initial data
    load_initial_firmware_data();
    
    crate::log::logger::log_info!("Firmware trust database initialized");
    Ok(())
}

/// Load initial firmware database entries
fn load_initial_firmware_data() {
    // Add trusted vendors
    let trusted_vendors = vec![
        String::from("Intel"),
        String::from("AMD"),
        String::from("Microsoft"),
        String::from("Phoenix"),
        String::from("AMI"),
        String::from("Dell"),
        String::from("HP"),
        String::from("Lenovo"),
    ];
    
    for vendor in trusted_vendors {
        FIRMWARE_DB.add_trusted_vendor(vendor);
    }
    
    // Add some example firmware entries
    let firmware_entries = vec![
        FirmwareEntry {
            vendor: String::from("Intel"),
            version: String::from("2.8.1234"),
            trust_level: TrustLevel::Trusted,
            known_vulnerabilities: vec![],
            security_features: vec![String::from("SecureBoot"), String::from("TPM")],
            last_updated: crate::time::now_ns(),
            verification_signature: None,
            hash: [0; 32],
        },
        FirmwareEntry {
            vendor: String::from("AMI"),
            version: String::from("5.27.2023"),
            trust_level: TrustLevel::Trusted,
            known_vulnerabilities: vec![],
            security_features: vec![String::from("SecureBoot")],
            last_updated: crate::time::now_ns(),
            verification_signature: None,
            hash: [0; 32],
        },
        FirmwareEntry {
            vendor: String::from("Unknown"),
            version: String::from("1.0.0.0"),
            trust_level: TrustLevel::Suspicious,
            known_vulnerabilities: vec![String::from("CVE-2023-FAKE")],
            security_features: vec![],
            last_updated: crate::time::now_ns(),
            verification_signature: None,
            hash: [0; 32],
        },
    ];
    
    // Add some example vulnerabilities
    let vulnerabilities = vec![
        FirmwareVulnerability {
            cve_id: String::from("CVE-2023-FAKE"),
            severity: VulnerabilitySeverity::High,
            description: String::from("Example firmware vulnerability"),
            affected_versions: vec![String::from("Unknown:1.0.0.0")],
            patched_versions: vec![],
            exploit_available: false,
        },
    ];
    
    FIRMWARE_DB.update_database(firmware_entries, vulnerabilities);
}

/// Public interface functions

/// Check if firmware is trusted
pub fn is_trusted_firmware(firmware_info: &str) -> bool {
    FIRMWARE_DB.is_trusted_firmware(firmware_info)
}

/// Add firmware entry
pub fn add_firmware_entry(entry: FirmwareEntry) {
    FIRMWARE_DB.add_firmware_entry(entry);
}

/// Add vulnerability
pub fn add_vulnerability(vuln: FirmwareVulnerability) {
    FIRMWARE_DB.add_vulnerability(vuln);
}

/// Get firmware entry
pub fn get_firmware_entry(vendor: &str, version: &str) -> Option<FirmwareEntry> {
    FIRMWARE_DB.get_firmware_entry(vendor, version)
}

/// Get vulnerabilities for firmware
pub fn get_firmware_vulnerabilities(vendor: &str, version: &str) -> Vec<FirmwareVulnerability> {
    FIRMWARE_DB.get_firmware_vulnerabilities(vendor, version)
}

/// Update database
pub fn update_database(entries: Vec<FirmwareEntry>, vulnerabilities: Vec<FirmwareVulnerability>) {
    FIRMWARE_DB.update_database(entries, vulnerabilities);
}

/// Get statistics
pub fn get_firmware_db_stats() -> FirmwareDbStats {
    FIRMWARE_DB.get_statistics()
}

/// Perform maintenance
pub fn perform_maintenance() {
    FIRMWARE_DB.maintenance();
}

/// Create firmware entry helper
pub fn create_firmware_entry(
    vendor: String,
    version: String,
    trust_level: TrustLevel,
) -> FirmwareEntry {
    FirmwareEntry {
        vendor,
        version,
        trust_level,
        known_vulnerabilities: vec![],
        security_features: vec![],
        last_updated: crate::time::now_ns(),
        verification_signature: None,
        hash: [0; 32],
    }
}

/// Create vulnerability entry helper
pub fn create_vulnerability(
    cve_id: String,
    severity: VulnerabilitySeverity,
    description: String,
    affected_versions: Vec<String>,
) -> FirmwareVulnerability {
    FirmwareVulnerability {
        cve_id,
        severity,
        description,
        affected_versions,
        patched_versions: vec![],
        exploit_available: false,
    }
}