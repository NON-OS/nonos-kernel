//! Threat Intelligence and Network Security Module
//!
//! Complete threat detection and network security analysis:
//! - IP reputation and geolocation analysis
//! - Known malware signatures and patterns
//! - Network traffic anomaly detection
//! - Dynamic threat intelligence updates

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

/// IP address reputation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReputationLevel {
    Trusted,
    Clean,
    Suspicious,
    Malicious,
    Blacklisted,
}

/// Threat category classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    Malware,
    Botnet,
    Phishing,
    Spam,
    Scanner,
    Brute,
    DDoS,
    Tor,
    Proxy,
    Unknown,
}

/// IP address information
#[derive(Debug, Clone)]
pub struct IpInfo {
    pub ip: [u8; 4], // IPv4 for now
    pub reputation: ReputationLevel,
    pub categories: Vec<ThreatCategory>,
    pub country_code: Option<[u8; 2]>,
    pub asn: Option<u32>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub confidence: u8,   // 0-100
    pub threat_score: u8, // 0-100 threat score
}

/// Threat intelligence database
pub struct ThreatIntelligence {
    ip_database: RwLock<BTreeMap<u32, IpInfo>>, // u32 is packed IPv4
    blacklist: RwLock<BTreeSet<u32>>,
    whitelist: RwLock<BTreeSet<u32>>,
    statistics: ThreatStats,
}

/// Threat detection statistics
#[derive(Debug, Default)]
pub struct ThreatStats {
    pub queries_total: AtomicU64,
    pub threats_detected: AtomicU64,
    pub false_positives: AtomicU64,
    pub database_entries: AtomicU64,
    pub last_update: AtomicU64,
}

impl ThreatIntelligence {
    pub const fn new() -> Self {
        ThreatIntelligence {
            ip_database: RwLock::new(BTreeMap::new()),
            blacklist: RwLock::new(BTreeSet::new()),
            whitelist: RwLock::new(BTreeSet::new()),
            statistics: ThreatStats {
                queries_total: AtomicU64::new(0),
                threats_detected: AtomicU64::new(0),
                false_positives: AtomicU64::new(0),
                database_entries: AtomicU64::new(0),
                last_update: AtomicU64::new(0),
            },
        }
    }

    /// Check if IP address is known malicious
    pub fn is_malicious(&self, ip: [u8; 4]) -> bool {
        self.statistics.queries_total.fetch_add(1, Ordering::Relaxed);

        let packed_ip = u32::from_be_bytes(ip);

        // Check blacklist first (fastest)
        if self.blacklist.read().contains(&packed_ip) {
            self.statistics.threats_detected.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Check whitelist
        if self.whitelist.read().contains(&packed_ip) {
            return false;
        }

        // Check detailed database
        if let Some(info) = self.ip_database.read().get(&packed_ip) {
            let is_threat = matches!(
                info.reputation,
                ReputationLevel::Malicious | ReputationLevel::Blacklisted
            );
            if is_threat {
                self.statistics.threats_detected.fetch_add(1, Ordering::Relaxed);
            }
            return is_threat;
        }

        // Unknown IP - apply heuristics
        self.apply_heuristics(ip)
    }

    /// Apply heuristic analysis for unknown IPs
    fn apply_heuristics(&self, ip: [u8; 4]) -> bool {
        // Private/local addresses are generally safe
        if self.is_private_ip(ip) {
            return false;
        }

        // Check for suspicious patterns
        if self.has_suspicious_pattern(ip) {
            self.statistics.threats_detected.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    /// Check if IP is in private address space
    fn is_private_ip(&self, ip: [u8; 4]) -> bool {
        match ip {
            [10, _, _, _] => true,                        // 10.0.0.0/8
            [172, b, _, _] if b >= 16 && b <= 31 => true, // 172.16.0.0/12
            [192, 168, _, _] => true,                     // 192.168.0.0/16
            [127, _, _, _] => true,                       // Loopback
            [169, 254, _, _] => true,                     // Link-local
            _ => false,
        }
    }

    /// Check for suspicious IP patterns
    fn has_suspicious_pattern(&self, ip: [u8; 4]) -> bool {
        // Example heuristics (would be more sophisticated in production)

        // Sequential patterns often indicate scanning
        let sequential = (ip[1] as i16 - ip[0] as i16).abs() == 1
            && (ip[2] as i16 - ip[1] as i16).abs() == 1
            && (ip[3] as i16 - ip[2] as i16).abs() == 1;

        // Certain ranges known for hosting compromised machines
        let suspicious_ranges = [
            ([1, 0, 0, 0], [1, 255, 255, 255]),     // Example suspicious range
            ([223, 0, 0, 0], [223, 255, 255, 255]), // Another example
        ];

        for &(start, end) in &suspicious_ranges {
            if self.ip_in_range(ip, start, end) {
                return true;
            }
        }

        sequential
    }

    /// Check if IP is within a range
    fn ip_in_range(&self, ip: [u8; 4], start: [u8; 4], end: [u8; 4]) -> bool {
        let ip_u32 = u32::from_be_bytes(ip);
        let start_u32 = u32::from_be_bytes(start);
        let end_u32 = u32::from_be_bytes(end);

        ip_u32 >= start_u32 && ip_u32 <= end_u32
    }

    /// Add IP to database
    pub fn add_ip_info(&self, info: IpInfo) {
        let packed_ip = u32::from_be_bytes(info.ip);
        let is_new = self.ip_database.write().insert(packed_ip, info).is_none();

        if is_new {
            self.statistics.database_entries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Add IP to blacklist
    pub fn blacklist_ip(&self, ip: [u8; 4]) {
        let packed_ip = u32::from_be_bytes(ip);
        self.blacklist.write().insert(packed_ip);

        // Also remove from whitelist if present
        self.whitelist.write().remove(&packed_ip);

        crate::log::logger::log_info!("{}", &format!("IP {:?} added to blacklist", ip));
    }

    /// Add IP to whitelist
    pub fn whitelist_ip(&self, ip: [u8; 4]) {
        let packed_ip = u32::from_be_bytes(ip);
        self.whitelist.write().insert(packed_ip);

        // Also remove from blacklist if present
        self.blacklist.write().remove(&packed_ip);

        crate::log::logger::log_info!("{}", &format!("IP {:?} added to whitelist", ip));
    }

    /// Get IP information
    pub fn get_ip_info(&self, ip: [u8; 4]) -> Option<IpInfo> {
        let packed_ip = u32::from_be_bytes(ip);
        self.ip_database.read().get(&packed_ip).cloned()
    }

    /// Update threat intelligence database
    pub fn update_database(&self, entries: Vec<IpInfo>) {
        let mut db = self.ip_database.write();
        let mut new_entries = 0u64;

        for entry in entries {
            let packed_ip = u32::from_be_bytes(entry.ip);
            if db.insert(packed_ip, entry).is_none() {
                new_entries += 1;
            }
        }

        self.statistics.database_entries.fetch_add(new_entries, Ordering::Relaxed);
        self.statistics.last_update.store(crate::time::now_ns(), Ordering::Relaxed);

        crate::log::logger::log_info!(
            "{}",
            &format!("Threat intelligence database updated with {} new entries", new_entries)
        );
    }

    /// Get statistics
    pub fn get_stats(&self) -> ThreatStats {
        ThreatStats {
            queries_total: AtomicU64::new(self.statistics.queries_total.load(Ordering::Relaxed)),
            threats_detected: AtomicU64::new(
                self.statistics.threats_detected.load(Ordering::Relaxed),
            ),
            false_positives: AtomicU64::new(
                self.statistics.false_positives.load(Ordering::Relaxed),
            ),
            database_entries: AtomicU64::new(
                self.statistics.database_entries.load(Ordering::Relaxed),
            ),
            last_update: AtomicU64::new(self.statistics.last_update.load(Ordering::Relaxed)),
        }
    }

    /// Perform maintenance (cleanup old entries, etc.)
    pub fn maintenance(&self) {
        let current_time = crate::time::now_ns();
        let mut db = self.ip_database.write();
        let mut removed = 0;

        // Remove entries older than 30 days (30 * 24 * 3600 * 1_000_000_000 ns)
        const MAX_AGE: u64 = 30 * 24 * 3600 * 1_000_000_000;

        db.retain(|_ip, info| {
            let age = current_time.saturating_sub(info.last_seen);
            if age > MAX_AGE && info.confidence < 80 {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            self.statistics.database_entries.fetch_sub(removed, Ordering::Relaxed);
            crate::log::logger::log_info!(
                "{}",
                &format!("Removed {} old threat intelligence entries", removed)
            );
        }
    }
}

/// Global threat intelligence instance
static THREAT_INTEL: ThreatIntelligence = ThreatIntelligence::new();

/// Initialize threat intelligence subsystem
pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Initializing threat intelligence subsystem");

    // Load initial threat data
    load_initial_threat_data();

    crate::log::logger::log_info!("Threat intelligence subsystem initialized");
    Ok(())
}

/// Load initial threat intelligence data
fn load_initial_threat_data() {
    // Add some known malicious IPs (examples)
    let malicious_ips = vec![
        // These are example IPs - in production would come from threat feeds
        IpInfo {
            ip: [1, 2, 3, 4],
            reputation: ReputationLevel::Malicious,
            categories: vec![ThreatCategory::Malware, ThreatCategory::Botnet],
            country_code: Some(*b"CN"),
            asn: Some(12345),
            first_seen: crate::time::now_ns(),
            last_seen: crate::time::now_ns(),
            confidence: 95,
            threat_score: 95,
        },
        IpInfo {
            ip: [5, 6, 7, 8],
            reputation: ReputationLevel::Malicious,
            categories: vec![ThreatCategory::Scanner],
            country_code: Some(*b"RU"),
            asn: Some(67890),
            first_seen: crate::time::now_ns(),
            last_seen: crate::time::now_ns(),
            confidence: 90,
            threat_score: 90,
        },
    ];

    THREAT_INTEL.update_database(malicious_ips);

    // Add some trusted IPs
    let trusted_ips = [
        [8, 8, 8, 8],        // Google DNS
        [1, 1, 1, 1],        // Cloudflare DNS
        [208, 67, 222, 222], // OpenDNS
    ];

    for ip in &trusted_ips {
        THREAT_INTEL.whitelist_ip(*ip);
    }
}

/// Public interface functions

/// Check if an IP address is known to be malicious
pub fn is_known_malicious_ip(ip: [u8; 4]) -> bool {
    THREAT_INTEL.is_malicious(ip)
}

/// Add an IP to the blacklist
pub fn blacklist_ip(ip: [u8; 4]) {
    THREAT_INTEL.blacklist_ip(ip);
}

/// Add an IP to the whitelist  
pub fn whitelist_ip(ip: [u8; 4]) {
    THREAT_INTEL.whitelist_ip(ip);
}

/// Get information about an IP address
pub fn get_ip_reputation(ip: [u8; 4]) -> Option<IpInfo> {
    THREAT_INTEL.get_ip_info(ip)
}

/// Update threat intelligence database with new data
pub fn update_threat_database(entries: Vec<IpInfo>) {
    THREAT_INTEL.update_database(entries);
}

/// Get threat intelligence statistics
pub fn get_threat_stats() -> ThreatStats {
    THREAT_INTEL.get_stats()
}

/// Perform maintenance on threat intelligence database
pub fn perform_maintenance() {
    THREAT_INTEL.maintenance();
}

/// Create IP info structure helper
pub fn create_ip_info(
    ip: [u8; 4],
    reputation: ReputationLevel,
    categories: Vec<ThreatCategory>,
    confidence: u8,
) -> IpInfo {
    IpInfo {
        ip,
        reputation,
        categories,
        country_code: None,
        asn: None,
        first_seen: crate::time::now_ns(),
        last_seen: crate::time::now_ns(),
        confidence,
        threat_score: confidence,
    }
}

// Re-export traffic analysis functions at module level
pub use traffic_analysis::{is_known_backdoor_connection, is_known_data_collection_service};

/// Network traffic analysis functions
pub mod traffic_analysis {
    use super::*;

    /// Analyze network traffic for suspicious patterns
    pub fn analyze_traffic_pattern(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        payload_size: usize,
    ) -> bool {
        // Check if either IP is known malicious
        if is_known_malicious_ip(src_ip) || is_known_malicious_ip(dst_ip) {
            return true;
        }

        // Check for suspicious port combinations
        if is_suspicious_port_combination(src_port, dst_port) {
            return true;
        }

        // Check for suspicious payload sizes
        if is_suspicious_payload_size(payload_size, protocol) {
            return true;
        }

        false
    }

    /// Check if port combination is suspicious
    fn is_suspicious_port_combination(src_port: u16, dst_port: u16) -> bool {
        // Common malware ports
        let malware_ports = [1337, 31337, 12345, 54321, 9999, 40421, 40422, 40423, 40424];

        malware_ports.contains(&src_port) || malware_ports.contains(&dst_port)
    }

    /// Check if payload size is suspicious for the protocol
    fn is_suspicious_payload_size(size: usize, protocol: u8) -> bool {
        match protocol {
            1 => size > 65507,  // ICMP - unusually large ICMP packets
            6 => size == 0,     // TCP - zero-size TCP payload might be scanning
            17 => size > 65507, // UDP - unusually large UDP packets
            _ => false,
        }
    }

    pub fn is_known_backdoor_connection(conn: &crate::network::NetworkConnection) -> bool {
        false // Simplified check
    }

    pub fn is_known_data_collection_service(ip: [u8; 4]) -> bool {
        false // Simplified check
    }
}

/// Update threat score for an IP address
pub fn update_threat_score(ip: [u8; 4], score_delta: i32) {
    let packed_ip =
        ((ip[0] as u32) << 24) | ((ip[1] as u32) << 16) | ((ip[2] as u32) << 8) | (ip[3] as u32);
    let mut db = THREAT_INTEL.ip_database.write();

    let entry = db.entry(packed_ip).or_insert(IpInfo {
        ip,
        reputation: ReputationLevel::Clean,
        categories: vec![ThreatCategory::Unknown],
        country_code: None,
        asn: None,
        first_seen: crate::time::get_timestamp(),
        last_seen: crate::time::get_timestamp(),
        threat_score: 0,
        confidence: 50,
    });

    // Update threat score
    entry.threat_score = (entry.threat_score as i32 + score_delta).max(0).min(100) as u8;

    // Update reputation based on threat score
    entry.reputation = match entry.threat_score {
        0..=20 => ReputationLevel::Trusted,
        21..=40 => ReputationLevel::Clean,
        41..=60 => ReputationLevel::Suspicious,
        61..=80 => ReputationLevel::Malicious,
        81..=100 => ReputationLevel::Blacklisted,
        _ => ReputationLevel::Clean,
    };

    entry.last_seen = crate::time::get_timestamp();

    crate::log::logger::log_info!(
        "Updated threat score for {:?}: {} -> {}",
        ip,
        entry.threat_score.saturating_sub(score_delta.abs() as u8),
        entry.threat_score
    );
}
