use alloc::{vec, vec::Vec, string::String, collections::BTreeMap, format};
use core::{mem, ptr, slice};
use crate::ui::SecurityLevel;

pub struct ThreatAssessment {
    pub threat_level: u8,
    pub is_malicious: bool,
}

pub struct DataLeakDetector {
    patterns: Vec<DataPattern>,
    encrypted_storage: Vec<EncryptedData>,
    monitoring_enabled: bool,
    violation_count: usize,
}

#[derive(Clone)]
pub struct DataPattern {
    pattern_type: PatternType,
    pattern_data: Vec<u8>,
    sensitivity_level: SensitivityLevel,
    description: String,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum PatternType {
    CreditCard = 1,
    SocialSecurity = 2,
    PhoneNumber = 3,
    EmailAddress = 4,
    IpAddress = 5,
    ApiKey = 6,
    PrivateKey = 7,
    Password = 8,
    PersonalData = 9,
    FinancialData = 10,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum SensitivityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
    TopSecret = 4,
}

#[derive(Clone)]
pub struct EncryptedData {
    encrypted_content: Vec<u8>,
    key_hash: [u8; 32],
    timestamp: u64,
    access_count: u32,
}

pub struct DataLeakEvent {
    pub event_type: LeakType,
    pub severity: SensitivityLevel,
    pub data_size: usize,
    pub timestamp: u64,
    pub process_id: u32,
    pub destination: String,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum LeakType {
    NetworkTransmission = 1,
    FileWrite = 2,
    ClipboardCopy = 3,
    MemoryDump = 4,
    PrintSpooler = 5,
    UsbTransfer = 6,
    EmailSend = 7,
    CloudUpload = 8,
}

pub struct NetworkMonitor {
    suspicious_connections: Vec<SuspiciousConnection>,
    blocked_ips: Vec<[u8; 4]>,
    data_transfer_log: Vec<DataTransfer>,
}

#[derive(Clone)]
pub struct SuspiciousConnection {
    remote_ip: [u8; 4],
    remote_port: u16,
    data_size: usize,
    timestamp: u64,
    threat_score: u8,
}

#[derive(Clone)]
pub struct DataTransfer {
    direction: TransferDirection,
    size: usize,
    contains_sensitive: bool,
    destination: String,
    timestamp: u64,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum TransferDirection {
    Outbound = 1,
    Inbound = 2,
}

impl DataLeakDetector {
    pub fn new() -> Self {
        let mut detector = DataLeakDetector {
            patterns: Vec::new(),
            encrypted_storage: Vec::new(),
            monitoring_enabled: true,
            violation_count: 0,
        };
        
        detector.initialize_default_patterns();
        detector
    }

    fn initialize_default_patterns(&mut self) {
        self.patterns.push(DataPattern {
            pattern_type: PatternType::CreditCard,
            pattern_data: b"\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b".to_vec(),
            sensitivity_level: SensitivityLevel::Confidential,
            description: "Credit Card Number Pattern".into(),
        });

        self.patterns.push(DataPattern {
            pattern_type: PatternType::SocialSecurity,
            pattern_data: b"\\b(?!000|666|9\\d{2})\\d{3}[-\\s]?(?!00)\\d{2}[-\\s]?(?!0000)\\d{4}\\b".to_vec(),
            sensitivity_level: SensitivityLevel::Restricted,
            description: "Social Security Number Pattern".into(),
        });

        self.patterns.push(DataPattern {
            pattern_type: PatternType::EmailAddress,
            pattern_data: b"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b".to_vec(),
            sensitivity_level: SensitivityLevel::Internal,
            description: "Email Address Pattern".into(),
        });

        self.patterns.push(DataPattern {
            pattern_type: PatternType::ApiKey,
            pattern_data: b"(?i)(?:api[_\\s-]?key|access[_\\s-]?token|secret[_\\s-]?key)[\"'\\s:=]*[\"']?([a-z0-9]{20,})".to_vec(),
            sensitivity_level: SensitivityLevel::TopSecret,
            description: "API Key Pattern".into(),
        });

        self.patterns.push(DataPattern {
            pattern_type: PatternType::PrivateKey,
            pattern_data: b"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----".to_vec(),
            sensitivity_level: SensitivityLevel::TopSecret,
            description: "Private Key Header Pattern".into(),
        });
    }

    pub fn scan_memory_region(&mut self, memory: &[u8], process_id: u32) -> Vec<DataLeakEvent> {
        let mut events = Vec::new();
        
        if !self.monitoring_enabled {
            return events;
        }

        for pattern in &self.patterns {
            if let Some(matches) = self.find_pattern_matches(memory, &pattern.pattern_data) {
                for match_pos in matches {
                    let event = DataLeakEvent {
                        event_type: LeakType::MemoryDump,
                        severity: pattern.sensitivity_level,
                        data_size: pattern.pattern_data.len(),
                        timestamp: crate::time::get_timestamp(),
                        process_id,
                        destination: format!("Memory@0x{:x}", match_pos),
                    };
                    events.push(event);
                    self.violation_count += 1;
                }
            }
        }

        events
    }

    fn find_pattern_matches(&self, data: &[u8], pattern: &[u8]) -> Option<Vec<usize>> {
        let mut matches = Vec::new();
        
        if pattern.is_empty() || data.len() < pattern.len() {
            return None;
        }

        for i in 0..=(data.len() - pattern.len()) {
            if self.boyer_moore_search(&data[i..], pattern) {
                matches.push(i);
            }
        }

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    fn boyer_moore_search(&self, text: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return true;
        }
        
        if text.len() < pattern.len() {
            return false;
        }

        let mut bad_char_table = [pattern.len(); 256];
        for (i, &byte) in pattern.iter().enumerate() {
            if i < pattern.len() - 1 {
                bad_char_table[byte as usize] = pattern.len() - 1 - i;
            }
        }

        let mut i = 0;
        while i <= text.len() - pattern.len() {
            let mut j = pattern.len();
            while j > 0 && pattern[j - 1] == text[i + j - 1] {
                j -= 1;
            }

            if j == 0 {
                return true;
            }

            let bad_char_skip = if i + j < text.len() {
                bad_char_table[text[i + j] as usize]
            } else {
                1
            };

            i += bad_char_skip.max(1);
        }

        false
    }

    pub fn monitor_network_traffic(&mut self, data: &[u8], destination_ip: [u8; 4], destination_port: u16) -> Option<DataLeakEvent> {
        if !self.monitoring_enabled {
            return None;
        }

        let contains_sensitive = self.scan_for_sensitive_data(data);
        
        if contains_sensitive {
            self.violation_count += 1;
            Some(DataLeakEvent {
                event_type: LeakType::NetworkTransmission,
                severity: SensitivityLevel::Confidential,
                data_size: data.len(),
                timestamp: crate::time::get_timestamp(),
                process_id: 0,
                destination: format!("{}.{}.{}.{}:{}", 
                    destination_ip[0], destination_ip[1], 
                    destination_ip[2], destination_ip[3], 
                    destination_port),
            })
        } else {
            None
        }
    }

    fn scan_for_sensitive_data(&self, data: &[u8]) -> bool {
        for pattern in &self.patterns {
            if pattern.sensitivity_level >= SensitivityLevel::Confidential {
                if self.find_pattern_matches(data, &pattern.pattern_data).is_some() {
                    return true;
                }
            }
        }
        false
    }

    pub fn monitor_file_operations(&mut self, file_path: &str, data: &[u8], operation: FileOperation) -> Option<DataLeakEvent> {
        if !self.monitoring_enabled {
            return None;
        }

        let contains_sensitive = self.scan_for_sensitive_data(data);
        
        if contains_sensitive && matches!(operation, FileOperation::Write | FileOperation::Create) {
            self.violation_count += 1;
            Some(DataLeakEvent {
                event_type: LeakType::FileWrite,
                severity: SensitivityLevel::Internal,
                data_size: data.len(),
                timestamp: crate::time::get_timestamp(),
                process_id: 0,
                destination: file_path.into(),
            })
        } else {
            None
        }
    }

    pub fn encrypt_sensitive_data(&mut self, data: &[u8], key: &[u8; 32]) -> Result<usize, &'static str> {
        if data.is_empty() {
            return Err("Empty data cannot be encrypted");
        }

        let encrypted = self.simple_xor_encrypt(data, key);
        let key_hash = self.hash_key(key);
        
        let encrypted_data = EncryptedData {
            encrypted_content: encrypted,
            key_hash,
            timestamp: crate::time::get_timestamp(),
            access_count: 0,
        };

        self.encrypted_storage.push(encrypted_data);
        Ok(self.encrypted_storage.len() - 1)
    }

    fn simple_xor_encrypt(&self, data: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let mut encrypted = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            encrypted.push(byte ^ key[i % 32]);
        }
        encrypted
    }

    fn hash_key(&self, key: &[u8; 32]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for (i, &byte) in key.iter().enumerate() {
            hash[i] = byte.wrapping_mul(31).wrapping_add(i as u8);
        }
        hash
    }

    pub fn decrypt_sensitive_data(&mut self, index: usize, key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        if index >= self.encrypted_storage.len() {
            return Err("Invalid encrypted data index");
        }

        let key_hash = self.hash_key(key);
        if self.encrypted_storage[index].key_hash != key_hash {
            return Err("Invalid decryption key");
        }

        let decrypted = self.simple_xor_encrypt(&self.encrypted_storage[index].encrypted_content, key);
        self.encrypted_storage[index].access_count += 1;
        
        Ok(decrypted)
    }

    pub fn get_violation_statistics(&self) -> DataLeakStatistics {
        DataLeakStatistics {
            total_violations: self.violation_count,
            encrypted_items: self.encrypted_storage.len(),
            active_patterns: self.patterns.len(),
            monitoring_status: self.monitoring_enabled,
        }
    }

    pub fn add_custom_pattern(&mut self, pattern_type: PatternType, pattern_data: Vec<u8>, sensitivity: SensitivityLevel, description: String) {
        let pattern = DataPattern {
            pattern_type,
            pattern_data,
            sensitivity_level: sensitivity,
            description,
        };
        self.patterns.push(pattern);
    }

    pub fn enable_monitoring(&mut self) {
        self.monitoring_enabled = true;
    }

    pub fn disable_monitoring(&mut self) {
        self.monitoring_enabled = false;
    }

    pub fn clear_violations(&mut self) {
        self.violation_count = 0;
    }

    pub fn scan_data_for_leaks(&self, data: &[u8], destination: &str) -> bool {
        if !self.monitoring_enabled {
            return false;
        }

        // Check against known patterns
        for pattern in &self.patterns {
            // Simple byte pattern matching (could be enhanced with regex)
            if data.windows(pattern.pattern_data.len()).any(|window| window == &pattern.pattern_data[..]) {
                crate::log_warn!("Data leak detected: {} to {}", pattern.description, destination);
                return true;
            }
        }

        false
    }
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum FileOperation {
    Read = 1,
    Write = 2,
    Create = 3,
    Delete = 4,
    Move = 5,
}

pub struct DataLeakStatistics {
    pub total_violations: usize,
    pub encrypted_items: usize,
    pub active_patterns: usize,
    pub monitoring_status: bool,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        NetworkMonitor {
            suspicious_connections: Vec::new(),
            blocked_ips: Vec::new(),
            data_transfer_log: Vec::new(),
        }
    }

    pub fn log_data_transfer(&mut self, direction: TransferDirection, size: usize, contains_sensitive: bool, destination: String) {
        let transfer = DataTransfer {
            direction,
            size,
            contains_sensitive,
            destination,
            timestamp: crate::time::get_timestamp(),
        };
        self.data_transfer_log.push(transfer);
    }

    pub fn add_suspicious_connection(&mut self, ip: [u8; 4], port: u16, data_size: usize, threat_score: u8) {
        let connection = SuspiciousConnection {
            remote_ip: ip,
            remote_port: port,
            data_size,
            timestamp: crate::time::get_timestamp(),
            threat_score,
        };
        self.suspicious_connections.push(connection);
    }

    pub fn block_ip(&mut self, ip: [u8; 4]) {
        if !self.blocked_ips.contains(&ip) {
            self.blocked_ips.push(ip);
        }
    }

    pub fn is_ip_blocked(&self, ip: [u8; 4]) -> bool {
        self.blocked_ips.contains(&ip)
    }

    pub fn get_transfer_statistics(&self) -> NetworkStatistics {
        let mut outbound_count = 0;
        let mut inbound_count = 0;
        let mut sensitive_transfers = 0;

        for transfer in &self.data_transfer_log {
            match transfer.direction {
                TransferDirection::Outbound => outbound_count += 1,
                TransferDirection::Inbound => inbound_count += 1,
            }
            if transfer.contains_sensitive {
                sensitive_transfers += 1;
            }
        }

        NetworkStatistics {
            outbound_transfers: outbound_count,
            inbound_transfers: inbound_count,
            sensitive_transfers,
            suspicious_connections: self.suspicious_connections.len(),
            blocked_ips: self.blocked_ips.len(),
        }
    }
}

pub struct NetworkStatistics {
    pub outbound_transfers: usize,
    pub inbound_transfers: usize,
    pub sensitive_transfers: usize,
    pub suspicious_connections: usize,
    pub blocked_ips: usize,
}

static mut DATA_LEAK_DETECTOR: Option<DataLeakDetector> = None;
static mut NETWORK_MONITOR: Option<NetworkMonitor> = None;

pub fn init_data_leak_detection() {
    unsafe {
        DATA_LEAK_DETECTOR = Some(DataLeakDetector::new());
        NETWORK_MONITOR = Some(NetworkMonitor::new());
    }
}

pub fn scan_process_memory(process_id: u32, memory_base: *const u8, size: usize) -> Vec<DataLeakEvent> {
    unsafe {
        if let Some(ref mut detector) = DATA_LEAK_DETECTOR {
            let memory_slice = slice::from_raw_parts(memory_base, size);
            detector.scan_memory_region(memory_slice, process_id)
        } else {
            Vec::new()
        }
    }
}

pub fn monitor_network_data(data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> Option<DataLeakEvent> {
    unsafe {
        if let Some(ref mut detector) = DATA_LEAK_DETECTOR {
            detector.monitor_network_traffic(data, dest_ip, dest_port)
        } else {
            None
        }
    }
}

pub fn monitor_file_access(file_path: &str, data: &[u8], operation: FileOperation) -> Option<DataLeakEvent> {
    unsafe {
        if let Some(ref mut detector) = DATA_LEAK_DETECTOR {
            detector.monitor_file_operations(file_path, data, operation)
        } else {
            None
        }
    }
}

pub fn get_leak_statistics() -> Option<DataLeakStatistics> {
    unsafe {
        DATA_LEAK_DETECTOR.as_ref().map(|d| d.get_violation_statistics())
    }
}

pub fn get_network_statistics() -> Option<NetworkStatistics> {
    unsafe {
        NETWORK_MONITOR.as_ref().map(|n| n.get_transfer_statistics())
    }
}

pub fn encrypt_sensitive_memory(data: &[u8], key: &[u8; 32]) -> Result<usize, &'static str> {
    unsafe {
        if let Some(ref mut detector) = DATA_LEAK_DETECTOR {
            detector.encrypt_sensitive_data(data, key)
        } else {
            Err("Data leak detector not initialized")
        }
    }
}

pub fn decrypt_sensitive_memory(index: usize, key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
    unsafe {
        if let Some(ref mut detector) = DATA_LEAK_DETECTOR {
            detector.decrypt_sensitive_data(index, key)
        } else {
            Err("Data leak detector not initialized")
        }
    }
}

/// Scan packet for personally identifiable information
pub fn scan_packet_for_pii(packet: &crate::network::PacketBuffer) -> bool {
    unsafe {
        if let Some(ref detector) = DATA_LEAK_DETECTOR {
            detector.scan_data_for_leaks(&packet.data, &packet.metadata.destination)
        } else {
            false
        }
    }
}

/// Check if data contains sensitive patterns
pub fn contains_sensitive_patterns(data: &[u8]) -> bool {
    unsafe {
        if let Some(ref detector) = DATA_LEAK_DETECTOR {
            detector.scan_data_for_leaks(data, "unknown")
        } else {
            false
        }
    }
}

/// Real memory scanner - scans actual physical and virtual memory
pub fn scan_memory() {
    crate::log::logger::log_info!("Starting real memory scan for data leaks");
    
    unsafe {
        if let Some(ref mut detector) = DATA_LEAK_DETECTOR {
            let mut total_scanned = 0usize;
            let mut violations = 0usize;
            
            // Get physical memory map from bootloader
            if let Some(memory_map) = crate::memory::get_memory_map() {
                for region in memory_map.iter().filter(|r| matches!(r.memory_type, crate::memory::MemoryType::Usable)) {
                    let phys_start = region.base_address;
                    let size = region.size;
                    
                    // Map physical memory to virtual addresses for scanning
                    if let Ok(virt_addr) = crate::memory::map_physical_memory(phys_start, size) {
                        let memory_slice = core::slice::from_raw_parts(
                            virt_addr.as_ptr::<u8>(), 
                            size as usize
                        );
                        
                        // Scan this memory region
                        let events = detector.scan_memory_region(memory_slice, 0);
                        violations += events.len();
                        total_scanned += size as usize;
                        
                        for event in events {
                            crate::log::logger::log_warn!("Memory leak at 0x{:x}: sensitive pattern detected", 
                                phys_start);
                        }
                        
                        // Unmap after scanning
                        crate::memory::unmap_physical_memory(virt_addr, size);
                    }
                }
            }
            
            // Scan kernel heap allocations
            let heap_allocations = crate::memory::heap::get_all_allocations();
            for allocation in heap_allocations {
                let alloc_slice = core::slice::from_raw_parts(
                    allocation.ptr as *const u8,
                    allocation.size
                );
                
                let events = detector.scan_memory_region(alloc_slice, 0);
                violations += events.len();
                total_scanned += allocation.size;
                
                for event in events {
                    crate::log::logger::log_warn!("Heap leak at 0x{:x}: {} bytes", 
                        allocation.ptr as usize, event.data_size);
                }
            }
            
            // Scan process memory via process memory regions
            for process in crate::process::get_all_processes() {
                // Process memory scanning would require page table access
                // Skip process memory scanning for now
                crate::log::logger::log_debug!("Process memory scan skipped for process {}", process.pid);
            }
            
            // Scan DMA buffers from device drivers (placeholder - no DMA buffer API)
            for device in crate::drivers::get_all_devices() {
                // Skip DMA scanning - would need device-specific buffer access
                crate::log::logger::log_debug!("DMA scan skipped for device {}", device.name);
            }
            
            // Scan network packet buffers
            if let Some(net_manager) = crate::network::get_network_stack() {
                // Network buffer scanning would need interface-specific access
                crate::log::logger::log_debug!("Network buffer scan attempted - skipped");
            }
            
            // Scan file system cache
            let fs_cache = crate::filesystem::get_cache_manager();
            for cache_entry in fs_cache.all_entries() {
                let cache_slice = core::slice::from_raw_parts(
                    cache_entry.data_ptr(),
                    cache_entry.size()
                );
                
                let events = detector.scan_memory_region(cache_slice, 0xAAAA);
                violations += events.len();
                total_scanned += cache_entry.size();
                
                for event in events {
                    crate::log::logger::log_warn!("FS cache leak in {}: sensitive data", 
                        cache_entry.path());
                }
            }
            
            crate::log::logger::log_info!("Memory scan complete: {} violations in {} bytes scanned", 
                violations, total_scanned);
        }
    }
}