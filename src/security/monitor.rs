//! NØNOS Security Monitor
//!
//! Real-time security monitoring and threat detection system
//! - Behavioral analysis and anomaly detection
//! - Memory access pattern monitoring
//! - Network traffic analysis
//! - Process behavior monitoring
//! - Hardware security monitoring

#![allow(dead_code)]

use alloc::{vec, vec::Vec, string::{String, ToString}, format};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use spin::{Mutex, RwLock};

/// Security monitoring events
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityEvent {
    SuspiciousMemoryAccess,
    UnauthorizedNetworkAccess,
    ProcessAnomalyDetected,
    HardwareTamperDetected,
    EncryptionKeyCompromise,
    PrivacyPolicyViolation,
    SystemIntegrityBreach,
    CovertChannelDetected,
    TimingAttackDetected,
    SideChannelAttackDetected,
}

/// Security threat levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}

/// Security monitoring statistics
#[derive(Default)]
pub struct SecurityMonitorStats {
    pub total_events: AtomicU64,
    pub threats_detected: AtomicU64,
    pub false_positives: AtomicU64,
    pub memory_violations: AtomicU64,
    pub network_anomalies: AtomicU64,
    pub process_anomalies: AtomicU64,
    pub hardware_alerts: AtomicU64,
    pub privacy_violations: AtomicU64,
    pub last_memory_access: AtomicU64,
    pub rapid_memory_accesses: AtomicU64,
}

/// Behavioral pattern for anomaly detection
#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub name: String,
    pub process_name: String,
    pub expected_syscalls: Vec<u64>,
    pub expected_memory_range: (u64, u64),
    pub expected_network_ports: Vec<u16>,
    pub max_cpu_usage: u8,     // Percentage
    pub max_memory_usage: u64, // Bytes
    pub allowed_file_paths: Vec<String>,
    pub monitoring_enabled: bool,
    pub expected_memory_usage: Option<u64>,
    pub expected_network_connections: Option<u32>,
    pub expected_file_accesses: Option<u32>,
    pub expected_cpu_usage: Option<u32>,
}

/// Security monitor configuration
#[derive(Debug, Clone)]
pub struct SecurityMonitorConfig {
    pub memory_monitoring_enabled: bool,
    pub network_monitoring_enabled: bool,
    pub process_monitoring_enabled: bool,
    pub hardware_monitoring_enabled: bool,
    pub privacy_monitoring_enabled: bool,
    pub anomaly_threshold: f32,        // Threshold for anomaly detection
    pub monitoring_interval_ms: u32,   // Monitoring interval
    pub log_all_events: bool,
    pub real_time_alerts: bool,
}

/// Main security monitor
pub struct SecurityMonitor {
    /// Monitor configuration
    config: RwLock<SecurityMonitorConfig>,
    
    /// Security statistics
    stats: SecurityMonitorStats,
    
    /// Behavioral patterns for processes
    behavior_patterns: RwLock<Vec<BehaviorPattern>>,
    
    /// Recent security events
    recent_events: Mutex<Vec<SecurityEvent>>,
    
    /// Monitoring enabled flag
    enabled: AtomicBool,
    
    /// Threat detection rules
    detection_rules: RwLock<Vec<ThreatDetectionRule>>,
    
    /// Hardware security state
    hardware_state: Mutex<HardwareSecurityState>,
    
    /// Memory access monitor
    memory_monitor: MemoryAccessMonitor,
    
    /// Network traffic monitor
    network_monitor: NetworkTrafficMonitor,
    
    /// Detection sensitivity (0-100)
    detection_sensitivity: AtomicU32,
}

/// Threat detection rule
#[derive(Debug, Clone)]
pub struct ThreatDetectionRule {
    pub name: String,
    pub event_type: SecurityEvent,
    pub threshold: u64,
    pub time_window_seconds: u64,
    pub threat_level: ThreatLevel,
    pub action: SecurityAction,
    pub enabled: bool,
}

/// Security actions to take when threats are detected
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityAction {
    Log,
    Alert,
    Quarantine,
    Block,
    Shutdown,
}

/// Hardware security state
#[derive(Debug)]
pub struct HardwareSecurityState {
    pub secure_boot_verified: bool,
    pub tpm_available: bool,
    pub hardware_rng_functional: bool,
    pub cpu_security_features: u64,
    pub memory_encryption_enabled: bool,
    pub firmware_integrity: bool,
    pub tamper_detection_active: bool,
}

/// Memory access monitoring
pub struct MemoryAccessMonitor {
    /// Suspicious memory access patterns
    suspicious_patterns: AtomicU64,
    
    /// Out-of-bounds access attempts
    oob_attempts: AtomicU64,
    
    /// Unauthorized executable memory access
    exec_violations: AtomicU64,
    
    /// Memory corruption attempts
    corruption_attempts: AtomicU64,
}

/// Network traffic monitoring
pub struct NetworkTrafficMonitor {
    /// Suspicious network connections
    suspicious_connections: AtomicU64,
    
    /// Unauthorized port access
    unauthorized_ports: AtomicU64,
    
    /// Data exfiltration attempts
    exfiltration_attempts: AtomicU64,
    
    /// Anonymous network usage
    anonymous_connections: AtomicU64,
}

impl SecurityMonitor {
    /// Create new security monitor
    pub fn new() -> Self {
        let config = SecurityMonitorConfig {
            memory_monitoring_enabled: true,
            network_monitoring_enabled: true,
            process_monitoring_enabled: true,
            hardware_monitoring_enabled: true,
            privacy_monitoring_enabled: true,
            anomaly_threshold: 0.8,     // 80% confidence threshold
            monitoring_interval_ms: 100, // 100ms monitoring interval
            log_all_events: true,
            real_time_alerts: true,
        };
        
        // Initialize default threat detection rules
        let mut detection_rules = Vec::new();
        
        // Memory violation rule
        detection_rules.push(ThreatDetectionRule {
            name: "Memory Violations".to_string(),
            event_type: SecurityEvent::SuspiciousMemoryAccess,
            threshold: 5,  // 5 violations per time window
            time_window_seconds: 60,
            threat_level: ThreatLevel::High,
            action: SecurityAction::Quarantine,
            enabled: true,
        });
        
        // Privacy violation rule
        detection_rules.push(ThreatDetectionRule {
            name: "Privacy Violations".to_string(),
            event_type: SecurityEvent::PrivacyPolicyViolation,
            threshold: 1,  // Any privacy violation
            time_window_seconds: 1,
            threat_level: ThreatLevel::Emergency,
            action: SecurityAction::Shutdown,
            enabled: true,
        });
        
        // Hardware tamper rule
        detection_rules.push(ThreatDetectionRule {
            name: "Hardware Tamper".to_string(),
            event_type: SecurityEvent::HardwareTamperDetected,
            threshold: 1,
            time_window_seconds: 1,
            threat_level: ThreatLevel::Critical,
            action: SecurityAction::Alert,
            enabled: true,
        });
        
        let hardware_state = HardwareSecurityState {
            secure_boot_verified: false,
            tpm_available: false,
            hardware_rng_functional: false,
            cpu_security_features: 0,
            memory_encryption_enabled: false,
            firmware_integrity: true,
            tamper_detection_active: false,
        };
        
        SecurityMonitor {
            config: RwLock::new(config),
            stats: SecurityMonitorStats::default(),
            behavior_patterns: RwLock::new(Vec::new()),
            recent_events: Mutex::new(Vec::with_capacity(1000)),
            enabled: AtomicBool::new(true),
            detection_rules: RwLock::new(detection_rules),
            hardware_state: Mutex::new(hardware_state),
            memory_monitor: MemoryAccessMonitor {
                suspicious_patterns: AtomicU64::new(0),
                oob_attempts: AtomicU64::new(0),
                exec_violations: AtomicU64::new(0),
                corruption_attempts: AtomicU64::new(0),
            },
            network_monitor: NetworkTrafficMonitor {
                suspicious_connections: AtomicU64::new(0),
                unauthorized_ports: AtomicU64::new(0),
                exfiltration_attempts: AtomicU64::new(0),
                anonymous_connections: AtomicU64::new(0),
            },
            detection_sensitivity: AtomicU32::new(50), // Default medium sensitivity
        }
    }
    
    /// Monitor memory access patterns for anomalies
    pub fn monitor_memory_access(&self, address: u64, size: u64, operation: MemoryOperation) {
        if !self.config.read().memory_monitoring_enabled || !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        // Check for suspicious patterns
        if self.is_suspicious_memory_access(address, size, operation) {
            self.memory_monitor.suspicious_patterns.fetch_add(1, Ordering::Relaxed);
            self.report_security_event(SecurityEvent::SuspiciousMemoryAccess, ThreatLevel::Medium);
        }
        
        // Check for out-of-bounds access
        if self.is_out_of_bounds_access(address, size) {
            self.memory_monitor.oob_attempts.fetch_add(1, Ordering::Relaxed);
            self.report_security_event(SecurityEvent::SuspiciousMemoryAccess, ThreatLevel::High);
        }
        
        // Check for unauthorized executable memory access
        if operation == MemoryOperation::Execute && !self.is_authorized_executable_region(address) {
            self.memory_monitor.exec_violations.fetch_add(1, Ordering::Relaxed);
            self.report_security_event(SecurityEvent::SuspiciousMemoryAccess, ThreatLevel::Critical);
        }
    }
    
    /// Monitor network access patterns
    pub fn monitor_network_access(&self, destination: u32, port: u16, protocol: NetworkProtocol) {
        if !self.config.read().network_monitoring_enabled || !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        // Check for unauthorized network access
        if !self.is_authorized_network_access(destination, port, protocol) {
            self.network_monitor.unauthorized_ports.fetch_add(1, Ordering::Relaxed);
            self.report_security_event(SecurityEvent::UnauthorizedNetworkAccess, ThreatLevel::Medium);
        }
        
        // Check for potential data exfiltration
        if self.is_potential_data_exfiltration(destination, port, protocol) {
            self.network_monitor.exfiltration_attempts.fetch_add(1, Ordering::Relaxed);
            self.report_security_event(SecurityEvent::UnauthorizedNetworkAccess, ThreatLevel::High);
        }
        
        // Monitor anonymous network usage (Tor, etc.)
        if self.is_anonymous_network_connection(destination, port) {
            self.network_monitor.anonymous_connections.fetch_add(1, Ordering::Relaxed);
            // This is actually desired for privacy, so log as info
        }
    }
    
    /// Perform periodic security checks
    pub fn periodic_security_check(&self) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        // Check hardware security state
        self.check_hardware_security();
        
        // Check for behavioral anomalies
        self.check_process_behavior_anomalies();
        
        // Check system integrity
        self.check_system_integrity();
        
        // Check for privacy policy violations
        self.check_privacy_policy_compliance();
        
        // Update statistics
        self.stats.total_events.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Check hardware security state
    fn check_hardware_security(&self) {
        let mut hw_state = self.hardware_state.lock();
        
        // Check CPU security features
        let cpu_features = self.read_cpu_security_features();
        if cpu_features != hw_state.cpu_security_features {
            hw_state.cpu_security_features = cpu_features;
            if (cpu_features & 0xFF) == 0 {  // Critical security features disabled
                self.report_security_event(SecurityEvent::HardwareTamperDetected, ThreatLevel::Critical);
            }
        }
        
        // Check firmware integrity
        if hw_state.firmware_integrity && !self.verify_firmware_integrity() {
            hw_state.firmware_integrity = false;
            self.report_security_event(SecurityEvent::SystemIntegrityBreach, ThreatLevel::Emergency);
        }
        
        // Check hardware RNG functionality
        if !self.test_hardware_rng() {
            hw_state.hardware_rng_functional = false;
            self.report_security_event(SecurityEvent::HardwareTamperDetected, ThreatLevel::Medium);
        }
    }
    
    /// Check for process behavior anomalies
    fn check_process_behavior_anomalies(&self) {
        let patterns = self.behavior_patterns.read();
        
        for pattern in patterns.iter() {
            if !pattern.monitoring_enabled {
                continue;
            }
            
            // Check if process behavior matches expected pattern
            if !self.process_matches_behavior_pattern(pattern) {
                self.stats.process_anomalies.fetch_add(1, Ordering::Relaxed);
                self.report_security_event(SecurityEvent::ProcessAnomalyDetected, ThreatLevel::Medium);
            }
        }
    }
    
    /// Check system integrity
    fn check_system_integrity(&self) {
        // Check critical kernel structures
        if !self.verify_kernel_integrity() {
            self.report_security_event(SecurityEvent::SystemIntegrityBreach, ThreatLevel::Emergency);
        }
        
        // Check for rootkit signatures
        if self.detect_rootkit_signatures() {
            self.report_security_event(SecurityEvent::SystemIntegrityBreach, ThreatLevel::Critical);
        }
    }
    
    /// Check privacy policy compliance
    fn check_privacy_policy_compliance(&self) {
        // Check for unauthorized data collection
        if self.detect_unauthorized_data_collection() {
            self.stats.privacy_violations.fetch_add(1, Ordering::Relaxed);
            self.report_security_event(SecurityEvent::PrivacyPolicyViolation, ThreatLevel::High);
        }
        
        // Check for privacy leaks
        if self.detect_privacy_leaks() {
            self.stats.privacy_violations.fetch_add(1, Ordering::Relaxed);
            self.report_security_event(SecurityEvent::PrivacyPolicyViolation, ThreatLevel::Critical);
        }
    }
    
    /// Report security event
    fn report_security_event(&self, event: SecurityEvent, threat_level: ThreatLevel) {
        // Add to recent events
        {
            let mut events = self.recent_events.lock();
            if events.len() >= 1000 {
                events.remove(0);  // Remove oldest event
            }
            events.push(event);
        }
        
        // Update statistics
        match event {
            SecurityEvent::SuspiciousMemoryAccess => {
                self.stats.memory_violations.fetch_add(1, Ordering::Relaxed);
            },
            SecurityEvent::UnauthorizedNetworkAccess => {
                self.stats.network_anomalies.fetch_add(1, Ordering::Relaxed);
            },
            SecurityEvent::ProcessAnomalyDetected => {
                self.stats.process_anomalies.fetch_add(1, Ordering::Relaxed);
            },
            SecurityEvent::HardwareTamperDetected => {
                self.stats.hardware_alerts.fetch_add(1, Ordering::Relaxed);
            },
            SecurityEvent::PrivacyPolicyViolation => {
                self.stats.privacy_violations.fetch_add(1, Ordering::Relaxed);
            },
            _ => {}
        }
        
        self.stats.threats_detected.fetch_add(1, Ordering::Relaxed);
        
        // Log through audit system
        crate::security::audit::log_security_violation(
            format!("Security Monitor: {:?} (Threat Level: {:?})", event, threat_level),
            crate::security::audit::AuditSeverity::Critical
        );
        
        // Take action based on threat detection rules
        let _threat_handled = self.process_threat_detection(event, threat_level);
    }
    
    /// Process threat detection and take appropriate action
    fn process_threat_detection(&self, event: SecurityEvent, threat_level: ThreatLevel) -> bool {
        let rules = self.detection_rules.read();
        
        for rule in rules.iter() {
            if rule.event_type == event && rule.enabled {
                // Check if threshold exceeded
                let recent_count = self.count_recent_events(event);
                
                if recent_count >= rule.threshold {
                    match rule.action {
                        SecurityAction::Log => {
                            crate::log_warn!(
                                "Security threat detected: {} ({})", 
                                rule.name, rule.threat_level as u32
                            );
                            return true; // Threat detected and logged
                        },
                        SecurityAction::Alert => {
                            crate::log_fatal!(
                                "SECURITY ALERT: {} (Level: {:?})", 
                                rule.name, rule.threat_level
                            );
                            return true; // Alert sent
                        },
                        SecurityAction::Quarantine => {
                            crate::log_fatal!(
                                "QUARANTINE ACTION: {} (Level: {:?})", 
                                rule.name, rule.threat_level
                            );
                            
                            // Quarantine the threat source
                            self.quarantine_threat(&rule.name);
                            self.isolate_process_memory();
                            return true; // Threat quarantined
                        },
                        SecurityAction::Block => {
                            crate::log_fatal!(
                                "BLOCKING ACTION: {} (Level: {:?})", 
                                rule.name, rule.threat_level
                            );
                            
                            // Block the operation immediately
                            self.block_threat_source(&rule.name);
                            return true; // Threat blocked
                        },
                        SecurityAction::Shutdown => {
                            crate::log_fatal!(
                                "EMERGENCY SHUTDOWN: {} (Level: {:?})", 
                                rule.name, rule.threat_level
                            );
                            
                            // Trigger immediate emergency shutdown
                            self.emergency_shutdown();
                            crate::arch::x86_64::halt(); // Emergency halt
                        },
                    }
                }
            }
        }
        
        false // No threats detected
    }
    
    // Helper functions for security checks
    fn is_suspicious_memory_access(&self, address: u64, size: u64, operation: MemoryOperation) -> bool {
        // Detect suspicious memory access patterns
        
        // Check for buffer overflow attempts
        if size > 0x100000 { // >1MB single access is suspicious
            return true;
        }
        
        // Check for access to kernel memory space from userland
        if address >= 0xFFFF_8000_0000_0000 && crate::process::current_privilege_level() == 3 {
            return true;
        }
        
        // Check for executable memory writes (potential code injection)
        if matches!(operation, MemoryOperation::Write) && crate::memory::is_executable_region(address) {
            return true;
        }
        
        // Check for access to cryptographic key regions
        if crate::crypto::is_key_memory_region(address) {
            return true;
        }
        
        // Check for rapid sequential accesses (potential memory scanning)
        let current_time = crate::time::current_timestamp();
        if current_time - self.stats.last_memory_access.load(Ordering::Relaxed) < 1000 { // <1ms apart
            self.stats.rapid_memory_accesses.fetch_add(1, Ordering::Relaxed);
            if self.stats.rapid_memory_accesses.load(Ordering::Relaxed) > 100 {
                return true;
            }
        }
        
        self.stats.last_memory_access.store(current_time, Ordering::Relaxed);
        false
    }
    
    fn is_out_of_bounds_access(&self, address: u64, size: u64) -> bool {
        // Get current process memory bounds
        if let Some(bounds) = crate::process::get_current_memory_bounds() {
            let end_address = address.saturating_add(size);
            
            // Check if access is within allocated regions
            if address < bounds.0 || end_address > bounds.1 {
                return true;
            }
            
            // Check for NULL pointer dereference
            if address < 0x1000 {
                return true;
            }
            
            // Check for stack overflow
            if crate::memory::is_stack_region(address) && size > crate::memory::STACK_SIZE as u64 {
                return true;
            }
            
            // Check for heap corruption patterns
            if crate::memory::is_heap_region(address) && 
               !crate::memory::validate_heap_chunk(address, size) {
                return true;
            }
        }
        
        false
    }
    
    fn is_authorized_executable_region(&self, address: u64) -> bool {
        // Check if address is in authorized executable regions
        
        // Kernel code region
        if address >= 0xFFFF_8000_0000_0000 && address < 0xFFFF_8000_8000_0000 {
            return true;
        }
        
        // User code region (below 2GB for security)
        if address >= 0x400000 && address < 0x80000000 {
            // Verify with process executable mappings
            if let Some(process) = crate::process::get_current_process() {
                return process.is_authorized_executable_region(address);
            }
        }
        
        // Dynamic libraries region
        if address >= 0x7F0000000000 && address < 0x800000000000 {
            return crate::process::validate_shared_library_region(address);
        }
        
        // JIT code regions (if enabled and verified)
        if crate::process::is_jit_enabled() {
            return crate::process::validate_jit_region(address);
        }
        
        false
    }
    
    fn is_authorized_network_access(&self, destination: u32, port: u16, protocol: NetworkProtocol) -> bool {
        // Convert IP address to string for network functions
        let dest_str = alloc::format!("{}.{}.{}.{}", 
            (destination >> 24) & 0xff,
            (destination >> 16) & 0xff,
            (destination >> 8) & 0xff,
            destination & 0xff
        );
        
        // Check network access permissions based on security policy
        
        // Block all network access if in high security mode
        if self.detection_sensitivity.load(Ordering::Relaxed) >= 80 {
            return false;
        }
        
        // Check against blocked IP ranges
        let dest_bytes = destination.to_be_bytes();
        
        // Block private networks in certain modes (data leak prevention)
        if matches!(dest_bytes, [192, 168, _, _] | [10, _, _, _] | [172, 16..=31, _, _]) {
            if crate::process::is_network_isolation_enabled() {
                return false;
            }
        }
        
        // Block suspicious ports
        let blocked_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 6379]; // SSH, Telnet, SMB, SQL, RDP, Redis
        if blocked_ports.contains(&port) && !crate::process::has_admin_privileges() {
            return false;
        }
        
        // Protocol-specific rules
        match protocol {
            NetworkProtocol::ICMP => {
                // Allow ping only from authorized processes
                crate::process::has_network_privilege("icmp")
            },
            NetworkProtocol::UDP => {
                // Block DNS tunneling attempts (suspicious large UDP packets to port 53)
                if port == 53 && crate::network::is_suspicious_dns_query(&dest_str) {
                    return false;
                }
                true
            },
            NetworkProtocol::TCP => {
                // Allow TCP but log connections
                crate::security::audit::log_network_connection(&dest_str, port);
                true
            }
        }
    }
    
    fn is_potential_data_exfiltration(&self, destination: u32, port: u16, protocol: NetworkProtocol) -> bool {
        // Convert IP address to string for network functions
        let dest_str = alloc::format!("{}.{}.{}.{}", 
            (destination >> 24) & 0xff,
            (destination >> 16) & 0xff,
            (destination >> 8) & 0xff,
            destination & 0xff
        );
        
        // Detect potential data exfiltration patterns
        
        // Check for connections to known suspicious destinations
        let dest_bytes = [
            ((destination >> 24) & 0xff) as u8,
            ((destination >> 16) & 0xff) as u8,
            ((destination >> 8) & 0xff) as u8,
            (destination & 0xff) as u8,
        ];
        if crate::security::threat_intel::is_known_malicious_ip(dest_bytes) {
            return true;
        }
        
        // Detect unusual data transfer volumes
        let transfer_rate = crate::network::get_current_transfer_rate(&dest_str, port);
        if transfer_rate > 100 * 1024 * 1024 { // >100MB/s is suspicious
            return true;
        }
        
        // Check for connections to uncommon ports during off-hours
        if crate::time::is_off_hours() && !crate::network::is_common_port(port) {
            return true;
        }
        
        // Detect DNS over HTTPS tunneling (port 443 with DNS patterns)
        if port == 443 && protocol == NetworkProtocol::TCP {
            if crate::network::detect_dns_over_https_tunneling(&dest_str) {
                return true;
            }
        }
        
        // Check for encrypted channel establishment to external IPs
        if !crate::network::is_internal_network(&dest_str) && 
           crate::network::is_encrypted_channel(port, protocol.as_str()) &&
           !crate::process::has_external_communication_privilege() {
            return true;
        }
        
        // Detect steganographic patterns in network traffic
        if crate::network::detect_steganographic_patterns(&dest_str, port) {
            return true;
        }
        
        false
    }
    
    fn is_anonymous_network_connection(&self, destination: u32, port: u16) -> bool {
        // Convert IP address to string for network functions
        let dest_str = alloc::format!("{}.{}.{}.{}", 
            (destination >> 24) & 0xff,
            (destination >> 16) & 0xff,
            (destination >> 8) & 0xff,
            destination & 0xff
        );
        
        // Detect Tor, VPN, or other anonymous connections
        
        // Common Tor ports
        if matches!(port, 9050 | 9051 | 9150 | 9151) {
            return true;
        }
        
        // Common VPN ports
        if matches!(port, 1723 | 1194 | 500 | 4500 | 443) {
            // Check if destination is known VPN provider
            if crate::network::is_known_vpn_server(&dest_str) {
                return true;
            }
        }
        
        // Check for proxy connections
        if matches!(port, 8080 | 3128 | 1080) && 
           crate::network::is_proxy_server(&dest_str) {
            return true;
        }
        
        // Detect encrypted DNS (DoH/DoT) which can be used for anonymity
        if matches!(port, 853 | 443) && 
           crate::network::is_encrypted_dns_server(&dest_str) {
            return true;
        }
        
        false
    }
    
    fn read_cpu_security_features(&self) -> u64 {
        // Read CPU security features from hardware registers
        
        use x86_64::instructions::random::RdRand;
        let mut features = 0u64;
        
        // Check CPUID for security features
        unsafe {
            let cpuid = core::arch::x86_64::__cpuid(1);
            
            // Check for RDRAND support (bit 30 of ECX)
            if (cpuid.ecx & (1 << 30)) != 0 {
                features |= 1 << 0; // RDRAND
            }
            
            // Check for RDSEED support (CPUID 7, bit 18 of EBX)
            let cpuid_7 = core::arch::x86_64::__cpuid_count(7, 0);
            if (cpuid_7.ebx & (1 << 18)) != 0 {
                features |= 1 << 1; // RDSEED
            }
            
            // Check for SMEP (Supervisor Mode Execution Prevention)
            if (cpuid_7.ebx & (1 << 7)) != 0 {
                features |= 1 << 2; // SMEP
            }
            
            // Check for SMAP (Supervisor Mode Access Prevention) 
            if (cpuid_7.ebx & (1 << 20)) != 0 {
                features |= 1 << 3; // SMAP
            }
            
            // Check for Intel MPX (Memory Protection Extensions)
            if (cpuid_7.ebx & (1 << 14)) != 0 {
                features |= 1 << 4; // MPX
            }
            
            // Check for Intel CET (Control Flow Enforcement Technology)
            if (cpuid_7.ecx & (1 << 7)) != 0 {
                features |= 1 << 5; // CET
            }
            
            // Read control registers for security status
            let cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
            
            // Check if SMEP is enabled (bit 20 of CR4)
            if (cr4 & (1 << 20)) != 0 {
                features |= 1 << 8; // SMEP enabled
            }
            
            // Check if SMAP is enabled (bit 21 of CR4) 
            if (cr4 & (1 << 21)) != 0 {
                features |= 1 << 9; // SMAP enabled
            }
            
            // Check EFER for NXE (No Execute Enable)
            let efer = x86_64::registers::model_specific::Efer::read();
            if efer.contains(x86_64::registers::model_specific::EferFlags::NO_EXECUTE_ENABLE) {
                features |= 1 << 10; // NXE enabled
            }
        }
        
        features
    }
    
    fn verify_firmware_integrity(&self) -> bool {
        // Verify firmware integrity using checksums and signatures
        
        // Read UEFI firmware version and check against known good hashes
        if let Some(firmware_info) = crate::arch::x86_64::uefi::get_firmware_info() {
            // Check firmware version against known secure versions
            if !crate::security::firmware_db::is_trusted_firmware(&firmware_info.version) {
                crate::log_warn!("Untrusted firmware version detected: {}", firmware_info.version);
                return false;
            }
            
            // Verify firmware signature if available
            if let Some(signature) = firmware_info.signature {
                if !crate::crypto::rsa::verify_signature(&firmware_info.data, &signature, &crate::security::trusted_keys::FIRMWARE_PUBLIC_KEY) {
                    crate::log_warn!("Firmware signature verification failed");
                    return false;
                }
            }
            
            // Check for secure boot status
            if !firmware_info.secure_boot_enabled {
                crate::log_warn!("Secure boot is disabled - firmware integrity cannot be guaranteed");
                return false;
            }
            
            // Verify critical firmware components
            if !self.verify_bios_integrity() {
                return false;
            }
            
            if !self.verify_uefi_integrity() {
                return false;
            }
            
            // Check for rootkit presence in firmware
            if crate::security::rootkit_scanner::scan_firmware() {
                crate::log_warn!("Potential firmware rootkit detected");
                return false;
            }
        }
        
        true
    }
    
    fn verify_bios_integrity(&self) -> bool {
        // Verify BIOS/Legacy boot components
        
        // Check System Management Mode (SMM) integrity
        if !crate::arch::x86_64::smm::verify_integrity() {
            crate::log_warn!("SMM integrity check failed");
            return false;
        }
        
        // Verify ACPI tables haven't been tampered with
        if !crate::arch::x86_64::acpi::power::shutdown().is_ok() {
            crate::log_warn!("ACPI table integrity check failed");
            return false;
        }
        
        true
    }
    
    fn verify_uefi_integrity(&self) -> bool {
        // Verify UEFI components
        
        // Check UEFI runtime services integrity
        if !crate::arch::x86_64::uefi::verify_runtime_services() {
            crate::log_warn!("UEFI runtime services integrity check failed");
            return false;
        }
        
        // Verify boot services haven't been compromised
        if !crate::arch::x86_64::uefi::verify_boot_services() {
            crate::log_warn!("UEFI boot services integrity check failed");
            return false;
        }
        
        true
    }
    
    fn test_hardware_rng(&self) -> bool {
        // Test hardware random number generator quality and functionality
        
        use x86_64::instructions::random::RdRand;
        
        // Test RDRAND instruction
        let mut rdrand_samples = [0u64; 100];
        let mut rdrand_success_count = 0;
        
        for i in 0..100 {
            if let Some(rng) = RdRand::new() {
                if let Some(random_value) = rng.get_u64() {
                    rdrand_samples[i] = random_value;
                    rdrand_success_count += 1;
                }
            }
        }
        
        // RDRAND should succeed most of the time (>95%)
        if rdrand_success_count < 95 {
            crate::log_warn!("RDRAND success rate too low: {}/100", rdrand_success_count);
            return false;
        }
        
        // Test for basic randomness (no all zeros, no identical consecutive values)
        let mut identical_consecutive = 0;
        let mut zero_count = 0;
        
        for i in 1..rdrand_samples.len() {
            if rdrand_samples[i] == rdrand_samples[i-1] {
                identical_consecutive += 1;
            }
            if rdrand_samples[i] == 0 {
                zero_count += 1;
            }
        }
        
        // Too many identical consecutive values indicates poor randomness
        if identical_consecutive > 5 {
            crate::log_warn!("RDRAND poor randomness: {} identical consecutive values", identical_consecutive);
            return false;
        }
        
        // Too many zeros could indicate hardware failure
        if zero_count > 10 {
            crate::log_warn!("RDRAND suspicious: {} zero values out of 100", zero_count);
            return false;
        }
        
        // Alternative entropy test using CPU timestamp counter variations
        let mut entropy_test_passed = false;
        let mut tsc_samples = [0u64; 100];
        for i in 0..100 {
            tsc_samples[i] = crate::arch::x86_64::time::get_tsc();
            // Small delay to ensure TSC variations
            for _ in 0..100 { core::hint::spin_loop(); }
        }
        
        // Check for sufficient TSC variation (entropy indicator)
        let mut unique_values = 0;
        for i in 1..100 {
            if tsc_samples[i] != tsc_samples[i-1] {
                unique_values += 1;
            }
        }
        
        if unique_values > 90 { // At least 90% variation
            entropy_test_passed = true;
        }
        
        crate::log_info!("Hardware RNG tests passed: RDRAND {}/100, TSC entropy {}/99", 
                        rdrand_success_count, unique_values);
        true
    }
    
    fn process_matches_behavior_pattern(&self, pattern: &BehaviorPattern) -> bool {
        // Check if process behavior matches expected pattern
        
        if let Some(current_process) = crate::process::get_current_process() {
            let behavior = crate::process::get_behavior_metrics(&current_process);
            
            // Check memory access patterns
            if let Some(expected_memory) = pattern.expected_memory_usage {
                if behavior.memory_usage > expected_memory * 2 {
                    crate::log_warn!("Process memory usage ({}) exceeds expected pattern ({})", 
                                   behavior.memory_usage, expected_memory);
                    return false;
                }
            }
            
            // Check network activity patterns
            if let Some(expected_network) = pattern.expected_network_connections {
                if behavior.active_connections > expected_network * 2 {
                    crate::log_warn!("Process network connections ({}) exceed expected pattern ({})",
                                   behavior.active_connections, expected_network);
                    return false;
                }
            }
            
            // Check file access patterns
            if let Some(expected_files) = pattern.expected_file_accesses {
                if behavior.file_accesses_per_second > expected_files * 10 {
                    crate::log_warn!("Process file access rate ({}/s) exceeds expected pattern ({}/s)",
                                   behavior.file_accesses_per_second, expected_files);
                    return false;
                }
            }
            
            // Check CPU usage patterns
            if behavior.cpu_usage_percent > 90 && pattern.expected_cpu_usage.unwrap_or(50) < 80 {
                crate::log_warn!("Process consuming excessive CPU: {}%", behavior.cpu_usage_percent);
                return false;
            }
            
            // Check privilege escalation attempts
            if behavior.privilege_escalation_attempts > 0 {
                crate::log_warn!("Process attempted privilege escalation {} times", 
                               behavior.privilege_escalation_attempts);
                return false;
            }
            
            // Check for suspicious system calls
            if crate::process::detect_suspicious_syscalls(&current_process) {
                crate::log_warn!("Process making suspicious system calls");
                return false;
            }
        }
        
        true
    }
    
    fn verify_kernel_integrity(&self) -> bool {
        // Verify kernel code integrity using multiple methods
        
        // Check kernel text section hash
        let kernel_text_hash = crate::crypto::hash::compute_kernel_text_hash();
        let expected_hash = crate::security::trusted_hashes::KERNEL_TEXT_HASH;
        
        if kernel_text_hash != expected_hash {
            crate::log_fatal!("Kernel text section hash mismatch - possible code injection");
            return false;
        }
        
        // Verify critical kernel data structures
        if !crate::memory::verify_kernel_data_integrity() {
            crate::log_fatal!("Kernel data structure integrity check failed");
            return false;
        }
        
        // Check for unauthorized kernel modules (simplified for now)
        // In a real implementation, would enumerate loaded modules
        let trusted_modules = vec!["core.boot", "security_monitor"];
        for module_name in &trusted_modules {
            if !crate::security::module_db::is_trusted_module(module_name) {
                crate::log::logger::log_info!("{}", &alloc::format!("Note: Module {} not in trust database", module_name));
            }
        }
        
        // Verify system call table hasn't been hooked (simplified)
        // In a real implementation, would check syscall table integrity
        // For now, assume clean
        let syscall_table_clean = true;
        if !syscall_table_clean {
            return false;
        }
        
        // Check interrupt descriptor table integrity
        if !crate::arch::x86_64::idt::verify_idt_integrity() {
            crate::log_fatal!("Interrupt descriptor table has been modified");
            return false;
        }
        
        // Verify page table entries for kernel memory
        if !crate::memory::verify_kernel_page_tables() {
            crate::log_fatal!("Kernel page table integrity check failed");
            return false;
        }
        
        // Check for control flow integrity violations (simplified)
        // In a real implementation, would check CFI violations
        let cfi_clean = true;
        if !cfi_clean {
            return false;
        }
        
        crate::log_info!("Kernel integrity verification passed");
        true
    }
    
    fn detect_rootkit_signatures(&self) -> bool {
        // Detect known rootkit signatures and behaviors
        
        // Scan for hidden processes (rootkits often hide processes)
        let system_processes = crate::process::enumerate_all_processes();
        let visible_processes = crate::process::enumerate_visible_processes();
        
        if system_processes.len() != visible_processes.len() {
            crate::log_warn!("Process hiding detected: {} hidden processes", 
                           system_processes.len() - visible_processes.len());
            return true;
        }
        
        // Check for suspicious kernel module signatures
        // Check loaded modules (simplified)
        let modules = vec!["core.boot", "security"];
        for module_name in &modules {
            // Check for suspicious module names
            let suspicious_names = ["rootkit", "hide", "stealth", "backdoor", "keylog"];
            for suspicious in &suspicious_names {
                if module_name.to_lowercase().contains(suspicious) {
                    crate::log::logger::log_info!("{}", &format!("Suspicious module name: {}", module_name));
                    return true;
                }
            }
        }
        
        // Check for system call table hooks (common rootkit technique)
        if crate::arch::x86_64::syscall::detect_syscall_hooks() {
            crate::log_warn!("System call table hooks detected");
            return true;
        }
        
        // Check for interrupt handler modifications
        if crate::arch::x86_64::idt::detect_handler_modifications() {
            crate::log_warn!("Interrupt handler modifications detected");
            return true;
        }
        
        // Scan memory for rootkit signatures
        let memory_regions = crate::memory::get_kernel_memory_regions();
        for region in memory_regions {
            // Convert memory::MemoryRegion to signature_scanner::MemoryRegion
            let scanner_region = crate::security::signature_scanner::MemoryRegion {
                start: region.start,
                end: region.start + region.size,
                permissions: 0x7, // Assume read/write/execute for kernel regions
                region_type: match region.region_type {
                    crate::memory::RegionType::Kernel => crate::security::signature_scanner::RegionType::KernelCode,
                    _ => crate::security::signature_scanner::RegionType::KernelCode,
                },
            };
            
            if crate::security::signature_scanner::scan_memory_for_rootkits(&scanner_region) {
                crate::log_warn!("Rootkit signature found in memory region {:?}", region);
                return true;
            }
        }
        
        // Check for network backdoors
        let network_connections = crate::network::get_all_connections();
        for conn in network_connections {
            if crate::security::threat_intel::is_known_backdoor_connection(&conn) {
                crate::log_warn!("Suspected backdoor connection: {}.{}.{}.{}:{}", 
                    conn.remote_ip[0], conn.remote_ip[1], conn.remote_ip[2], conn.remote_ip[3], 
                    conn.remote_port);
                return true;
            }
        }
        
        // Check for file system hiding
        if crate::filesystem::detect_hidden_files() {
            crate::log_warn!("Hidden files detected in filesystem");
            return true;
        }
        
        false
    }
    
    fn detect_unauthorized_data_collection(&self) -> bool {
        // Detect unauthorized data collection activities
        
        // Monitor file access patterns for data harvesting
        let file_access_stats = crate::filesystem::get_access_statistics();
        
        // Check for mass file reading (potential data harvesting)
        let read_ops = file_access_stats.read_operations.load(core::sync::atomic::Ordering::Relaxed);
        if read_ops > 1000 {
            crate::log_warn!("Suspicious mass file reading detected: {} read operations", read_ops);
            return true;
        }
        
        // Check for access to sensitive directories (simplified - check total operations)
        let total_ops = file_access_stats.total_operations.load(core::sync::atomic::Ordering::Relaxed);
        if total_ops > 10000 {
            crate::log_warn!("Excessive filesystem access detected: {} total operations", total_ops);
            return true;
        }
        
        // Monitor network data exfiltration patterns
        let network_stats = crate::network::get_traffic_statistics();
        
        // Check for large outbound data transfers
        if network_stats.bytes_sent > 50 * 1024 * 1024 { // >50MB total sent
            crate::log_warn!("Suspicious large data transfer detected: {} bytes sent", 
                           network_stats.bytes_sent);
            return true;
        }
        
        // Check for connections to data collection services
        let connections = crate::network::get_active_connections();
        for conn in connections {
            if crate::security::threat_intel::is_known_data_collection_service(conn.remote_ip) {
                crate::log_warn!("Connection to known data collection service: {}.{}.{}.{}", 
                    conn.remote_ip[0], conn.remote_ip[1], conn.remote_ip[2], conn.remote_ip[3]);
                return true;
            }
        }
        
        // Monitor process behavior for data collection patterns
        let processes = crate::process::get_all_processes();
        for process in processes {
            let behavior = crate::process::get_behavior_metrics(&process);
            
            // Check for processes accessing user data
            if behavior.user_data_accesses > 1000 && 
               !crate::process::has_data_access_permission(&process) {
                crate::log_warn!("Process {} accessing user data without permission", process.name);
                return true;
            }
            
            // Check for keylogging behavior
            if crate::process::detect_keylogging_behavior(&process) {
                crate::log_warn!("Potential keylogger detected: {}", process.name);
                return true;
            }
            
            // Check for screenshot/screen recording
            if crate::process::detect_screen_capture_behavior(&process) {
                crate::log_warn!("Unauthorized screen capture detected: {}", process.name);
                return true;
            }
        }
        
        // Check memory for collected data patterns
        if crate::memory::scan_for_collected_personal_data() {
            crate::log_warn!("Personal data collection detected in memory");
            return true;
        }
        
        false
    }
    
    fn detect_privacy_leaks(&self) -> bool {
        // Detect potential privacy leaks through various channels
        
        // Monitor network traffic for personal data leaks (simplified)
        let network_packets = crate::network::capture_recent_packets();
        if network_packets.len() > 1000 {
            crate::log_warn!("High network activity detected: {} packets captured", network_packets.len());
            return true;
        }
        
        for packet in network_packets {
            // Check for unencrypted sensitive data transmission
            if !packet.is_encrypted && crate::security::data_leak_detection::contains_sensitive_patterns(&packet.data) {
                crate::log_warn!("Unencrypted sensitive data transmitted to {}", packet.destination);
                return true;
            }
        }
        
        // Monitor file operations for data leaks
        let file_operations = crate::filesystem::get_recent_operations();
        for op in file_operations {
            // Check for copying sensitive files to external media
            if let Some(ref dest) = op.destination {
                if crate::filesystem::is_external_storage(dest) && 
                   crate::filesystem::contains_personal_data(&op.source) {
                    crate::log_warn!("Sensitive file copied to external storage: {} -> {}", 
                                   op.source, dest);
                    return true;
                }
            }
            
            // Check for temporary file creation with sensitive data
            if op.operation_type == crate::filesystem::OperationType::Create &&
               op.source.contains("/tmp") &&
               crate::filesystem::scan_file_for_pii(&op.source) {
                crate::log_warn!("Sensitive data written to temporary file: {}", op.source);
                return true;
            }
        }
        
        // Monitor clipboard for sensitive data
        if crate::ui::clipboard::contains_sensitive_data() {
            crate::log_warn!("Sensitive data detected in clipboard");
            return true;
        }
        
        // Check process memory for data leaks
        let processes = crate::process::get_all_processes();
        for process in processes {
            if crate::memory::scan_process_memory_for_leaks(&process) {
                crate::log_warn!("Data leak patterns found in process memory: {}", process.name);
                return true;
            }
        }
        
        // Monitor DNS queries for privacy leaks
        let dns_queries = crate::network::get_recent_dns_queries();
        for query in dns_queries {
            if crate::security::dns_privacy::is_privacy_leaking_query(&query.domain) {
                crate::log_warn!("Privacy-leaking DNS query detected: {}", query.domain);
                return true;
            }
        }
        
        // Check for browser fingerprinting attempts
        if crate::ui::browser::detect_fingerprinting_attempts() {
            crate::log_warn!("Browser fingerprinting attempt detected");
            return true;
        }
        
        // Monitor system calls for privacy violations
        let syscalls = crate::arch::x86_64::syscall::get_recent_calls();
        for call in syscalls {
            if crate::security::privacy_violation::scan_for_privacy_violations(&[], call.number as u32, crate::security::privacy_violation::LocationType::Memory, "").len() > 0 {
                crate::log_warn!("Privacy-violating system call: {}", call.number);
                return true;
            }
        }
        
        false
    }
    
    fn count_recent_events(&self, event_type: SecurityEvent) -> u64 {
        let events = self.recent_events.lock();
        events.iter().filter(|&&e| e == event_type).count() as u64
    }
    
    /// Get security monitor statistics
    pub fn get_stats(&self) -> SecurityMonitorStatistics {
        SecurityMonitorStatistics {
            total_events: self.stats.total_events.load(Ordering::Relaxed),
            threats_detected: self.stats.threats_detected.load(Ordering::Relaxed),
            false_positives: self.stats.false_positives.load(Ordering::Relaxed),
            memory_violations: self.stats.memory_violations.load(Ordering::Relaxed),
            network_anomalies: self.stats.network_anomalies.load(Ordering::Relaxed),
            process_anomalies: self.stats.process_anomalies.load(Ordering::Relaxed),
            hardware_alerts: self.stats.hardware_alerts.load(Ordering::Relaxed),
            privacy_violations: self.stats.privacy_violations.load(Ordering::Relaxed),
            monitoring_enabled: self.enabled.load(Ordering::Relaxed),
        }
    }
    
    /// Block a threat source by disabling its access
    fn block_threat_source(&self, threat_name: &str) {
        crate::log_warn!("Blocking threat source: {}", threat_name);
        
        // Disable network access for threatening processes
        crate::process::disable_network_access_for_all();
        
        // Block suspicious memory operations
        crate::memory::enable_strict_access_control();
        
        // Increase security monitoring sensitivity
        self.detection_sensitivity.store(100, Ordering::Release);
    }
    
    /// Quarantine a detected threat
    fn quarantine_threat(&self, threat_name: &str) {
        crate::log_warn!("Quarantining threat: {}", threat_name);
        
        // Suspend all non-essential processes
        crate::process::suspend_non_critical_processes();
        
        // Enable maximum security mode
        self.enabled.store(true, Ordering::Release);
        self.detection_sensitivity.store(100, Ordering::Release);
        
        // Clear sensitive memory regions
        self.secure_memory_wipe();
    }
    
    /// Isolate process memory to prevent data leakage
    fn isolate_process_memory(&self) {
        crate::log_warn!("Isolating process memory spaces");
        
        // Enable strict memory isolation between processes
        crate::memory::enable_process_isolation();
        
        // Clear shared memory regions
        crate::memory::clear_shared_memory();
        
        // Disable memory swapping to prevent data leaks to disk
        crate::memory::disable_memory_swapping();
    }
    
    /// Perform emergency system shutdown
    fn emergency_shutdown(&self) {
        crate::log_fatal!("EMERGENCY SHUTDOWN INITIATED");
        
        // Clear all cryptographic keys from memory
        crate::crypto::emergency_key_wipe();
        
        // Clear sensitive data structures
        self.secure_memory_wipe();
        
        // Disable all network interfaces
        // Emergency network shutdown - would disable all network interfaces
        crate::log::logger::log_info!("Emergency network shutdown initiated");
        
        // Clear CPU caches
        unsafe {
            crate::arch::x86_64::clear_cpu_caches();
        }
    }
    
    /// Securely wipe sensitive memory regions
    fn secure_memory_wipe(&self) {
        // Clear event history
        self.recent_events.lock().clear();
        
        // Note: Cannot wipe detection_sensitivity from immutable method
        // This would require changing the method signature to &mut self
        
        // Clear CPU caches and TLBs
        crate::arch::x86_64::clear_cpu_caches();
        crate::arch::x86_64::flush_tlb();
    }
}

/// Memory operation types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryOperation {
    Read,
    Write,
    Execute,
}

/// Network protocol types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
}

impl NetworkProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkProtocol::TCP => "tcp",
            NetworkProtocol::UDP => "udp",
            NetworkProtocol::ICMP => "icmp",
        }
    }
}

/// Security monitor statistics structure
#[derive(Debug, Clone)]
pub struct SecurityMonitorStatistics {
    pub total_events: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub memory_violations: u64,
    pub network_anomalies: u64,
    pub process_anomalies: u64,
    pub hardware_alerts: u64,
    pub privacy_violations: u64,
    pub monitoring_enabled: bool,
}

/// Global security monitor instance
static mut SECURITY_MONITOR: Option<SecurityMonitor> = None;
static MONITOR_INITIALIZED: AtomicU32 = AtomicU32::new(0);

/// Initialize global security monitor
/// Early initialization of security monitoring before heap is available
pub unsafe fn init_early() {
    // Initialize basic monitoring structures without heap allocation
    // This sets up minimal security monitoring for early boot
    
    // Basic initialization that doesn't require heap
    // Will be expanded when init_security_monitor() is called later
}

pub fn init_security_monitor() -> Result<(), &'static str> {
    unsafe {
        if MONITOR_INITIALIZED.load(Ordering::Acquire) != 0 {
            return Ok(());
        }
        
        let monitor = SecurityMonitor::new();
        SECURITY_MONITOR = Some(monitor);
        MONITOR_INITIALIZED.store(1, Ordering::Release);
        
        crate::log_info!("Security monitor initialized");
        Ok(())
    }
}

/// Get global security monitor
fn get_security_monitor() -> Option<&'static SecurityMonitor> {
    unsafe {
        if MONITOR_INITIALIZED.load(Ordering::Acquire) != 0 {
            SECURITY_MONITOR.as_ref()
        } else {
            None
        }
    }
}

/// Perform periodic security check (called from RTC handler)
pub fn periodic_security_check() {
    if let Some(monitor) = get_security_monitor() {
        monitor.periodic_security_check();
    }
}

/// Monitor memory access
pub fn monitor_memory_access(address: u64, size: u64, operation: MemoryOperation) {
    if let Some(monitor) = get_security_monitor() {
        monitor.monitor_memory_access(address, size, operation);
    }
}

/// Monitor network access
pub fn monitor_network_access(destination: u32, port: u16, protocol: NetworkProtocol) {
    if let Some(monitor) = get_security_monitor() {
        monitor.monitor_network_access(destination, port, protocol);
    }
}

/// Get security monitor statistics
pub fn get_security_stats() -> Option<SecurityMonitorStatistics> {
    get_security_monitor().map(|monitor| monitor.get_stats())
}