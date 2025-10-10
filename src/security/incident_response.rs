//! NONOS Incident Response System
//!
//! Real-time security incident detection, logging, and automated response

use crate::arch::x86_64::time::timer;
use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

#[derive(Debug, Clone)]
pub struct SecurityIncident {
    pub incident_id: u64,
    pub timestamp: u64,
    pub incident_type: IncidentType,
    pub severity: Severity,
    pub source_ip: Option<[u8; 4]>,
    pub affected_process: Option<u32>,
    pub description: String,
    pub evidence: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum IncidentType {
    IntegrityViolation,
    PrivacyViolation,
    RootkitDetected,
    UnauthorizedAccess,
    DataExfiltration,
    SystemCompromise,
    NetworkIntrusion,
    MalwareDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

pub struct IncidentResponse {
    incidents: Mutex<Vec<SecurityIncident>>,
    incident_counter: AtomicU64,
    blocked_ips: Mutex<BTreeMap<[u8; 4], u64>>,
    quarantined_processes: Mutex<Vec<u32>>,
    alerts_sent: AtomicU32,
    system_lockdown: core::sync::atomic::AtomicBool,
}

static INCIDENT_RESPONSE: Mutex<Option<IncidentResponse>> = Mutex::new(None);

impl IncidentResponse {
    pub fn new() -> Self {
        IncidentResponse {
            incidents: Mutex::new(Vec::new()),
            incident_counter: AtomicU64::new(1),
            blocked_ips: Mutex::new(BTreeMap::new()),
            quarantined_processes: Mutex::new(Vec::new()),
            alerts_sent: AtomicU32::new(0),
            system_lockdown: core::sync::atomic::AtomicBool::new(false),
        }
    }

    fn log_incident(&self, mut incident: SecurityIncident) -> u64 {
        incident.incident_id = self.incident_counter.fetch_add(1, Ordering::SeqCst);
        incident.timestamp = timer::get_timestamp_ms().unwrap_or(0);

        let incident_id = incident.incident_id;
        self.incidents.lock().push(incident.clone());

        // Automated response based on severity
        match incident.severity {
            Severity::Critical => self.handle_critical_incident(&incident),
            Severity::High => self.handle_high_incident(&incident),
            Severity::Medium => self.handle_medium_incident(&incident),
            Severity::Low => self.handle_low_incident(&incident),
        }

        incident_id
    }

    fn handle_critical_incident(&self, incident: &SecurityIncident) {
        // Immediate system protection measures
        match incident.incident_type {
            IncidentType::SystemCompromise | IncidentType::RootkitDetected => {
                // Lock down system
                self.system_lockdown.store(true, Ordering::SeqCst);

                // Disable network interfaces
                if let Some(ip) = incident.source_ip {
                    self.block_ip_immediately(ip);
                }

                // Quarantine affected process
                if let Some(pid) = incident.affected_process {
                    self.quarantine_process(pid);
                }
            }
            IncidentType::DataExfiltration => {
                // Block network access immediately
                if let Some(ip) = incident.source_ip {
                    self.block_ip_immediately(ip);
                }

                // Alert system administrator
                self.send_emergency_alert(incident);
            }
            _ => {
                // General critical response
                if let Some(ip) = incident.source_ip {
                    self.block_ip_immediately(ip);
                }
            }
        }

        self.send_emergency_alert(incident);
    }

    fn handle_high_incident(&self, incident: &SecurityIncident) {
        if let Some(ip) = incident.source_ip {
            self.block_ip_temporarily(ip, 3600); // Block for 1 hour
        }

        if let Some(pid) = incident.affected_process {
            // Suspend process for investigation
            self.suspend_process(pid);
        }

        self.send_alert(incident);
    }

    fn handle_medium_incident(&self, incident: &SecurityIncident) {
        if let Some(ip) = incident.source_ip {
            self.rate_limit_ip(ip);
        }

        // Log for investigation
        self.queue_for_investigation(incident);
    }

    fn handle_low_incident(&self, incident: &SecurityIncident) {
        // Just log and monitor
        self.update_threat_intelligence(incident);
    }

    fn block_ip_immediately(&self, ip: [u8; 4]) {
        let mut blocked_ips = self.blocked_ips.lock();
        blocked_ips.insert(ip, u64::MAX); // Permanent block

        // Implementation: Add to kernel firewall rules
        let _ = crate::network::firewall::block_ip(ip);
    }

    fn block_ip_temporarily(&self, ip: [u8; 4], duration_seconds: u64) {
        let mut blocked_ips = self.blocked_ips.lock();
        let expiry = timer::get_timestamp_ms().unwrap_or(0) + (duration_seconds * 1000);
        blocked_ips.insert(ip, expiry);

        let _ = crate::network::firewall::block_ip_temporarily(ip, duration_seconds);
    }

    fn rate_limit_ip(&self, ip: [u8; 4]) {
        let _ = crate::network::firewall::rate_limit_ip(ip);
    }

    fn quarantine_process(&self, pid: u32) {
        self.quarantined_processes.lock().push(pid);

        // Implementation: Isolate process in secure container
        let _ = crate::process::isolate_process(pid);
    }

    fn suspend_process(&self, pid: u32) {
        // Implementation: Suspend process execution
        let _ = crate::process::suspend_process(pid);
    }

    fn send_emergency_alert(&self, incident: &SecurityIncident) {
        self.alerts_sent.fetch_add(1, Ordering::SeqCst);

        // Emergency alert through secure channels
        let alert_msg = alloc::format!(
            "CRITICAL SECURITY INCIDENT #{}: {} detected at {}. Immediate action required.",
            incident.incident_id,
            self.incident_type_to_string(incident.incident_type),
            incident.timestamp
        );

        // Send through emergency communication channels
        let _ = crate::drivers::console::emergency_alert(&alert_msg);
    }

    fn send_alert(&self, incident: &SecurityIncident) {
        self.alerts_sent.fetch_add(1, Ordering::SeqCst);

        let alert_msg = alloc::format!(
            "Security Incident #{}: {} severity {} detected",
            incident.incident_id,
            self.incident_type_to_string(incident.incident_type),
            self.severity_to_string(incident.severity)
        );

        let _ = crate::drivers::console::log_alert(&alert_msg);
    }

    fn queue_for_investigation(&self, _incident: &SecurityIncident) {
        // Queue incident for security team review
        // Implementation: Add to investigation queue
    }

    fn update_threat_intelligence(&self, incident: &SecurityIncident) {
        if let Some(ip) = incident.source_ip {
            let _ = crate::security::threat_intel::update_threat_score(ip, 10);
        }
    }

    fn incident_type_to_string(&self, incident_type: IncidentType) -> &'static str {
        match incident_type {
            IncidentType::IntegrityViolation => "Integrity Violation",
            IncidentType::PrivacyViolation => "Privacy Violation",
            IncidentType::RootkitDetected => "Rootkit Detected",
            IncidentType::UnauthorizedAccess => "Unauthorized Access",
            IncidentType::DataExfiltration => "Data Exfiltration",
            IncidentType::SystemCompromise => "System Compromise",
            IncidentType::NetworkIntrusion => "Network Intrusion",
            IncidentType::MalwareDetected => "Malware Detected",
        }
    }

    fn severity_to_string(&self, severity: Severity) -> &'static str {
        match severity {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn get_incident_count(&self) -> usize {
        self.incidents.lock().len()
    }

    pub fn get_blocked_ips(&self) -> Vec<[u8; 4]> {
        self.blocked_ips.lock().keys().copied().collect()
    }

    pub fn is_system_locked_down(&self) -> bool {
        self.system_lockdown.load(Ordering::SeqCst)
    }

    pub fn clear_expired_blocks(&self) {
        let current_time = timer::get_timestamp_ms().unwrap_or(0);
        let mut blocked_ips = self.blocked_ips.lock();
        blocked_ips.retain(|_ip, &mut expiry| {
            if expiry == u64::MAX {
                true // Permanent block
            } else {
                current_time < expiry // Keep if not expired
            }
        });
    }
}

pub fn init() -> Result<(), &'static str> {
    let response_system = IncidentResponse::new();
    *INCIDENT_RESPONSE.lock() = Some(response_system);
    Ok(())
}

pub fn trigger_integrity_violation(failures: &[String]) {
    if let Some(system) = INCIDENT_RESPONSE.lock().as_ref() {
        let evidence = failures.join(", ").into_bytes();
        let incident = SecurityIncident {
            incident_id: 0, // Will be set by log_incident
            timestamp: 0,   // Will be set by log_incident
            incident_type: IncidentType::IntegrityViolation,
            severity: Severity::High,
            source_ip: None,
            affected_process: None,
            description: alloc::format!("System integrity violations detected: {}", failures.len()),
            evidence,
        };

        system.log_incident(incident);
    }
}

pub fn trigger_privacy_violation(violations: &[String]) {
    if let Some(system) = INCIDENT_RESPONSE.lock().as_ref() {
        let evidence = violations.join(", ").into_bytes();
        let incident = SecurityIncident {
            incident_id: 0,
            timestamp: 0,
            incident_type: IncidentType::PrivacyViolation,
            severity: Severity::High,
            source_ip: None,
            affected_process: None,
            description: alloc::format!("Privacy violations detected: {}", violations.len()),
            evidence,
        };

        system.log_incident(incident);
    }
}

pub fn trigger_rootkit_detected(rootkit_info: &str) {
    if let Some(system) = INCIDENT_RESPONSE.lock().as_ref() {
        let incident = SecurityIncident {
            incident_id: 0,
            timestamp: 0,
            incident_type: IncidentType::RootkitDetected,
            severity: Severity::Critical,
            source_ip: None,
            affected_process: None,
            description: alloc::format!("Rootkit detected: {}", rootkit_info),
            evidence: rootkit_info.as_bytes().to_vec(),
        };

        system.log_incident(incident);
    }
}

pub fn trigger_network_intrusion(source_ip: [u8; 4], details: &str) {
    if let Some(system) = INCIDENT_RESPONSE.lock().as_ref() {
        let incident = SecurityIncident {
            incident_id: 0,
            timestamp: 0,
            incident_type: IncidentType::NetworkIntrusion,
            severity: Severity::High,
            source_ip: Some(source_ip),
            affected_process: None,
            description: alloc::format!("Network intrusion from {:?}: {}", source_ip, details),
            evidence: details.as_bytes().to_vec(),
        };

        system.log_incident(incident);
    }
}

pub fn get_incident_response() -> &'static Mutex<Option<IncidentResponse>> {
    &INCIDENT_RESPONSE
}

pub fn cleanup_expired_responses() {
    if let Some(system) = INCIDENT_RESPONSE.lock().as_ref() {
        system.clear_expired_blocks();
    }
}
