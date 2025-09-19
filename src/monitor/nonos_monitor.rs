#![no_std]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::{RwLock, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NonosSecurityEventType {
    ProcessCreation = 0x1000,
    ProcessTermination = 0x1001,
    MemoryViolation = 0x2000,
    FileSystemAccess = 0x3000,
    NetworkConnection = 0x4000,
    CryptographicFailure = 0x5000,
    SystemCall = 0x6000,
    CapabilityViolation = 0x7000,
    QuantumDecoherence = 0x8000,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NonosThreatLevel {
    Minimal = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
    Catastrophic = 5,
}

#[derive(Debug, Clone)]
pub struct NonosSecurityEvent {
    pub event_id: u64,
    pub event_type: NonosSecurityEventType,
    pub timestamp: u64,
    pub process_id: Option<u64>,
    pub thread_id: Option<u64>,
    pub threat_level: NonosThreatLevel,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct NonosSecurityMonitor {
    event_log: Mutex<Vec<NonosSecurityEvent>>,
    threat_level: RwLock<NonosThreatLevel>,
}

impl NonosSecurityMonitor {
    pub const fn new() -> Self {
        Self {
            event_log: Mutex::new(Vec::new()),
            threat_level: RwLock::new(NonosThreatLevel::Minimal),
        }
    }

    pub fn log_security_event(&self, event: NonosSecurityEvent) {
        // Update threat level based on event
        self.update_threat_level(event.threat_level);
        
        // Add to event log
        if let Some(mut log) = self.event_log.try_lock() {
            log.push(event);
            
            // Maintain log size
            if log.len() > 10000 {
                log.drain(0..1000);
            }
        }
    }

    fn update_threat_level(&self, new_level: NonosThreatLevel) {
        if let Some(mut current_level) = self.threat_level.try_write() {
            if new_level > *current_level {
                *current_level = new_level;
            }
        }
    }

    pub fn get_threat_level(&self) -> NonosThreatLevel {
        *self.threat_level.read()
    }

    pub fn get_event_count(&self) -> usize {
        self.event_log.lock().len()
    }

    pub fn generate_security_report(&self) -> NonosSecurityReport {
        let log = self.event_log.lock();
        let total_events = log.len() as u64;
        let current_threat_level = *self.threat_level.read();
        
        // Calculate threat distribution
        let mut threat_distribution = BTreeMap::new();
        for event in log.iter() {
            *threat_distribution.entry(event.threat_level).or_insert(0) += 1;
        }

        NonosSecurityReport {
            report_id: self.get_timestamp(),
            generation_time: self.get_timestamp(),
            total_events,
            current_threat_level,
            threat_distribution,
        }
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

#[derive(Debug)]
pub struct NonosSecurityReport {
    pub report_id: u64,
    pub generation_time: u64,
    pub total_events: u64,
    pub current_threat_level: NonosThreatLevel,
    pub threat_distribution: BTreeMap<NonosThreatLevel, u64>,
}

// Global security monitor instance
pub static NONOS_SECURITY_MONITOR: NonosSecurityMonitor = NonosSecurityMonitor::new();

// Convenience functions
pub fn log_security_event(event: NonosSecurityEvent) {
    NONOS_SECURITY_MONITOR.log_security_event(event);
}

pub fn get_current_threat_level() -> NonosThreatLevel {
    NONOS_SECURITY_MONITOR.get_threat_level()
}

pub fn generate_security_report() -> NonosSecurityReport {
    NONOS_SECURITY_MONITOR.generate_security_report()
}

pub fn init_security_monitor() {
    // Initialize security monitoring
    crate::log::logger::log!("Security monitor initialized");
}