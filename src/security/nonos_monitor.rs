#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Security event types for behavioral and system monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosSecurityEventType {
    SuspiciousMemoryAccess,
    UnauthorizedNetworkAccess,
    ProcessAnomaly,
    HardwareTamper,
    PrivilegeEscalation,
    SyscallAnomaly,
    FilesystemViolation,
    CapabilityAbuse,
    PrivacyViolation,
    RootkitDetection,
    IntegrityBreach,
}

/// Security event structure
#[derive(Debug, Clone)]
pub struct NonosSecurityEvent {
    pub timestamp: u64,
    pub event_type: NonosSecurityEventType,
    pub severity: u8, // 0=info, 1=warn, 2=error, 3=critical
    pub description: String,
    pub process_id: Option<u64>,
    pub module: Option<String>,
    pub extra_tags: Option<Vec<String>>,
}

/// Per-subsystem stats
#[derive(Default)]
pub struct NonosMonitorStats {
    pub total_events: AtomicU64,
    pub critical_events: AtomicU64,
    pub memory_violations: AtomicU64,
    pub network_anomalies: AtomicU64,
    pub process_anomalies: AtomicU64,
    pub rootkit_alerts: AtomicU64,
    pub privacy_violations: AtomicU64,
}

/// Global monitor state
static MONITOR_LOG: Mutex<Vec<NonosSecurityEvent>> = Mutex::new(Vec::new());
static MONITOR_STATS: NonosMonitorStats = NonosMonitorStats::default();
static MONITOR_ENABLED: AtomicBool = AtomicBool::new(true);

/// Log a security event
pub fn log_event(
    event_type: NonosSecurityEventType,
    severity: u8,
    description: String,
    process_id: Option<u64>,
    module: Option<String>,
    extra_tags: Option<Vec<String>>,
) {
    let event = NonosSecurityEvent {
        timestamp: crate::time::timestamp_millis(),
        event_type,
        severity,
        description,
        process_id,
        module,
        extra_tags,
    };
    {
        let mut log = MONITOR_LOG.lock();
        if log.len() > 4096 {
            log.remove(0);
        }
        log.push(event.clone());
    }
    MONITOR_STATS.total_events.fetch_add(1, Ordering::Relaxed);
    if severity >= 3 {
        MONITOR_STATS.critical_events.fetch_add(1, Ordering::Relaxed);
    }
    match event_type {
        NonosSecurityEventType::SuspiciousMemoryAccess => MONITOR_STATS.memory_violations.fetch_add(1, Ordering::Relaxed),
        NonosSecurityEventType::UnauthorizedNetworkAccess => MONITOR_STATS.network_anomalies.fetch_add(1, Ordering::Relaxed),
        NonosSecurityEventType::ProcessAnomaly => MONITOR_STATS.process_anomalies.fetch_add(1, Ordering::Relaxed),
        NonosSecurityEventType::RootkitDetection => MONITOR_STATS.rootkit_alerts.fetch_add(1, Ordering::Relaxed),
        NonosSecurityEventType::PrivacyViolation => MONITOR_STATS.privacy_violations.fetch_add(1, Ordering::Relaxed),
        _ => {},
    }
}

/// Get the latest N security events
pub fn get_recent_events(n: usize) -> Vec<NonosSecurityEvent> {
    let log = MONITOR_LOG.lock();
    let len = log.len();
    log.iter().skip(len.saturating_sub(n)).cloned().collect()
}

/// Get monitor stats
pub fn get_stats() -> NonosMonitorStats {
    NonosMonitorStats {
        total_events: AtomicU64::new(MONITOR_STATS.total_events.load(Ordering::Relaxed)),
        critical_events: AtomicU64::new(MONITOR_STATS.critical_events.load(Ordering::Relaxed)),
        memory_violations: AtomicU64::new(MONITOR_STATS.memory_violations.load(Ordering::Relaxed)),
        network_anomalies: AtomicU64::new(MONITOR_STATS.network_anomalies.load(Ordering::Relaxed)),
        process_anomalies: AtomicU64::new(MONITOR_STATS.process_anomalies.load(Ordering::Relaxed)),
        rootkit_alerts: AtomicU64::new(MONITOR_STATS.rootkit_alerts.load(Ordering::Relaxed)),
        privacy_violations: AtomicU64::new(MONITOR_STATS.privacy_violations.load(Ordering::Relaxed)),
    }
}

/// Enable or disable monitoring (for incident response)
pub fn set_enabled(enabled: bool) {
    MONITOR_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Is monitor enabled?
pub fn is_enabled() -> bool {
    MONITOR_ENABLED.load(Ordering::Relaxed)
}
