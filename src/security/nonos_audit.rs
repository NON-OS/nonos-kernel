#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Severity levels for audit events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
    Emergency,
}

/// Security audit event
#[derive(Debug, Clone)]
pub struct SecurityAuditEvent {
    pub timestamp: u64,
    pub subsystem: &'static str,
    pub severity: AuditSeverity,
    pub description: String,
    pub process_id: Option<u64>,
    pub module: Option<String>,
    pub extra_tags: Option<Vec<String>>,
}

const MAX_AUDIT_LOG: usize = 8192;
static AUDIT_LOG: Mutex<Vec<SecurityAuditEvent>> = Mutex::new(Vec::new());
static AUDIT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Log a security event to the audit log
pub fn log_security_event(
    subsystem: &'static str,
    severity: AuditSeverity,
    description: String,
    process_id: Option<u64>,
    module: Option<String>,
    extra_tags: Option<Vec<String>>,
) {
    let event = SecurityAuditEvent {
        timestamp: crate::time::timestamp_millis(),
        subsystem,
        severity,
        description,
        process_id,
        module,
        extra_tags,
    };
    let mut log = AUDIT_LOG.lock();
    if log.len() < MAX_AUDIT_LOG {
        log.push(event);
    } else {
        // Overwrite oldest entry
        let idx = (AUDIT_COUNTER.fetch_add(1, Ordering::Relaxed) % MAX_AUDIT_LOG as u64) as usize;
        log[idx] = event;
    }
}

/// Log a severe security violation
pub fn log_security_violation(description: String, severity: AuditSeverity) {
    log_security_event("security", severity, description, None, None, None);
}

/// Retrieve all audit events
pub fn get_audit_log() -> Vec<SecurityAuditEvent> {
    AUDIT_LOG.lock().clone()
}

/// Clear the entire audit log (admin only)
pub fn clear_audit_log() {
    AUDIT_LOG.lock().clear();
}

/// Initialize audit system
pub fn init() -> Result<(), &'static str> {
    Ok(())
}

/// Audit event compatibility alias
pub type AuditEvent = SecurityAuditEvent;

/// Log audit event compatibility function
pub fn audit_event(
    subsystem: &'static str,
    severity: AuditSeverity,
    description: String,
    process_id: Option<u64>,
    module: Option<String>,
    extra_tags: Option<Vec<String>>,
) {
    log_security_event(subsystem, severity, description, process_id, module, extra_tags);
}
