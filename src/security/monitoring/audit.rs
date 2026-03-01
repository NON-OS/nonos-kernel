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

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
    Emergency,
}

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
        let idx = (AUDIT_COUNTER.fetch_add(1, Ordering::Relaxed) % MAX_AUDIT_LOG as u64) as usize;
        log[idx] = event;
    }
}

pub fn log_security_violation(description: String, severity: AuditSeverity) {
    log_security_event("security", severity, description, None, None, None);
}

pub fn get_audit_log() -> Vec<SecurityAuditEvent> {
    AUDIT_LOG.lock().clone()
}

pub fn clear_audit_log() {
    AUDIT_LOG.lock().clear();
}

pub fn init() -> Result<(), &'static str> {
    Ok(())
}

pub type AuditEvent = SecurityAuditEvent;

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
