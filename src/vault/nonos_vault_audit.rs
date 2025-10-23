//! NØNOS Vault Audit & Compliance Framework 

extern crate alloc;
use alloc::{string::String, vec::Vec};
use spin::Mutex;
use crate::vault::nonos_vault::VaultAuditEvent;

/// Audit log manager
pub struct VaultAuditManager {
    log: Mutex<Vec<VaultAuditEvent>>,
}

impl VaultAuditManager {
    pub const fn new() -> Self {
        Self {
            log: Mutex::new(Vec::new()),
        }
    }

    /// Log a new audit event
    pub fn log_event(&self, event: VaultAuditEvent) {
        self.log.lock().push(event);
    }

    /// List last N audit events (reverse chronological)
    pub fn recent(&self, n: usize) -> Vec<VaultAuditEvent> {
        let log = self.log.lock();
        log.iter().rev().take(n).cloned().collect()
    }

    /// Filter events by op, status or context substring
    pub fn filter(&self, op: Option<&str>, status: Option<&str>, context: Option<&str>) -> Vec<VaultAuditEvent> {
        let log = self.log.lock();
        log.iter()
            .filter(|e| {
                op.map_or(true, |o| e.event.contains(o)) &&
                status.map_or(true, |s| e.status.as_ref().map_or(false, |st| st.contains(s))) &&
                context.map_or(true, |c| e.context.as_ref().map_or(false, |cx| cx.contains(c)))
            })
            .cloned()
            .collect()
    }

    /// Export all events 
    pub fn export_all(&self) -> Vec<VaultAuditEvent> {
        self.log.lock().clone()
    }

    /// Erase audit log securely
    pub fn secure_erase(&self) {
        let mut log = self.log.lock();
        for event in log.iter_mut() {
            if let Some(ctx) = &mut event.context {
                for b in unsafe { ctx.as_mut_vec() } {
                    *b = 0;
                }
            }
            if let Some(st) = &mut event.status {
                for b in unsafe { st.as_mut_vec() } {
                    *b = 0;
                }
            }
        }
        log.clear();
    }
}

// Global singleton
pub static VAULT_AUDIT_MANAGER: VaultAuditManager = VaultAuditManager::new();

// ---------- API ----------
pub fn vault_log_event(event: VaultAuditEvent) {
    VAULT_AUDIT_MANAGER.log_event(event);
}
pub fn vault_audit_recent(n: usize) -> Vec<VaultAuditEvent> {
    VAULT_AUDIT_MANAGER.recent(n)
}
pub fn vault_audit_filter(op: Option<&str>, status: Option<&str>, context: Option<&str>) -> Vec<VaultAuditEvent> {
    VAULT_AUDIT_MANAGER.filter(op, status, context)
}
pub fn vault_audit_export() -> Vec<VaultAuditEvent> {
    VAULT_AUDIT_MANAGER.export_all()
}
pub fn vault_audit_secure_erase() {
    VAULT_AUDIT_MANAGER.secure_erase();
}
