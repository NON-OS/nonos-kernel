#![no_std]

use alloc::{vec::Vec, collections::BTreeMap};
use spin::{RwLock, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NonosCapabilityType {
    MemoryRead = 0x1000,
    MemoryWrite = 0x1001,
    MemoryExecute = 0x1002,
    MemoryAllocate = 0x1003,
    ProcessCreate = 0x2000,
    ProcessTerminate = 0x2001,
    ProcessSignal = 0x2002,
    FileRead = 0x3000,
    FileWrite = 0x3001,
    FileCreate = 0x3002,
    FileDelete = 0x3003,
    NetworkBind = 0x4000,
    NetworkConnect = 0x4001,
    SystemShutdown = 0x6000,
    SystemReboot = 0x6001,
    CryptoGenerate = 0x7000,
    CryptoSign = 0x7001,
    CryptoVerify = 0x7002,
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
pub struct NonosCapabilityGrant {
    pub capability: NonosCapabilityType,
    pub subject_id: u64,
    pub object_id: Option<u64>,
    pub granted_time: u64,
    pub expiry_time: Option<u64>,
    pub usage_count: u64,
    pub max_usage: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub enum NonosCapabilityResult {
    Allowed,
    Denied,
    Quarantined,
    Deferred,
}

#[derive(Debug)]
pub struct NonosCapabilityMatrix {
    grants: RwLock<BTreeMap<u64, Vec<NonosCapabilityGrant>>>,
    revocations: RwLock<BTreeMap<u64, Vec<u64>>>,
    audit_log: Mutex<Vec<NonosCapabilityAuditEntry>>,
    real_time_enforcement: bool,
}

#[derive(Debug)]
pub struct NonosCapabilityAuditEntry {
    pub timestamp: u64,
    pub subject_id: u64,
    pub capability: NonosCapabilityType,
    pub object_id: Option<u64>,
    pub result: NonosCapabilityResult,
    pub enforcement_time_ns: u64,
}

impl NonosCapabilityMatrix {
    pub const fn new() -> Self {
        Self {
            grants: RwLock::new(BTreeMap::new()),
            revocations: RwLock::new(BTreeMap::new()),
            audit_log: Mutex::new(Vec::new()),
            real_time_enforcement: true,
        }
    }

    pub fn check_capability(
        &self,
        subject_id: u64,
        capability: NonosCapabilityType,
        object_id: Option<u64>
    ) -> NonosCapabilityResult {
        let start_time = self.get_timestamp_ns();
        
        // Check revocations first
        if let Some(revoked_caps) = self.revocations.read().get(&subject_id) {
            if revoked_caps.contains(&(capability as u64)) {
                self.log_audit_entry(subject_id, capability, object_id, NonosCapabilityResult::Denied, start_time);
                return NonosCapabilityResult::Denied;
            }
        }

        // Check grants
        if let Some(grants) = self.grants.read().get(&subject_id) {
            for grant in grants {
                if grant.capability == capability && self.matches_object(grant, object_id) {
                    if self.validate_grant_conditions(grant) {
                        let enforcement_time = self.get_timestamp_ns() - start_time;
                        self.log_audit_entry(subject_id, capability, object_id, NonosCapabilityResult::Allowed, enforcement_time);
                        return NonosCapabilityResult::Allowed;
                    }
                }
            }
        }

        let enforcement_time = self.get_timestamp_ns() - start_time;
        self.log_audit_entry(subject_id, capability, object_id, NonosCapabilityResult::Denied, enforcement_time);
        NonosCapabilityResult::Denied
    }

    fn matches_object(&self, grant: &NonosCapabilityGrant, object_id: Option<u64>) -> bool {
        match (grant.object_id, object_id) {
            (None, _) => true,
            (Some(g_obj), Some(r_obj)) => g_obj == r_obj,
            _ => false,
        }
    }

    fn validate_grant_conditions(&self, grant: &NonosCapabilityGrant) -> bool {
        let current_time = self.get_timestamp_ns();
        
        // Check expiry
        if let Some(expiry) = grant.expiry_time {
            if current_time > expiry {
                return false;
            }
        }
        
        // Check usage limits
        if let Some(max_usage) = grant.max_usage {
            if grant.usage_count >= max_usage {
                return false;
            }
        }
        
        true
    }

    pub fn grant_capability(
        &self,
        subject_id: u64,
        capability: NonosCapabilityType,
        object_id: Option<u64>
    ) -> Result<(), &'static str> {
        let grant = NonosCapabilityGrant {
            capability,
            subject_id,
            object_id,
            granted_time: self.get_timestamp_ns(),
            expiry_time: None,
            usage_count: 0,
            max_usage: None,
        };

        let mut grants = self.grants.write();
        grants.entry(subject_id).or_insert_with(Vec::new).push(grant);
        
        Ok(())
    }

    pub fn revoke_capability(
        &self,
        subject_id: u64,
        capability: NonosCapabilityType
    ) -> Result<(), &'static str> {
        let mut revocations = self.revocations.write();
        revocations.entry(subject_id).or_insert_with(Vec::new).push(capability as u64);
        
        Ok(())
    }

    fn log_audit_entry(
        &self,
        subject_id: u64,
        capability: NonosCapabilityType,
        object_id: Option<u64>,
        result: NonosCapabilityResult,
        enforcement_time: u64
    ) {
        let entry = NonosCapabilityAuditEntry {
            timestamp: self.get_timestamp_ns(),
            subject_id,
            capability,
            object_id,
            result,
            enforcement_time_ns: enforcement_time,
        };

        if let Some(mut log) = self.audit_log.try_lock() {
            log.push(entry);
            
            // Maintain log size
            if log.len() > 10000 {
                log.drain(0..1000);
            }
        }
    }

    fn get_timestamp_ns(&self) -> u64 {
        // Hardware timestamp counter
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    pub fn get_capability_statistics(&self) -> NonosCapabilityStatistics {
        let audit_log = self.audit_log.lock();
        let total_checks = audit_log.len() as u64;
        let allowed_checks = audit_log.iter()
            .filter(|e| matches!(e.result, NonosCapabilityResult::Allowed))
            .count() as u64;
        let denied_checks = audit_log.iter()
            .filter(|e| matches!(e.result, NonosCapabilityResult::Denied))
            .count() as u64;
        
        let average_enforcement_time = if total_checks > 0 {
            audit_log.iter().map(|e| e.enforcement_time_ns).sum::<u64>() / total_checks
        } else {
            0
        };

        NonosCapabilityStatistics {
            total_checks,
            allowed_checks,
            denied_checks,
            average_enforcement_time_ns: average_enforcement_time,
        }
    }
}

#[derive(Debug)]
pub struct NonosCapabilityStatistics {
    pub total_checks: u64,
    pub allowed_checks: u64,
    pub denied_checks: u64,
    pub average_enforcement_time_ns: u64,
}

// Global capability matrix instance
pub static NONOS_CAPABILITY_MATRIX: NonosCapabilityMatrix = NonosCapabilityMatrix::new();

// Convenience functions
pub fn check_capability(
    subject_id: u64,
    capability: NonosCapabilityType,
    object_id: Option<u64>
) -> NonosCapabilityResult {
    NONOS_CAPABILITY_MATRIX.check_capability(subject_id, capability, object_id)
}

pub fn grant_capability(
    subject_id: u64,
    capability: NonosCapabilityType,
    object_id: Option<u64>
) -> Result<(), &'static str> {
    NONOS_CAPABILITY_MATRIX.grant_capability(subject_id, capability, object_id)
}

pub fn revoke_capability(
    subject_id: u64,
    capability: NonosCapabilityType
) -> Result<(), &'static str> {
    NONOS_CAPABILITY_MATRIX.revoke_capability(subject_id, capability)
}

pub fn get_capability_stats() -> NonosCapabilityStatistics {
    NONOS_CAPABILITY_MATRIX.get_capability_statistics()
}

/// Initialize the NONOS capability system
pub fn init_nonos_capabilities() -> Result<(), &'static str> {
    // The global static is already initialized, but we can perform any setup here
    crate::log::logger::log_info!("NONOS capability system initialized");
    Ok(())
}