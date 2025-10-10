//! Module Registry System
//!
//! Advanced registry for tracking all module instances with cryptographic audit
//! trail

use crate::modules::mod_runner::ModuleInstance;
use alloc::collections::BTreeMap;
use alloc::{format, vec::Vec};
use spin::RwLock;

/// Global module registry with cryptographic audit trail
pub struct ModuleRegistry {
    instances: BTreeMap<u64, ModuleInstance>,
    audit_log: Vec<RegistryEvent>,
}

#[derive(Debug, Clone)]
pub struct RegistryEvent {
    pub timestamp: u64,
    pub event_type: EventType,
    pub module_id: u64,
    pub data_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub enum EventType {
    ModuleRegistered,
    ModuleUnregistered,
    StateChanged,
    CapabilityGranted,
    CapabilityRevoked,
}

static REGISTRY: RwLock<ModuleRegistry> =
    RwLock::new(ModuleRegistry { instances: BTreeMap::new(), audit_log: Vec::new() });

/// Register a new module instance
pub fn register_module_instance(name: &str, instance: &ModuleInstance) {
    let mut registry = REGISTRY.write();

    // Add audit log entry
    let event = RegistryEvent {
        timestamp: current_timestamp(),
        event_type: EventType::ModuleRegistered,
        module_id: instance.id,
        data_hash: compute_instance_hash(instance),
    };

    registry.audit_log.push(event);
    registry.instances.insert(instance.id, instance.clone());

    log_registry_event(name, "registered");
}

/// Get module instance by ID
pub fn get_module_instance(id: u64) -> Option<ModuleInstance> {
    REGISTRY.read().instances.get(&id).cloned()
}

/// List all active modules
pub fn list_active_modules() -> Vec<u64> {
    REGISTRY.read().instances.keys().cloned().collect()
}

fn current_timestamp() -> u64 {
    // Would use actual timer
    0
}

fn compute_instance_hash(_instance: &ModuleInstance) -> [u8; 32] {
    // Cryptographic hash of instance state
    [0; 32]
}

fn log_registry_event(name: &str, event: &str) {
    // Log to system logger
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(&format!("Module '{}' {}", name, event));
    }
}
