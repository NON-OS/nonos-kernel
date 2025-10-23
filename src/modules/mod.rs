//! NØNOS Modules Subsystem 

pub mod nonos_auth;
pub mod nonos_manifest;
pub mod nonos_loader;
pub mod nonos_mod_runner;
pub mod nonos_registry;
pub mod nonos_sandbox;
pub mod nonos_module_loader;

// Re-exports for compatibility
pub use nonos_module_loader as mod_loader;
pub use nonos_manifest as manifest;
pub use nonos_mod_runner as runtime;

use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::RwLock;

/// Active modules registry with real module tracking
static ACTIVE_MODULES: RwLock<BTreeMap<String, ModuleInfo>> = RwLock::new(BTreeMap::new());

#[derive(Debug, Clone)]
struct ModuleInfo {
    id: String,
    loaded: bool,
    entry_point: Option<fn()>,
}

/// Check if a module is currently active and loaded
pub fn is_module_active(module_id: &str) -> bool {
    let modules = ACTIVE_MODULES.read();
    if let Some(module) = modules.get(module_id) {
        module.loaded
    } else {
        false
    }
}

/// Register a module as active
pub fn register_active_module(module_id: &str, entry_point: Option<fn()>) {
    let mut modules = ACTIVE_MODULES.write();
    modules.insert(module_id.into(), ModuleInfo {
        id: module_id.into(),
        loaded: true,
        entry_point,
    });
}

/// Deregister a module 
pub fn deregister_module(module_id: &str) {
    let mut modules = ACTIVE_MODULES.write();
    modules.remove(module_id);
}
