//! NØNOS Capsule Runtime Manager
//!
//! Manages the lifecycle of isolated execution capsules in the zero-state
//! environment.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::log::logger::{log_info, log_warn};
use crate::memory::region::MemRegion;
use crate::modules::runtime::{CapsuleState, RuntimeCapsule};
use alloc::{string::String, vec::Vec};

/// Unique capsule identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapsuleId(pub u64);

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl CapsuleId {
    pub fn new() -> Self {
        CapsuleId(NEXT_ID.fetch_add(1, Ordering::SeqCst))
    }
}

/// Capsule runtime environment
pub struct CapsuleRuntime {
    pub id: CapsuleId,
    pub name: String,
    pub memory: MemRegion,
    pub state: Arc<RwLock<RuntimeCapsule>>,
    pub parent: Option<CapsuleId>,
    pub children: Vec<CapsuleId>,
}

impl CapsuleRuntime {
    pub fn new(name: String, memory: MemRegion, runtime: RuntimeCapsule) -> Self {
        Self {
            id: CapsuleId::new(),
            name,
            memory,
            state: Arc::new(RwLock::new(runtime)),
            parent: None,
            children: Vec::new(),
        }
    }

    /// Check if capsule is still active
    pub fn is_active(&self) -> bool {
        self.state.read().is_active()
    }

    /// Suspend the capsule
    pub fn suspend(&self) {
        self.state.write().suspend();
    }

    /// Resume from suspension
    pub fn resume(&self) {
        let mut state = self.state.write();
        if state.state() == CapsuleState::Suspended {
            state.state = CapsuleState::Active;
            state.tick();
        }
    }

    /// Terminate the capsule
    pub fn terminate(&self) {
        self.state.write().terminate();

        // Clean up children
        for child_id in &self.children {
            if let Some(child) = get_capsule(*child_id) {
                child.terminate();
            }
        }
    }
}

// Global capsule registry
static CAPSULES: RwLock<heapless::FnvIndexMap<CapsuleId, Arc<CapsuleRuntime>, 256>> =
    RwLock::new(heapless::FnvIndexMap::new());

/// Initialize capsule runtime subsystem
pub fn init_capsule_runtime() {
    log_info!("[CAPSULE] Runtime manager initialized");
}

/// Register a new capsule
pub fn register_capsule(runtime: CapsuleRuntime) -> CapsuleId {
    let id = runtime.id;
    let arc = Arc::new(runtime);

    CAPSULES.write().insert(id, arc.clone()).ok();

    log_info!("[CAPSULE] Registered capsule {:?}: {}", id, arc.name);
    id
}

/// Get capsule by ID
pub fn get_capsule(id: CapsuleId) -> Option<Arc<CapsuleRuntime>> {
    CAPSULES.read().get(&id).cloned()
}

/// Remove capsule from registry
pub fn unregister_capsule(id: CapsuleId) {
    if let Some(capsule) = CAPSULES.write().remove(&id) {
        log_info!("[CAPSULE] Unregistered capsule {:?}: {}", id, capsule.name);
    }
}

/// List all active capsules
pub fn list_active_capsules() -> Vec<(CapsuleId, String)> {
    CAPSULES
        .read()
        .iter()
        .filter(|(_, c)| c.is_active())
        .map(|(id, c)| (*id, c.name.clone()))
        .collect()
}

/// Get runtime statistics
pub struct CapsuleStats {
    pub total: usize,
    pub active: usize,
    pub suspended: usize,
    pub memory_used: usize,
}

pub fn get_stats() -> CapsuleStats {
    let capsules = CAPSULES.read();
    let mut stats = CapsuleStats { total: capsules.len(), active: 0, suspended: 0, memory_used: 0 };

    for capsule in capsules.values() {
        stats.memory_used += capsule.memory.size_bytes() as usize;

        match capsule.state.read().state() {
            CapsuleState::Active => stats.active += 1,
            CapsuleState::Suspended => stats.suspended += 1,
            _ => {}
        }
    }

    stats
}
