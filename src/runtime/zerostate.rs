//! NØNOS ZeroState Runtime Core
//!
//! Implements the ephemeral, RAM-only execution environment where nothing
//! persists across reboots. All state is cryptographically tracked but never
//! written to persistent storage.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;

use crate::crypto::hash::blake3_hash;
use crate::log::logger::{log_info, log_warn};
use crate::memory::region::MemRegion;
use crate::modules::sandbox::SandboxContext;
use alloc::vec::Vec;

/// Global ZeroState configuration
#[derive(Clone, Copy)]
pub struct ZeroStateConfig {
    pub max_capsules: usize,
    pub ephemeral_heap_size: usize,
    pub enable_attestation: bool,
    pub checkpoint_interval_ms: u64,
}

impl Default for ZeroStateConfig {
    fn default() -> Self {
        Self {
            max_capsules: 256,
            ephemeral_heap_size: 128 * 1024 * 1024, // 128MB
            enable_attestation: true,
            checkpoint_interval_ms: 5000,
        }
    }
}

/// Runtime state snapshot
#[derive(Clone)]
pub struct StateSnapshot {
    pub timestamp: u64,
    pub hash: [u8; 32],
    pub capsule_count: usize,
    pub memory_used: usize,
    pub proof_root: [u8; 32],
}

/// Active sandboxes registry
struct SandboxRegistry {
    sandboxes: BTreeMap<[u8; 32], SandboxContext>,
    total_memory: usize,
    snapshot_counter: u64,
}

static REGISTRY: RwLock<Option<SandboxRegistry>> = RwLock::new(None);
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static EPOCH: AtomicU64 = AtomicU64::new(0);
static CONFIG: RwLock<ZeroStateConfig> = RwLock::new(ZeroStateConfig {
    max_capsules: 256,
    ephemeral_heap_size: 128 * 1024 * 1024,
    enable_attestation: true,
    checkpoint_interval_ms: 5000,
});

/// Initialize the ZeroState runtime
pub fn init_zerostate() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize registry
    *REGISTRY.write() =
        Some(SandboxRegistry { sandboxes: BTreeMap::new(), total_memory: 0, snapshot_counter: 0 });

    // Start new epoch
    EPOCH.store(generate_epoch(), Ordering::SeqCst);

    // Initialize ephemeral memory pool
    init_ephemeral_pool();

    // Start attestation service if enabled
    if CONFIG.read().enable_attestation {
        start_attestation_service();
    }

    log_info!("[ZEROSTATE] Runtime initialized with epoch {}", EPOCH.load(Ordering::Relaxed));
}

/// Track an active sandbox in the zero-state registry
pub fn track_active_sandbox(sandbox: &SandboxContext) {
    let mut reg = REGISTRY.write();
    if let Some(registry) = reg.as_mut() {
        registry.sandboxes.insert(sandbox.exec_id(), sandbox.clone());
        registry.total_memory += sandbox.memory.size;
        registry.snapshot_counter += 1;

        // Generate attestation
        if CONFIG.read().enable_attestation {
            generate_attestation(sandbox);
        }
    }
}

/// Remove sandbox from tracking
pub fn untrack_sandbox(exec_id: &[u8; 32]) {
    let mut reg = REGISTRY.write();
    if let Some(registry) = reg.as_mut() {
        if let Some(sandbox) = registry.sandboxes.remove(exec_id) {
            registry.total_memory -= sandbox.memory.size;

            // Zero out memory before release
            zero_memory_region(&sandbox.memory);
        }
    }
}

/// Generate a state snapshot for attestation
pub fn snapshot_state() -> StateSnapshot {
    let reg = REGISTRY.read();
    let registry = reg.as_ref().expect("ZeroState not initialized");

    // Compute merkle root of all active sandboxes
    let mut hasher = blake3::Hasher::new();
    for (exec_id, _) in &registry.sandboxes {
        hasher.update(exec_id);
    }
    let proof_root = *hasher.finalize().as_bytes();

    // Compute overall state hash
    let mut state_data = Vec::new();
    state_data.extend_from_slice(&EPOCH.load(Ordering::Relaxed).to_le_bytes());
    state_data.extend_from_slice(&(registry.sandboxes.len() as u64).to_le_bytes());
    state_data.extend_from_slice(&(registry.total_memory as u64).to_le_bytes());
    state_data.extend_from_slice(&proof_root);

    let hash = blake3_hash(&state_data);

    StateSnapshot {
        timestamp: current_time(),
        hash,
        capsule_count: registry.sandboxes.len(),
        memory_used: registry.total_memory,
        proof_root,
    }
}

/// Check if we're at capacity
pub fn can_admit_capsule(memory_required: usize) -> bool {
    let reg = REGISTRY.read();
    if let Some(registry) = reg.as_ref() {
        let config = CONFIG.read();

        registry.sandboxes.len() < config.max_capsules
            && registry.total_memory + memory_required <= config.ephemeral_heap_size
    } else {
        false
    }
}

/// Get current epoch
pub fn current_epoch() -> u64 {
    EPOCH.load(Ordering::Relaxed)
}

/// Force a new epoch (invalidates all prior attestations)
pub fn rotate_epoch() {
    let new_epoch = generate_epoch();
    EPOCH.store(new_epoch, Ordering::SeqCst);

    // Clear all sandboxes on epoch rotation
    let mut reg = REGISTRY.write();
    if let Some(registry) = reg.as_mut() {
        let sandboxes = core::mem::take(&mut registry.sandboxes);
        for (_, sandbox) in sandboxes {
            zero_memory_region(&sandbox.memory);
        }
        registry.total_memory = 0;
        registry.snapshot_counter = 0;
    }

    log_warn!("[ZEROSTATE] Epoch rotated to {}, all state cleared", new_epoch);
}

// ===== Private Helpers =====

fn init_ephemeral_pool() {
    // Allocate ephemeral heap from physical memory
    let config = CONFIG.read();
    let pages = config.ephemeral_heap_size / 4096;

    // This would allocate from phys and map to a dedicated VA range
    // For now, we track virtually

    log_info!("[ZEROSTATE] Ephemeral pool: {} MB", config.ephemeral_heap_size / (1024 * 1024));
}

fn start_attestation_service() {
    use crate::sched::task;

    extern "C" fn attestation_thread(_: usize) -> ! {
        loop {
            let snapshot = snapshot_state();

            // Publish attestation event (TODO: Add ProofRoot variant to Event enum)
            // crate::ui::event::publish(crate::ui::event::Event::ProofRoot {
            //     root: snapshot.proof_root,
            //     epoch: current_epoch(),
            // });

            // Sleep until next checkpoint
            let interval_ms = CONFIG.read().checkpoint_interval_ms;
            crate::arch::x86_64::time::timer::sleep_long_ns(interval_ms * 1_000_000, || {});
        }
    }

    task::kspawn(
        "zerostate.attestation",
        attestation_thread,
        0,
        task::Priority::Low,
        task::Affinity::ANY,
    );
}

fn generate_attestation(sandbox: &SandboxContext) {
    let attestation = sandbox.export_attestation();

    // Log to audit trail
    log_info!(
        "[ZEROSTATE] Attestation: capsule {} | state={:?} | mem={}KB",
        sandbox.name,
        attestation.state,
        attestation.memory_used / 1024
    );

    // Could publish to network or store in ring buffer
}

fn zero_memory_region(region: &MemRegion) {
    unsafe {
        core::ptr::write_bytes(region.start as *mut u8, 0, region.size_bytes() as usize);
    }
}

fn generate_epoch() -> u64 {
    // Combine boot time with entropy
    let boot_ns = crate::arch::x86_64::time::timer::now_ns();
    let entropy = crate::crypto::entropy::rand_u64();
    boot_ns ^ entropy.rotate_left(17)
}

fn current_time() -> u64 {
    crate::arch::x86_64::time::timer::now_ns()
}

// ===== Public Statistics =====

pub struct ZeroStateStats {
    pub epoch: u64,
    pub active_capsules: usize,
    pub memory_used: usize,
    pub memory_available: usize,
    pub snapshots_taken: u64,
}

pub fn get_stats() -> ZeroStateStats {
    let reg = REGISTRY.read();
    let config = CONFIG.read();

    if let Some(registry) = reg.as_ref() {
        ZeroStateStats {
            epoch: current_epoch(),
            active_capsules: registry.sandboxes.len(),
            memory_used: registry.total_memory,
            memory_available: config.ephemeral_heap_size - registry.total_memory,
            snapshots_taken: registry.snapshot_counter,
        }
    } else {
        ZeroStateStats {
            epoch: 0,
            active_capsules: 0,
            memory_used: 0,
            memory_available: 0,
            snapshots_taken: 0,
        }
    }
}
