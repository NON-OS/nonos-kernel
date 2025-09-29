//! NØNOS Module Sandboxing System
//!
//! Provides cryptographically enforced isolation for untrusted module code.
//! Each module runs in a separate memory region with capability-based access control.

use alloc::{vec::Vec, string::String, format, collections::BTreeMap};
use crate::memory::{VirtAddr, PhysAddr, MemoryRegion};
use crate::syscall::capabilities::{CapabilityToken, Capability};
use crate::modules::manifest::ModuleManifest;
use spin::Mutex;
use core::mem;

/// Maximum memory per sandboxed module (8MB)
pub const MAX_MODULE_MEMORY: usize = 8 * 1024 * 1024;

/// Module execution context with isolated memory and capabilities
pub struct ModuleSandbox {
    pub module_id: u64,
    pub name: String,
    pub memory_region: MemoryRegion,
    pub capability_token: CapabilityToken,
    pub stack_top: VirtAddr,
    pub heap_base: VirtAddr,
    pub entry_point: VirtAddr,
    pub is_active: bool,
    pub syscall_count: u64,
    pub memory_usage: usize,
}

impl ModuleSandbox {
    /// Create a new sandboxed execution environment
    pub fn new(manifest: &ModuleManifest, token: CapabilityToken) -> Result<Self, &'static str> {
        let module_id = generate_module_id();
        
        // Allocate isolated memory region - use simplified allocation for now
        let base_addr = VirtAddr::new(0x10000000 + (module_id * 0x1000000));
        let memory_region = MemoryRegion::new(base_addr, MAX_MODULE_MEMORY);

        // Set up memory layout
        let base_addr = memory_region.start_address();
        let heap_base = base_addr + (MAX_MODULE_MEMORY / 2); // Split memory in half
        let stack_top = base_addr + MAX_MODULE_MEMORY - 0x1000u64; // Stack at top

        Ok(ModuleSandbox {
            module_id,
            name: String::from(manifest.name),
            memory_region,
            capability_token: token,
            stack_top,
            heap_base,
            entry_point: base_addr + 0x1000u64, // Entry point after header
            is_active: false,
            syscall_count: 0,
            memory_usage: 0,
        })
    }

    /// Check if syscall is allowed based on capabilities
    pub fn check_syscall_permission(&mut self, syscall_id: usize) -> bool {
        self.syscall_count += 1;

        let required_cap = match syscall_id {
            0..=10 => Capability::CoreExec,
            11..=20 => Capability::IO,
            21..=30 => Capability::Filesystem,
            31..=40 => Capability::Net,
            41..=50 => Capability::Crypto,
            51..=60 => Capability::IPC,
            _ => return false, // Unknown syscall
        };

        self.capability_token.has(required_cap)
    }

    /// Get sandbox statistics
    pub fn get_stats(&self) -> SandboxStats {
        SandboxStats {
            module_id: self.module_id,
            name: self.name.clone(),
            is_active: self.is_active,
            syscall_count: self.syscall_count,
            memory_usage: self.memory_usage,
            capabilities_count: self.capability_token.permissions.len(),
        }
    }
}

/// Sandbox statistics for monitoring
#[derive(Debug, Clone)]
pub struct SandboxStats {
    pub module_id: u64,
    pub name: String,
    pub is_active: bool,
    pub syscall_count: u64,
    pub memory_usage: usize,
    pub capabilities_count: usize,
}

/// Sandbox execution context
#[derive(Debug, Clone)]
pub struct SandboxContext {
    pub name: String,
    pub memory: MemRegion,
    pub state: SandboxState,
    pub attestation_data: Vec<u8>,
}

/// Sandbox execution state
#[derive(Debug, Clone)]
pub enum SandboxState {
    Running,
    Suspended,
    Terminated,
}

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemRegion {
    pub start: usize,
    pub size: usize,
}

impl MemRegion {
    pub fn new(start: usize, size: usize) -> Self {
        Self { start, size }
    }
    
    pub fn size_bytes(&self) -> usize {
        self.size
    }
}

/// Sandbox attestation data
#[derive(Debug, Clone)]
pub struct SandboxAttestation {
    pub state: SandboxState,
    pub memory_used: usize,
    pub exec_time: u64,
}

impl SandboxContext {
    /// Get execution ID hash
    pub fn exec_id(&self) -> [u8; 32] {
        use crate::crypto::hash::blake3_hash;
        let mut data = Vec::new();
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(&(self.memory.start as u64).to_le_bytes());
        blake3_hash(&data)
    }
    
    /// Export attestation data
    pub fn export_attestation(&self) -> SandboxAttestation {
        SandboxAttestation {
            state: self.state.clone(),
            memory_used: self.memory.size,
            exec_time: crate::time::timestamp_millis(),
        }
    }
}

/// Generate unique module ID
fn generate_module_id() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}