//! Advanced Sandbox System
//! 
//! Hardware-assisted sandboxing with capability enforcement

use crate::memory::region::MemRegion;
use crate::syscall::capabilities::CapabilityToken;
use alloc::{string::String, format};

/// Sandbox context for module execution
#[derive(Debug, Clone)]
pub struct SandboxContext {
    pub name: String,
    pub memory: MemRegion,
    pub capabilities: CapabilityToken,
    pub state: SandboxState,
}

#[derive(Debug, Clone, Copy)]
pub enum SandboxState {
    Created,
    Running,
    Suspended,
    Terminated,
}

/// Attestation data for sandbox
pub struct SandboxAttestation {
    pub state: SandboxState,
    pub memory_used: usize,
    pub cpu_time: u64,
    pub syscalls_made: u64,
}

impl SandboxContext {
    /// Get execution ID for tracking
    pub fn exec_id(&self) -> [u8; 32] {
        use crate::crypto::hash::blake3_hash;
        let data = format!("{}:{}", self.name, self.memory.start);
        blake3_hash(data.as_bytes())
    }
    
    /// Export attestation data
    pub fn export_attestation(&self) -> SandboxAttestation {
        SandboxAttestation {
            state: self.state,
            memory_used: self.memory.size,
            cpu_time: 0, // Would track actual CPU time
            syscalls_made: 0, // Would track syscall count
        }
    }
}
