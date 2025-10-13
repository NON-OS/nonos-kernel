//! NØNOS Secure Sandbox

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;
use crate::process::capabilities::Capability;
use crate::memory::{secure_erase, allocate_zeroed_pages, deallocate_pages};
use crate::crypto::{
    kyber::{kyber_keygen, KyberKeyPair},
    dilithium::{dilithium_keypair, DilithiumKeyPair},
};

/// Configuration for a sandbox context (RAM-only).
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub memory_limit: usize,                // bytes
    pub allowed_capabilities: Vec<Capability>,
    pub audit: bool,                        // audit activity in RAM, never persisted
    pub quantum_isolation: bool,            // enable PQC boundary (Kyber/Dilithium)
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit: 4096,
            allowed_capabilities: Vec::new(),
            audit: false,
            quantum_isolation: false,
        }
    }
}

/// Internal sandbox state (RAM-only, never persisted)
#[derive(Debug)]
struct SandboxState {
    pub module_id: u64,
    pub base_addr: usize,
    pub size: usize,
    pub capabilities: Vec<Capability>,
    pub quantum_keys: Option<(KyberKeyPair, DilithiumKeyPair)>,
}

/// Registry of created sandboxes (RAM-only, zero-state)
static SANDBOXES: Mutex<Vec<SandboxState>> = Mutex::new(Vec::new());

/// Create a RAM-only sandbox for a module
pub fn setup_sandbox(module_id: u64, config: &SandboxConfig) -> Result<(), &'static str> {
    if config.memory_limit == 0 {
        return Err("Sandbox memory limit must be nonzero");
    }
    // Enforce capability boundary
    for cap in &config.allowed_capabilities {
        if !cap.is_allowed() {
            return Err("Sandbox capability violation");
        }
    }
    // Allocate zeroed, RAM-only pages for sandbox memory
    let base_addr = allocate_zeroed_pages((config.memory_limit + 4095) / 4096)?; // returns physical address

    // PQC keys for quantum isolation (Kyber KEM + Dilithium signature)
    let quantum_keys = if config.quantum_isolation {
        let kyber_keys = kyber_keygen().map_err(|_| "Kyber keygen failed")?;
        let dilithium_keys = dilithium_keypair().map_err(|_| "Dilithium keygen failed")?;
        Some((kyber_keys, dilithium_keys))
    } else {
        None
    };

    // Store sandbox state in RAM-only registry
    SANDBOXES.lock().push(SandboxState {
        module_id,
        base_addr,
        size: config.memory_limit,
        capabilities: config.allowed_capabilities.clone(),
        quantum_keys,
    });
    Ok(())
}

/// Destroy a sandbox and securely erase all associated RAM and cryptographic keys.
pub fn destroy_sandbox(module_id: u64, config: &SandboxConfig) -> Result<(), &'static str> {
    let mut sandboxes = SANDBOXES.lock();
    if let Some(idx) = sandboxes.iter().position(|s| s.module_id == module_id) {
        let mut state = sandboxes.remove(idx);
        // Securely erase RAM
        unsafe {
            secure_erase(core::slice::from_raw_parts_mut(state.base_addr as *mut u8, state.size));
            deallocate_pages(state.base_addr, (state.size + 4095) / 4096)?;
        }
        // Securely erase PQC keys (Kyber/Dilithium)
        if let Some((kyber_keys, dilithium_keys)) = state.quantum_keys.take() {
            let mut pk = kyber_keys.public_key.bytes;
            let mut sk = kyber_keys.secret_key.bytes;
            let mut dkpk = dilithium_keys.public_key.bytes;
            let mut dksk = dilithium_keys.secret_key.bytes;
            for b in pk.iter_mut() { unsafe { ptr::write_volatile(b, 0) }; }
            for b in sk.iter_mut() { unsafe { ptr::write_volatile(b, 0) }; }
            for b in dkpk.iter_mut() { unsafe { ptr::write_volatile(b, 0) }; }
            for b in dksk.iter_mut() { unsafe { ptr::write_volatile(b, 0) }; }
        }
        Ok(())
    } else {
        Err("Sandbox not found for destruction")
    }
}

/// Query if a module currently has a sandbox (RAM-only)
pub fn is_sandbox_active(module_id: u64) -> bool {
    SANDBOXES.lock().iter().any(|s| s.module_id == module_id)
}

/// List all active sandboxes (RAM-only)
pub fn list_active_sandboxes() -> Vec<u64> {
    SANDBOXES.lock().iter().map(|s| s.module_id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::capabilities::Capability;

    #[test]
    fn test_setup_and_destroy_sandbox_basic() {
        let mut cfg = SandboxConfig::default();
        cfg.memory_limit = 4096;
        cfg.allowed_capabilities = vec![];
        cfg.quantum_isolation = true;
        let module_id = 12345;
        assert!(setup_sandbox(module_id, &cfg).is_ok());
        assert!(is_sandbox_active(module_id));
        assert!(destroy_sandbox(module_id, &cfg).is_ok());
        assert!(!is_sandbox_active(module_id));
    }

    #[test]
    fn test_capability_violation() {
        let mut cfg = SandboxConfig::default();
        cfg.memory_limit = 4096;
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct Forbidden;
        impl Capability {
            pub fn is_allowed(&self) -> bool {
                false
            }
        }
        cfg.allowed_capabilities = vec![Capability::default()];
        assert!(setup_sandbox(2, &cfg).is_err());
    }

    #[test]
    fn test_list_active() {
        let module_id = 222;
        let cfg = SandboxConfig { memory_limit: 4096, allowed_capabilities: vec![], audit: false, quantum_isolation: false };
        setup_sandbox(module_id, &cfg).unwrap();
        let active = list_active_sandboxes();
        assert!(active.contains(&module_id));
        destroy_sandbox(module_id, &cfg).unwrap();
    }
}
