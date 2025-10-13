#![no_std]

extern crate alloc;

use crate::capabilities::{
    Capability, CapabilityToken, create_token, sign_token, verify_token, revoke_token, has_signing_key, roles,
    delegation, audit, resource, multisig, chain,
};
use alloc::vec::Vec;

/// Returns the signed capability token for the current process.
/// On process/session startup, a `CapabilityToken` should be minted and signed using the kernel key.
pub fn current_caps() -> CapabilityToken {
    let proc = crate::process::current_process().expect("no process context");
    // Must be a signed cryptographic CapabilityToken, not a bitmask.
    proc.capability_token()
}

/// Mint a new token for a process with a given role and expiry (ms).
/// Call on process/session creation, store as proc.capability_token.
pub fn mint_process_token(owner_module: u64, role: &[Capability], ttl_ms: Option<u64>) -> CapabilityToken {
    create_token(owner_module, role, ttl_ms).expect("token mint failed")
}

/// Revoke a token (owner + nonce).
pub fn revoke_process_token(token: &CapabilityToken) {
    revoke_token(token.owner_module, token.nonce);
}

/// Check if a token is valid (signature, expiry, revocation).
pub fn is_token_valid(token: &CapabilityToken) -> bool {
    token.is_valid()
}

/// Accessor methods for syscall checks 
impl CapabilityToken {
    #[inline] pub fn can_exit(&self)   -> bool { self.grants(Capability::CoreExec) && self.is_valid() }
    #[inline] pub fn can_read(&self)   -> bool { self.grants(Capability::IO) && self.is_valid() }
    #[inline] pub fn can_write(&self)  -> bool { self.grants(Capability::IO) && self.is_valid() }
    #[inline] pub fn can_open_files(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_close_files(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_stat(&self)   -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_seek(&self)   -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_allocate_memory(&self) -> bool { self.grants(Capability::Memory) && self.is_valid() }
    #[inline] pub fn can_deallocate_memory(&self) -> bool { self.grants(Capability::Memory) && self.is_valid() }
    #[inline] pub fn can_modify_dirs(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }
    #[inline] pub fn can_unlink(&self) -> bool { self.grants(Capability::FileSystem) && self.is_valid() }

}

/// Delegation API
pub use delegation::{
    Delegation, create_delegation, sign_delegation, verify_delegation
};

/// Audit API
pub use audit::{
    AuditEntry, log_use, get_log
};

/// Resource token API
pub use resource::{
    ResourceQuota, ResourceToken, create_resource_token, sign_resource_token, verify_resource_token
};

/// Multi-sig API
pub use multisig::{
    MultiSigToken, create_multisig_token, add_signature, verify_multisig
};

/// Capability chain API
pub use chain::{
    CapabilityChain
};

/// Role presets re-export
pub use roles::{KERNEL, SYSTEM_SERVICE, SANDBOXED_MOD};

/// Capability system initialization.
/// Must be called at boot after `set_signing_key()` (see capabilities/mod.rs).
pub fn init_capabilities() {
    if !has_signing_key() {
        panic!("capabilities: signing key not set; call set_signing_key() at boot");
    }
}
