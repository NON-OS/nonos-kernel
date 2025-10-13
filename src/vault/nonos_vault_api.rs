//! NØNOS Vault Public API & Syscall Layer 

extern crate alloc;
use alloc::{string::String, vec::Vec};
use crate::vault::nonos_vault::*;
use crate::vault::nonos_vault_seal::*;
use crate::vault::nonos_vault_policy::*;
use crate::vault::nonos_vault_crypto::*;
use crate::crypto::Hash256;

/// Vault API error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultApiError {
    NotInitialized,
    PolicyDenied,
    KeyNotFound,
    SealFailed,
    UnsealFailed,
    InvalidArguments,
    InternalError,
}

/// Vault API result type
pub type VaultApiResult<T> = core::result::Result<T, VaultApiError>;

/// Initialize the vault subsystem (all modules)
pub fn vault_init() -> VaultApiResult<()> {
    initialize_vault().map_err(|_| VaultApiError::InternalError)?;
    Ok(())
}

/// Check vault status
pub fn vault_status() -> bool {
    vault_initialized()
}

/// Derive a key (policy enforced)
pub fn vault_derive(context: &str, key_length: usize, caller: &str) -> VaultApiResult<Vec<u8>> {
    if !check_vault_policy(caller, VaultCapability::Derive) {
        return Err(VaultApiError::PolicyDenied);
    }
    let key = derive_vault_key(context, key_length).map_err(|_| VaultApiError::KeyNotFound)?;
    increment_vault_policy_usage(caller, VaultCapability::Derive);
    Ok(key)
}

/// Seal a secret (policy enforced)
pub fn vault_seal(
    plaintext: &[u8],
    aad: &[u8],
    policy: SealPolicy,
    caller: &str,
) -> VaultApiResult<SealedSecret> {
    if !check_vault_policy(caller, VaultCapability::Seal) {
        return Err(VaultApiError::PolicyDenied);
    }
    let sealed = seal_secret(plaintext, aad, policy).map_err(|_| VaultApiError::SealFailed)?;
    increment_vault_policy_usage(caller, VaultCapability::Seal);
    Ok(sealed)
}

/// Unseal a secret (policy enforced)
pub fn vault_unseal(
    sealed: &SealedSecret,
    caller: &str,
) -> VaultApiResult<Vec<u8>> {
    if !check_vault_policy(caller, VaultCapability::Unseal) {
        return Err(VaultApiError::PolicyDenied);
    }
    let data = unseal_secret(sealed).map_err(|_| VaultApiError::UnsealFailed)?;
    increment_vault_policy_usage(caller, VaultCapability::Unseal);
    Ok(data)
}

/// Secure erase (policy enforced)
pub fn vault_erase(caller: &str) -> VaultApiResult<()> {
    if !check_vault_policy(caller, VaultCapability::Erase) {
        return Err(VaultApiError::PolicyDenied);
    }
    secure_erase_vault();
    secure_erase_sealed(None);
    increment_vault_policy_usage(caller, VaultCapability::Erase);
    Ok(())
}

/// List recent audit events
pub fn vault_audit(n: usize) -> Vec<VaultAuditEvent> {
    vault_recent_audit(n)
}

/// Diagnostics: List all current policies
pub fn vault_list_policies() -> Vec<(String, Vec<VaultPolicyRule>)> {
    list_vault_policies()
}

/// Statistics: Vault status and usage
pub struct VaultStats {
    pub initialized: bool,
    pub audit_events: usize,
    pub policies: usize,
}

pub fn vault_stats() -> VaultStats {
    VaultStats {
        initialized: vault_initialized(),
        audit_events: vault_recent_audit(usize::MAX).len(),
        policies: vault_list_policies().len(),
    }
}

pub fn vault_syscall_dispatch(
    op: u32,
    args: &[u8],
    caller: &str,
) -> VaultApiResult<Vec<u8>> {
    match op {
        0 => { // Init
            vault_init()?;
            Ok(Vec::new())
        }
        1 => { // Derive key
            let context = core::str::from_utf8(&args[..32]).unwrap_or_default();
            let keylen = u32::from_le_bytes(args[32..36].try_into().unwrap_or([0;4])) as usize;
            vault_derive(context, keylen, caller)
        }
        2 => { // Seal
            // args: plaintext || aad || policy
            Err(VaultApiError::InvalidArguments)
        }
        3 => { // Unseal
            // args: sealed secret serialization
            Err(VaultApiError::InvalidArguments)
        }
        4 => { // Erase
            vault_erase(caller)?;
            Ok(Vec::new())
        }
        _ => Err(VaultApiError::InvalidArguments),
    }
}
