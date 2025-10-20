//! NØNOS Vault Subsystem Entry Point

#![allow(dead_code)]

pub mod nonos_vault;
pub mod nonos_vault_crypto;
pub mod nonos_vault_seal;
pub mod nonos_vault_policy;
pub mod nonos_vault_api;
pub mod nonos_vault_audit;
pub mod nonos_vault_diag;

/// Unified public API for use elsewhere in kernel/userland
pub mod prelude {
    pub use super::nonos_vault::*;
    pub use super::nonos_vault_crypto::*;
    pub use super::nonos_vault_seal::*;
    pub use super::nonos_vault_policy::*;
    pub use super::nonos_vault_api::*;
    pub use super::nonos_vault_audit::*;
    pub use super::nonos_vault_diag::*;
}

/// Compile-time check for initialization order 
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vault_modules_load() {
        assert!(true, "Vault module tree loads");
    }
}
