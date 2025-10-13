//! Integration tests for NØNOS Vault Subsystem

extern crate alloc;
use alloc::vec::Vec;
use nonos_kernel::vault::{
    vault_init, vault_status, vault_derive, vault_seal, vault_unseal, vault_erase,
    vault_audit, vault_list_policies,
    SealPolicy, VaultCapability, set_vault_policy, VaultPolicyRule,
};

#[test]
fn test_vault_lifecycle() {
    // Init vault
    assert!(vault_init().is_ok());
    assert!(vault_status());

    // Set a policy
    set_vault_policy("testproc", VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "testproc".to_string(),
        max_uses: Some(2),
        used: 0,
        expires_at: None,
        allow: true,
    });

    // Seal & unseal
    let secret = b"super_secret";
    let aad = b"header";
    let sealed = vault_seal(secret, aad, SealPolicy::RAMOnly, "testproc").expect("seal failed");
    let unsealed = vault_unseal(&sealed, "testproc").expect("unseal failed");
    assert_eq!(secret.to_vec(), unsealed);

    // Policy usage limit
    let _ = vault_seal(secret, aad, SealPolicy::RAMOnly, "testproc");
    assert!(vault_seal(secret, aad, SealPolicy::RAMOnly, "testproc").is_err());

    // Erase vault
    assert!(vault_erase("testproc").is_ok());
}

#[test]
fn test_vault_audit_and_policy() {
    assert!(vault_init().is_ok());
    set_vault_policy("auditor", VaultPolicyRule {
        capability: VaultCapability::Audit,
        context: "auditor".to_string(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    });
    let audit_events = vault_audit(10);
    assert!(audit_events.len() >= 1);
    let policies = vault_list_policies();
    assert!(!policies.is_empty());
}
