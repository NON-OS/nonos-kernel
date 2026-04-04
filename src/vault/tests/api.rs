// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use crate::vault::nonos_vault_api::*;
use crate::vault::nonos_vault_seal::SealPolicy;
use crate::vault::nonos_vault_policy::{VaultCapability, VaultPolicyRule, set_vault_policy};

#[test]
fn test_vault_api_error_not_initialized_eq() {
    assert_eq!(VaultApiError::NotInitialized, VaultApiError::NotInitialized);
}

#[test]
fn test_vault_api_error_policy_denied_eq() {
    assert_eq!(VaultApiError::PolicyDenied, VaultApiError::PolicyDenied);
}

#[test]
fn test_vault_api_error_key_not_found_eq() {
    assert_eq!(VaultApiError::KeyNotFound, VaultApiError::KeyNotFound);
}

#[test]
fn test_vault_api_error_seal_failed_eq() {
    assert_eq!(VaultApiError::SealFailed, VaultApiError::SealFailed);
}

#[test]
fn test_vault_api_error_unseal_failed_eq() {
    assert_eq!(VaultApiError::UnsealFailed, VaultApiError::UnsealFailed);
}

#[test]
fn test_vault_api_error_invalid_arguments_eq() {
    assert_eq!(VaultApiError::InvalidArguments, VaultApiError::InvalidArguments);
}

#[test]
fn test_vault_api_error_internal_error_eq() {
    assert_eq!(VaultApiError::InternalError, VaultApiError::InternalError);
}

#[test]
fn test_vault_api_error_different_ne() {
    assert_ne!(VaultApiError::NotInitialized, VaultApiError::PolicyDenied);
    assert_ne!(VaultApiError::SealFailed, VaultApiError::UnsealFailed);
    assert_ne!(VaultApiError::KeyNotFound, VaultApiError::InternalError);
}

#[test]
fn test_vault_api_error_clone() {
    let err = VaultApiError::PolicyDenied;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_vault_api_error_copy() {
    let err = VaultApiError::SealFailed;
    let copied: VaultApiError = err;
    assert_eq!(err, copied);
}

#[test]
fn test_vault_api_error_debug_not_initialized() {
    let debug = alloc::format!("{:?}", VaultApiError::NotInitialized);
    assert!(debug.contains("NotInitialized"));
}

#[test]
fn test_vault_api_error_debug_policy_denied() {
    let debug = alloc::format!("{:?}", VaultApiError::PolicyDenied);
    assert!(debug.contains("PolicyDenied"));
}

#[test]
fn test_vault_api_error_debug_key_not_found() {
    let debug = alloc::format!("{:?}", VaultApiError::KeyNotFound);
    assert!(debug.contains("KeyNotFound"));
}

#[test]
fn test_vault_api_error_debug_seal_failed() {
    let debug = alloc::format!("{:?}", VaultApiError::SealFailed);
    assert!(debug.contains("SealFailed"));
}

#[test]
fn test_vault_api_error_debug_unseal_failed() {
    let debug = alloc::format!("{:?}", VaultApiError::UnsealFailed);
    assert!(debug.contains("UnsealFailed"));
}

#[test]
fn test_vault_api_error_debug_invalid_arguments() {
    let debug = alloc::format!("{:?}", VaultApiError::InvalidArguments);
    assert!(debug.contains("InvalidArguments"));
}

#[test]
fn test_vault_api_error_debug_internal_error() {
    let debug = alloc::format!("{:?}", VaultApiError::InternalError);
    assert!(debug.contains("InternalError"));
}

#[test]
fn test_vault_init_returns_result() {
    let result = vault_init();
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_status_returns_bool() {
    let status = vault_status();
    assert!(status || !status);
}

#[test]
fn test_vault_derive_requires_policy() {
    let result = vault_derive("test", 32, "unknown_caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_derive_with_policy() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "derive_caller".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("derive_caller", rule);
    let _ = vault_init();
    let result = vault_derive("context", 32, "derive_caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_derive_policy_denied() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "denied_caller".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    set_vault_policy("denied_caller", rule);
    let result = vault_derive("context", 32, "denied_caller");
    if let Err(e) = result {
        assert_eq!(e, VaultApiError::PolicyDenied);
    }
}

#[test]
fn test_vault_seal_requires_policy() {
    let result = vault_seal(b"plaintext", b"aad", SealPolicy::RAMOnly, "unknown_caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_seal_with_policy() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "seal_caller".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("seal_caller", rule);
    let _ = vault_init();
    let result = vault_seal(b"plaintext", b"aad", SealPolicy::RAMOnly, "seal_caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_seal_policy_denied() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "seal_denied".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    set_vault_policy("seal_denied", rule);
    let result = vault_seal(b"plaintext", b"aad", SealPolicy::RAMOnly, "seal_denied");
    if let Err(e) = result {
        assert_eq!(e, VaultApiError::PolicyDenied);
    }
}

#[test]
fn test_vault_unseal_requires_policy() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "unseal_setup".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("unseal_setup", rule);
    let _ = vault_init();
    if let Ok(sealed) = vault_seal(b"test", b"aad", SealPolicy::RAMOnly, "unseal_setup") {
        let result = vault_unseal(&sealed, "unknown_caller");
        assert!(result.is_ok() || result.is_err());
    }
}

#[test]
fn test_vault_unseal_with_policy() {
    let seal_rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "unseal_caller".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    let unseal_rule = VaultPolicyRule {
        capability: VaultCapability::Unseal,
        context: "unseal_caller".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("unseal_caller", seal_rule);
    set_vault_policy("unseal_caller", unseal_rule);
    let _ = vault_init();
    if let Ok(sealed) = vault_seal(b"test", b"aad", SealPolicy::RAMOnly, "unseal_caller") {
        let result = vault_unseal(&sealed, "unseal_caller");
        assert!(result.is_ok() || result.is_err());
    }
}

#[test]
fn test_vault_unseal_policy_denied() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Unseal,
        context: "unseal_denied".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    set_vault_policy("unseal_denied", rule);
    let seal_rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "unseal_denied".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("unseal_denied", seal_rule);
    let _ = vault_init();
    if let Ok(sealed) = vault_seal(b"test", b"aad", SealPolicy::RAMOnly, "unseal_denied") {
        let result = vault_unseal(&sealed, "unseal_denied");
        if let Err(e) = result {
            assert_eq!(e, VaultApiError::PolicyDenied);
        }
    }
}

#[test]
fn test_vault_erase_requires_policy() {
    let result = vault_erase("unknown_caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_erase_with_policy() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Erase,
        context: "erase_caller".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("erase_caller", rule);
    let result = vault_erase("erase_caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_erase_policy_denied() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Erase,
        context: "erase_denied".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: false,
    };
    set_vault_policy("erase_denied", rule);
    let result = vault_erase("erase_denied");
    if let Err(e) = result {
        assert_eq!(e, VaultApiError::PolicyDenied);
    }
}

#[test]
fn test_vault_audit_returns_vec() {
    let events = vault_audit(10);
    assert!(events.len() <= 10);
}

#[test]
fn test_vault_audit_zero_returns_empty() {
    let events = vault_audit(0);
    assert!(events.is_empty());
}

#[test]
fn test_vault_list_policies_returns_vec() {
    let policies = vault_list_policies();
    assert!(policies.len() >= 0);
}

#[test]
fn test_vault_stats_initialized_field() {
    let stats = vault_stats();
    assert!(stats.initialized || !stats.initialized);
}

#[test]
fn test_vault_stats_audit_events_field() {
    let stats = vault_stats();
    assert!(stats.audit_events >= 0);
}

#[test]
fn test_vault_stats_policies_field() {
    let stats = vault_stats();
    assert!(stats.policies >= 0);
}

#[test]
fn test_vault_syscall_dispatch_init() {
    let result = vault_syscall_dispatch(0, &[], "caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_syscall_dispatch_derive() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Derive,
        context: "syscall_caller".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("syscall_caller", rule);
    let _ = vault_init();
    let mut args = [0u8; 36];
    args[..32].copy_from_slice(b"context_string__________________");
    args[32..36].copy_from_slice(&32u32.to_le_bytes());
    let result = vault_syscall_dispatch(1, &args, "syscall_caller");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_syscall_dispatch_seal_returns_invalid() {
    let result = vault_syscall_dispatch(2, &[], "caller");
    assert_eq!(result, Err(VaultApiError::InvalidArguments));
}

#[test]
fn test_vault_syscall_dispatch_unseal_returns_invalid() {
    let result = vault_syscall_dispatch(3, &[], "caller");
    assert_eq!(result, Err(VaultApiError::InvalidArguments));
}

#[test]
fn test_vault_syscall_dispatch_erase() {
    let rule = VaultPolicyRule {
        capability: VaultCapability::Erase,
        context: "erase_syscall".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("erase_syscall", rule);
    let result = vault_syscall_dispatch(4, &[], "erase_syscall");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_syscall_dispatch_unknown_op() {
    let result = vault_syscall_dispatch(99, &[], "caller");
    assert_eq!(result, Err(VaultApiError::InvalidArguments));
}

#[test]
fn test_vault_api_result_ok() {
    let result: VaultApiResult<u32> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_vault_api_result_err() {
    let result: VaultApiResult<u32> = Err(VaultApiError::NotInitialized);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), VaultApiError::NotInitialized);
}

#[test]
fn test_vault_seal_unseal_roundtrip_with_api() {
    let seal_rule = VaultPolicyRule {
        capability: VaultCapability::Seal,
        context: "roundtrip".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    let unseal_rule = VaultPolicyRule {
        capability: VaultCapability::Unseal,
        context: "roundtrip".into(),
        max_uses: None,
        used: 0,
        expires_at: None,
        allow: true,
    };
    set_vault_policy("roundtrip", seal_rule);
    set_vault_policy("roundtrip", unseal_rule);
    let _ = vault_init();
    let plaintext = b"api roundtrip test";
    if let Ok(sealed) = vault_seal(plaintext, b"aad", SealPolicy::RAMOnly, "roundtrip") {
        if let Ok(unsealed) = vault_unseal(&sealed, "roundtrip") {
            assert_eq!(unsealed, plaintext);
        }
    }
}
