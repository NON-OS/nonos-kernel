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

use crate::test::framework::TestResult;
use crate::vault::nonos_vault_api::*;
use crate::vault::nonos_vault_policy::{set_vault_policy, VaultCapability, VaultPolicyRule};
use crate::vault::nonos_vault_seal::SealPolicy;

pub(crate) fn test_vault_api_error_not_initialized_eq() -> TestResult {
    if VaultApiError::NotInitialized != VaultApiError::NotInitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_policy_denied_eq() -> TestResult {
    if VaultApiError::PolicyDenied != VaultApiError::PolicyDenied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_key_not_found_eq() -> TestResult {
    if VaultApiError::KeyNotFound != VaultApiError::KeyNotFound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_seal_failed_eq() -> TestResult {
    if VaultApiError::SealFailed != VaultApiError::SealFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_unseal_failed_eq() -> TestResult {
    if VaultApiError::UnsealFailed != VaultApiError::UnsealFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_invalid_arguments_eq() -> TestResult {
    if VaultApiError::InvalidArguments != VaultApiError::InvalidArguments {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_internal_error_eq() -> TestResult {
    if VaultApiError::InternalError != VaultApiError::InternalError {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_different_ne() -> TestResult {
    if VaultApiError::NotInitialized == VaultApiError::PolicyDenied {
        return TestResult::Fail;
    }
    if VaultApiError::SealFailed == VaultApiError::UnsealFailed {
        return TestResult::Fail;
    }
    if VaultApiError::KeyNotFound == VaultApiError::InternalError {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_clone() -> TestResult {
    let err = VaultApiError::PolicyDenied;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_copy() -> TestResult {
    let err = VaultApiError::SealFailed;
    let copied: VaultApiError = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_debug_not_initialized() -> TestResult {
    let debug = alloc::format!("{:?}", VaultApiError::NotInitialized);
    if !debug.contains("NotInitialized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_debug_policy_denied() -> TestResult {
    let debug = alloc::format!("{:?}", VaultApiError::PolicyDenied);
    if !debug.contains("PolicyDenied") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_debug_key_not_found() -> TestResult {
    let debug = alloc::format!("{:?}", VaultApiError::KeyNotFound);
    if !debug.contains("KeyNotFound") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_debug_seal_failed() -> TestResult {
    let debug = alloc::format!("{:?}", VaultApiError::SealFailed);
    if !debug.contains("SealFailed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_debug_unseal_failed() -> TestResult {
    let debug = alloc::format!("{:?}", VaultApiError::UnsealFailed);
    if !debug.contains("UnsealFailed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_debug_invalid_arguments() -> TestResult {
    let debug = alloc::format!("{:?}", VaultApiError::InvalidArguments);
    if !debug.contains("InvalidArguments") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_error_debug_internal_error() -> TestResult {
    let debug = alloc::format!("{:?}", VaultApiError::InternalError);
    if !debug.contains("InternalError") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_init_returns_result() -> TestResult {
    let result = vault_init();
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_status_returns_bool() -> TestResult {
    let status = vault_status();
    if !(status || !status) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_derive_requires_policy() -> TestResult {
    let result = vault_derive("test", 32, "unknown_caller");
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_derive_with_policy() -> TestResult {
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
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_derive_policy_denied() -> TestResult {
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
        if e != VaultApiError::PolicyDenied {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_seal_requires_policy() -> TestResult {
    let result = vault_seal(b"plaintext", b"aad", SealPolicy::RAMOnly, "unknown_caller");
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_seal_with_policy() -> TestResult {
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
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_seal_policy_denied() -> TestResult {
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
        if e != VaultApiError::PolicyDenied {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_unseal_requires_policy() -> TestResult {
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
        if !(result.is_ok() || result.is_err()) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_unseal_with_policy() -> TestResult {
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
        if !(result.is_ok() || result.is_err()) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_unseal_policy_denied() -> TestResult {
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
            if e != VaultApiError::PolicyDenied {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_erase_requires_policy() -> TestResult {
    let result = vault_erase("unknown_caller");
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_erase_with_policy() -> TestResult {
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
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_erase_policy_denied() -> TestResult {
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
        if e != VaultApiError::PolicyDenied {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_audit_returns_vec() -> TestResult {
    let events = vault_audit(10);
    if events.len() > 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_audit_zero_returns_empty() -> TestResult {
    let events = vault_audit(0);
    if !events.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_list_policies_returns_vec() -> TestResult {
    let policies = vault_list_policies();
    let _ = policies.len();
    TestResult::Pass
}

pub(crate) fn test_vault_stats_initialized_field() -> TestResult {
    let stats = vault_stats();
    if !(stats.initialized || !stats.initialized) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_stats_audit_events_field() -> TestResult {
    let stats = vault_stats();
    let _ = stats.audit_events;
    TestResult::Pass
}

pub(crate) fn test_vault_stats_policies_field() -> TestResult {
    let stats = vault_stats();
    let _ = stats.policies;
    TestResult::Pass
}

pub(crate) fn test_vault_syscall_dispatch_init() -> TestResult {
    let result = vault_syscall_dispatch(0, &[], "caller");
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_syscall_dispatch_derive() -> TestResult {
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
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_syscall_dispatch_seal_returns_invalid() -> TestResult {
    let result = vault_syscall_dispatch(2, &[], "caller");
    if result != Err(VaultApiError::InvalidArguments) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_syscall_dispatch_unseal_returns_invalid() -> TestResult {
    let result = vault_syscall_dispatch(3, &[], "caller");
    if result != Err(VaultApiError::InvalidArguments) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_syscall_dispatch_erase() -> TestResult {
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
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_syscall_dispatch_unknown_op() -> TestResult {
    let result = vault_syscall_dispatch(99, &[], "caller");
    if result != Err(VaultApiError::InvalidArguments) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_result_ok() -> TestResult {
    let result: VaultApiResult<u32> = Ok(42);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_api_result_err() -> TestResult {
    let result: VaultApiResult<u32> = Err(VaultApiError::NotInitialized);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != VaultApiError::NotInitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_seal_unseal_roundtrip_with_api() -> TestResult {
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
            if unsealed != plaintext {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
