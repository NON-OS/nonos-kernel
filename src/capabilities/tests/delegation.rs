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

use crate::capabilities::*;
use crate::test::framework::TestResult;

fn make_delegation(delegator: u64, delegatee: u64, caps: &[Capability]) -> Delegation {
    Delegation {
        delegator,
        delegatee,
        capabilities: caps.to_vec(),
        expires_at_ms: None,
        parent_nonce: 12345,
        signature: [0u8; 64],
    }
}

pub(crate) fn test_delegation_grants_true() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin, Capability::Debug]);
    if !del.grants(Capability::Admin) {
        return TestResult::Fail;
    }
    if !del.grants(Capability::Debug) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_grants_false() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if del.grants(Capability::Debug) {
        return TestResult::Fail;
    }
    if del.grants(Capability::Network) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_capability_count() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin, Capability::Debug, Capability::Crypto]);
    if del.capability_count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_capability_count_empty() -> TestResult {
    let del = make_delegation(1, 2, &[]);
    if del.capability_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_grants_all_true() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin, Capability::Debug, Capability::Crypto]);
    if !del.grants_all(&[Capability::Admin, Capability::Debug]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_grants_all_false() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if del.grants_all(&[Capability::Admin, Capability::Debug]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_grants_all_empty() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if !del.grants_all(&[]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_grants_any_true() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if !del.grants_any(&[Capability::Admin, Capability::Debug]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_grants_any_false() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if del.grants_any(&[Capability::Debug, Capability::Network]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_grants_any_empty() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if del.grants_any(&[]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_is_valid_no_expiry() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if !del.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_is_expired_no_expiry() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if del.is_expired() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_is_expired_future() -> TestResult {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(u64::MAX),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    if del.is_expired() {
        return TestResult::Fail;
    }
    if !del.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_is_expired_past() -> TestResult {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(0),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    if !del.is_expired() {
        return TestResult::Fail;
    }
    if del.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_remaining_ms_none() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    if del.remaining_ms().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_remaining_ms_future() -> TestResult {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(u64::MAX),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    let remaining = del.remaining_ms();
    if remaining.is_none() {
        return TestResult::Fail;
    }
    if remaining.unwrap() == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_remaining_ms_past() -> TestResult {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(0),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    let remaining = del.remaining_ms();
    if remaining.is_none() {
        return TestResult::Fail;
    }
    if remaining.unwrap() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_display() -> TestResult {
    let del = make_delegation(10, 20, &[Capability::Admin, Capability::Debug]);
    let display = alloc::format!("{}", del);
    if !display.contains("10") {
        return TestResult::Fail;
    }
    if !display.contains("20") {
        return TestResult::Fail;
    }
    if !display.contains("caps:2") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_display_with_expiry() -> TestResult {
    let del = Delegation {
        delegator: 10,
        delegatee: 20,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(1000000),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    let display = alloc::format!("{}", del);
    if !display.contains("1000000ms") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_display_no_expiry() -> TestResult {
    let del = make_delegation(10, 20, &[Capability::Admin]);
    let display = alloc::format!("{}", del);
    if !display.contains("never") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_missing_signing_key_as_str() -> TestResult {
    let err = DelegationError::MissingSigningKey;
    if err.as_str() != "Signing key not available" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_invalid_parent_token_as_str() -> TestResult {
    let err = DelegationError::InvalidParentToken;
    if err.as_str() != "Parent token is invalid" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_parent_expired_as_str() -> TestResult {
    let err = DelegationError::ParentExpired;
    if err.as_str() != "Parent token has expired" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_capability_not_held_as_str() -> TestResult {
    let err = DelegationError::CapabilityNotHeld;
    if err.as_str() != "Cannot delegate capability not held" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_delegation_expired_as_str() -> TestResult {
    let err = DelegationError::DelegationExpired;
    if err.as_str() != "Delegation has expired" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_invalid_signature_as_str() -> TestResult {
    let err = DelegationError::InvalidSignature;
    if err.as_str() != "Signature verification failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_no_capabilities_as_str() -> TestResult {
    let err = DelegationError::NoCapabilities;
    if err.as_str() != "No capabilities specified" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_is_recoverable_delegation_expired() -> TestResult {
    let err = DelegationError::DelegationExpired;
    if !err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_is_recoverable_parent_expired() -> TestResult {
    let err = DelegationError::ParentExpired;
    if !err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_is_recoverable_invalid_signature() -> TestResult {
    let err = DelegationError::InvalidSignature;
    if err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_is_recoverable_missing_key() -> TestResult {
    let err = DelegationError::MissingSigningKey;
    if err.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_display() -> TestResult {
    let err = DelegationError::NoCapabilities;
    let display = alloc::format!("{}", err);
    if display != "No capabilities specified" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_error_equality() -> TestResult {
    if DelegationError::NoCapabilities != DelegationError::NoCapabilities {
        return TestResult::Fail;
    }
    if DelegationError::NoCapabilities == DelegationError::ParentExpired {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_material_produces_48_bytes() -> TestResult {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    let mat = delegation_material(&del, del.parent_nonce);
    if mat.len() != 48 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_material_deterministic() -> TestResult {
    let del = make_delegation(100, 200, &[Capability::Admin, Capability::Debug]);
    let mat1 = delegation_material(&del, del.parent_nonce);
    let mat2 = delegation_material(&del, del.parent_nonce);
    if mat1 != mat2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_material_different_for_different_delegators() -> TestResult {
    let del1 = make_delegation(1, 2, &[Capability::Admin]);
    let del2 = make_delegation(99, 2, &[Capability::Admin]);
    let mat1 = delegation_material(&del1, del1.parent_nonce);
    let mat2 = delegation_material(&del2, del2.parent_nonce);
    if mat1 == mat2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delegation_material_different_for_different_delegatees() -> TestResult {
    let del1 = make_delegation(1, 2, &[Capability::Admin]);
    let del2 = make_delegation(1, 99, &[Capability::Admin]);
    let mat1 = delegation_material(&del1, del1.parent_nonce);
    let mat2 = delegation_material(&del2, del2.parent_nonce);
    if mat1 == mat2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_delegation_signature_produces_64_bytes() -> TestResult {
    let key = [0u8; 32];
    let material = [1u8; 48];
    let sig = compute_delegation_signature(&key, &material);
    if sig.len() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_delegation_signature_deterministic() -> TestResult {
    let key = [1u8; 32];
    let material = [2u8; 48];
    let sig1 = compute_delegation_signature(&key, &material);
    let sig2 = compute_delegation_signature(&key, &material);
    if sig1 != sig2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_delegation_signature_different_keys() -> TestResult {
    let material = [1u8; 48];
    let sig1 = compute_delegation_signature(&[0u8; 32], &material);
    let sig2 = compute_delegation_signature(&[1u8; 32], &material);
    if sig1 == sig2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_delegation_signature_different_material() -> TestResult {
    let key = [0u8; 32];
    let sig1 = compute_delegation_signature(&key, &[0u8; 48]);
    let sig2 = compute_delegation_signature(&key, &[1u8; 48]);
    if sig1 == sig2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_create_delegation_unchecked_empty_caps() -> TestResult {
    let result = create_delegation_unchecked(1, 2, &[], None, 12345);
    if !matches!(result, Err(DelegationError::NoCapabilities)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_delegation_standalone_expired() -> TestResult {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(0),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    if verify_delegation_standalone(&del) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
