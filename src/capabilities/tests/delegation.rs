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

use crate::capabilities::*;

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

#[test]
fn test_delegation_grants_true() {
    let del = make_delegation(1, 2, &[Capability::Admin, Capability::Debug]);
    assert!(del.grants(Capability::Admin));
    assert!(del.grants(Capability::Debug));
}

#[test]
fn test_delegation_grants_false() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(!del.grants(Capability::Debug));
    assert!(!del.grants(Capability::Network));
}

#[test]
fn test_delegation_capability_count() {
    let del = make_delegation(1, 2, &[Capability::Admin, Capability::Debug, Capability::Crypto]);
    assert_eq!(del.capability_count(), 3);
}

#[test]
fn test_delegation_capability_count_empty() {
    let del = make_delegation(1, 2, &[]);
    assert_eq!(del.capability_count(), 0);
}

#[test]
fn test_delegation_grants_all_true() {
    let del = make_delegation(1, 2, &[Capability::Admin, Capability::Debug, Capability::Crypto]);
    assert!(del.grants_all(&[Capability::Admin, Capability::Debug]));
}

#[test]
fn test_delegation_grants_all_false() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(!del.grants_all(&[Capability::Admin, Capability::Debug]));
}

#[test]
fn test_delegation_grants_all_empty() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(del.grants_all(&[]));
}

#[test]
fn test_delegation_grants_any_true() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(del.grants_any(&[Capability::Admin, Capability::Debug]));
}

#[test]
fn test_delegation_grants_any_false() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(!del.grants_any(&[Capability::Debug, Capability::Network]));
}

#[test]
fn test_delegation_grants_any_empty() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(!del.grants_any(&[]));
}

#[test]
fn test_delegation_is_valid_no_expiry() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(del.is_valid());
}

#[test]
fn test_delegation_is_expired_no_expiry() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(!del.is_expired());
}

#[test]
fn test_delegation_is_expired_future() {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(u64::MAX),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!del.is_expired());
    assert!(del.is_valid());
}

#[test]
fn test_delegation_is_expired_past() {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(0),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(del.is_expired());
    assert!(!del.is_valid());
}

#[test]
fn test_delegation_remaining_ms_none() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    assert!(del.remaining_ms().is_none());
}

#[test]
fn test_delegation_remaining_ms_future() {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(u64::MAX),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    let remaining = del.remaining_ms();
    assert!(remaining.is_some());
    assert!(remaining.unwrap() > 0);
}

#[test]
fn test_delegation_remaining_ms_past() {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(0),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    let remaining = del.remaining_ms();
    assert!(remaining.is_some());
    assert_eq!(remaining.unwrap(), 0);
}

#[test]
fn test_delegation_display() {
    let del = make_delegation(10, 20, &[Capability::Admin, Capability::Debug]);
    let display = alloc::format!("{}", del);
    assert!(display.contains("10"));
    assert!(display.contains("20"));
    assert!(display.contains("caps:2"));
}

#[test]
fn test_delegation_display_with_expiry() {
    let del = Delegation {
        delegator: 10,
        delegatee: 20,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(1000000),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    let display = alloc::format!("{}", del);
    assert!(display.contains("1000000ms"));
}

#[test]
fn test_delegation_display_no_expiry() {
    let del = make_delegation(10, 20, &[Capability::Admin]);
    let display = alloc::format!("{}", del);
    assert!(display.contains("never"));
}

#[test]
fn test_delegation_error_missing_signing_key_as_str() {
    let err = DelegationError::MissingSigningKey;
    assert_eq!(err.as_str(), "Signing key not available");
}

#[test]
fn test_delegation_error_invalid_parent_token_as_str() {
    let err = DelegationError::InvalidParentToken;
    assert_eq!(err.as_str(), "Parent token is invalid");
}

#[test]
fn test_delegation_error_parent_expired_as_str() {
    let err = DelegationError::ParentExpired;
    assert_eq!(err.as_str(), "Parent token has expired");
}

#[test]
fn test_delegation_error_capability_not_held_as_str() {
    let err = DelegationError::CapabilityNotHeld;
    assert_eq!(err.as_str(), "Cannot delegate capability not held");
}

#[test]
fn test_delegation_error_delegation_expired_as_str() {
    let err = DelegationError::DelegationExpired;
    assert_eq!(err.as_str(), "Delegation has expired");
}

#[test]
fn test_delegation_error_invalid_signature_as_str() {
    let err = DelegationError::InvalidSignature;
    assert_eq!(err.as_str(), "Signature verification failed");
}

#[test]
fn test_delegation_error_no_capabilities_as_str() {
    let err = DelegationError::NoCapabilities;
    assert_eq!(err.as_str(), "No capabilities specified");
}

#[test]
fn test_delegation_error_is_recoverable_delegation_expired() {
    let err = DelegationError::DelegationExpired;
    assert!(err.is_recoverable());
}

#[test]
fn test_delegation_error_is_recoverable_parent_expired() {
    let err = DelegationError::ParentExpired;
    assert!(err.is_recoverable());
}

#[test]
fn test_delegation_error_is_recoverable_invalid_signature() {
    let err = DelegationError::InvalidSignature;
    assert!(!err.is_recoverable());
}

#[test]
fn test_delegation_error_is_recoverable_missing_key() {
    let err = DelegationError::MissingSigningKey;
    assert!(!err.is_recoverable());
}

#[test]
fn test_delegation_error_display() {
    let err = DelegationError::NoCapabilities;
    let display = alloc::format!("{}", err);
    assert_eq!(display, "No capabilities specified");
}

#[test]
fn test_delegation_error_equality() {
    assert_eq!(DelegationError::NoCapabilities, DelegationError::NoCapabilities);
    assert_ne!(DelegationError::NoCapabilities, DelegationError::ParentExpired);
}

#[test]
fn test_delegation_material_produces_48_bytes() {
    let del = make_delegation(1, 2, &[Capability::Admin]);
    let mat = delegation_material(&del, del.parent_nonce);
    assert_eq!(mat.len(), 48);
}

#[test]
fn test_delegation_material_deterministic() {
    let del = make_delegation(100, 200, &[Capability::Admin, Capability::Debug]);
    let mat1 = delegation_material(&del, del.parent_nonce);
    let mat2 = delegation_material(&del, del.parent_nonce);
    assert_eq!(mat1, mat2);
}

#[test]
fn test_delegation_material_different_for_different_delegators() {
    let del1 = make_delegation(1, 2, &[Capability::Admin]);
    let del2 = make_delegation(99, 2, &[Capability::Admin]);
    let mat1 = delegation_material(&del1, del1.parent_nonce);
    let mat2 = delegation_material(&del2, del2.parent_nonce);
    assert_ne!(mat1, mat2);
}

#[test]
fn test_delegation_material_different_for_different_delegatees() {
    let del1 = make_delegation(1, 2, &[Capability::Admin]);
    let del2 = make_delegation(1, 99, &[Capability::Admin]);
    let mat1 = delegation_material(&del1, del1.parent_nonce);
    let mat2 = delegation_material(&del2, del2.parent_nonce);
    assert_ne!(mat1, mat2);
}

#[test]
fn test_compute_delegation_signature_produces_64_bytes() {
    let key = [0u8; 32];
    let material = [1u8; 48];
    let sig = compute_delegation_signature(&key, &material);
    assert_eq!(sig.len(), 64);
}

#[test]
fn test_compute_delegation_signature_deterministic() {
    let key = [1u8; 32];
    let material = [2u8; 48];
    let sig1 = compute_delegation_signature(&key, &material);
    let sig2 = compute_delegation_signature(&key, &material);
    assert_eq!(sig1, sig2);
}

#[test]
fn test_compute_delegation_signature_different_keys() {
    let material = [1u8; 48];
    let sig1 = compute_delegation_signature(&[0u8; 32], &material);
    let sig2 = compute_delegation_signature(&[1u8; 32], &material);
    assert_ne!(sig1, sig2);
}

#[test]
fn test_compute_delegation_signature_different_material() {
    let key = [0u8; 32];
    let sig1 = compute_delegation_signature(&key, &[0u8; 48]);
    let sig2 = compute_delegation_signature(&key, &[1u8; 48]);
    assert_ne!(sig1, sig2);
}

#[test]
fn test_create_delegation_unchecked_empty_caps() {
    let result = create_delegation_unchecked(1, 2, &[], None, 12345);
    assert!(matches!(result, Err(DelegationError::NoCapabilities)));
}

#[test]
fn test_verify_delegation_standalone_expired() {
    let del = Delegation {
        delegator: 1,
        delegatee: 2,
        capabilities: alloc::vec![Capability::Admin],
        expires_at_ms: Some(0),
        parent_nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!verify_delegation_standalone(&del));
}
