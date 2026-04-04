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

#[test]
fn test_resource_quota_new() {
    let q = ResourceQuota::new(1000, 100, Some(5000));
    assert_eq!(q.bytes, 1000);
    assert_eq!(q.ops, 100);
    assert_eq!(q.expires_at_ms, Some(5000));
}

#[test]
fn test_resource_quota_unlimited() {
    let q = ResourceQuota::unlimited();
    assert_eq!(q.bytes, u64::MAX);
    assert_eq!(q.ops, u64::MAX);
    assert!(q.expires_at_ms.is_none());
}

#[test]
fn test_resource_quota_bytes_only() {
    let q = ResourceQuota::bytes_only(5000);
    assert_eq!(q.bytes, 5000);
    assert_eq!(q.ops, u64::MAX);
    assert!(q.expires_at_ms.is_none());
}

#[test]
fn test_resource_quota_ops_only() {
    let q = ResourceQuota::ops_only(500);
    assert_eq!(q.bytes, u64::MAX);
    assert_eq!(q.ops, 500);
    assert!(q.expires_at_ms.is_none());
}

#[test]
fn test_resource_quota_is_expired_no_expiry() {
    let q = ResourceQuota::new(100, 100, None);
    assert!(!q.is_expired());
}

#[test]
fn test_resource_quota_is_expired_future() {
    let q = ResourceQuota::new(100, 100, Some(u64::MAX));
    assert!(!q.is_expired());
}

#[test]
fn test_resource_quota_is_expired_past() {
    let q = ResourceQuota::new(100, 100, Some(0));
    assert!(q.is_expired());
}

#[test]
fn test_resource_quota_is_empty_true() {
    let q = ResourceQuota::new(0, 0, None);
    assert!(q.is_empty());
}

#[test]
fn test_resource_quota_is_empty_false_bytes() {
    let q = ResourceQuota::new(1, 0, None);
    assert!(!q.is_empty());
}

#[test]
fn test_resource_quota_is_empty_false_ops() {
    let q = ResourceQuota::new(0, 1, None);
    assert!(!q.is_empty());
}

#[test]
fn test_resource_quota_is_unlimited_true() {
    let q = ResourceQuota::unlimited();
    assert!(q.is_unlimited());
}

#[test]
fn test_resource_quota_is_unlimited_false_bytes() {
    let q = ResourceQuota::new(100, u64::MAX, None);
    assert!(!q.is_unlimited());
}

#[test]
fn test_resource_quota_is_unlimited_false_ops() {
    let q = ResourceQuota::new(u64::MAX, 100, None);
    assert!(!q.is_unlimited());
}

#[test]
fn test_resource_quota_is_unlimited_false_expiry() {
    let q = ResourceQuota::new(u64::MAX, u64::MAX, Some(1000));
    assert!(!q.is_unlimited());
}

#[test]
fn test_resource_quota_remaining_ms_none() {
    let q = ResourceQuota::new(100, 100, None);
    assert!(q.remaining_ms().is_none());
}

#[test]
fn test_resource_quota_remaining_ms_future() {
    let q = ResourceQuota::new(100, 100, Some(u64::MAX));
    let remaining = q.remaining_ms();
    assert!(remaining.is_some());
    assert!(remaining.unwrap() > 0);
}

#[test]
fn test_resource_quota_remaining_ms_past() {
    let q = ResourceQuota::new(100, 100, Some(0));
    let remaining = q.remaining_ms();
    assert!(remaining.is_some());
    assert_eq!(remaining.unwrap(), 0);
}

#[test]
fn test_resource_quota_display() {
    let q = ResourceQuota::new(1000, 50, None);
    let display = alloc::format!("{}", q);
    assert!(display.contains("1000B"));
    assert!(display.contains("50ops"));
}

#[test]
fn test_resource_quota_display_with_expiry() {
    let q = ResourceQuota::new(1000, 50, Some(5000));
    let display = alloc::format!("{}", q);
    assert!(display.contains("exp:5000ms"));
}

#[test]
fn test_resource_quota_default() {
    let q = ResourceQuota::default();
    assert_eq!(q.bytes, 0);
    assert_eq!(q.ops, 0);
    assert!(q.expires_at_ms.is_none());
}

#[test]
fn test_resource_error_missing_signing_key_as_str() {
    let err = ResourceError::MissingSigningKey;
    assert_eq!(err.as_str(), "Signing key not available");
}

#[test]
fn test_resource_error_token_expired_as_str() {
    let err = ResourceError::TokenExpired;
    assert_eq!(err.as_str(), "Token has expired");
}

#[test]
fn test_resource_error_invalid_signature_as_str() {
    let err = ResourceError::InvalidSignature;
    assert_eq!(err.as_str(), "Signature verification failed");
}

#[test]
fn test_resource_error_insufficient_bytes_as_str() {
    let err = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    assert_eq!(err.as_str(), "Insufficient bytes");
}

#[test]
fn test_resource_error_insufficient_ops_as_str() {
    let err = ResourceError::InsufficientOps { requested: 10, available: 5 };
    assert_eq!(err.as_str(), "Insufficient operations");
}

#[test]
fn test_resource_error_zero_quota_as_str() {
    let err = ResourceError::ZeroQuota;
    assert_eq!(err.as_str(), "Zero quota not allowed");
}

#[test]
fn test_resource_error_is_quota_error_bytes() {
    let err = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    assert!(err.is_quota_error());
}

#[test]
fn test_resource_error_is_quota_error_ops() {
    let err = ResourceError::InsufficientOps { requested: 10, available: 5 };
    assert!(err.is_quota_error());
}

#[test]
fn test_resource_error_is_quota_error_false() {
    assert!(!ResourceError::TokenExpired.is_quota_error());
    assert!(!ResourceError::ZeroQuota.is_quota_error());
    assert!(!ResourceError::InvalidSignature.is_quota_error());
}

#[test]
fn test_resource_error_display_missing_key() {
    let err = ResourceError::MissingSigningKey;
    let display = alloc::format!("{}", err);
    assert!(display.contains("Signing key"));
}

#[test]
fn test_resource_error_display_insufficient_bytes() {
    let err = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("100"));
    assert!(display.contains("50"));
}

#[test]
fn test_resource_error_display_insufficient_ops() {
    let err = ResourceError::InsufficientOps { requested: 10, available: 5 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("10"));
    assert!(display.contains("5"));
}

#[test]
fn test_resource_error_equality() {
    assert_eq!(ResourceError::ZeroQuota, ResourceError::ZeroQuota);
    assert_ne!(ResourceError::ZeroQuota, ResourceError::TokenExpired);
    assert_eq!(
        ResourceError::InsufficientBytes { requested: 100, available: 50 },
        ResourceError::InsufficientBytes { requested: 100, available: 50 }
    );
    assert_ne!(
        ResourceError::InsufficientBytes { requested: 100, available: 50 },
        ResourceError::InsufficientBytes { requested: 200, available: 50 }
    );
}

#[test]
fn test_create_resource_token_zero_quota() {
    let q = ResourceQuota::default();
    let result = create_resource_token(1, q);
    assert!(matches!(result, Err(ResourceError::ZeroQuota)));
}

#[test]
fn test_create_resource_token_with_nonce_zero_quota() {
    let q = ResourceQuota::default();
    let result = create_resource_token_with_nonce(1, q, 12345);
    assert!(matches!(result, Err(ResourceError::ZeroQuota)));
}

#[test]
fn test_resource_next_nonce_nonzero() {
    let n = resource_next_nonce();
    assert!(n > 0);
}

#[test]
fn test_resource_next_nonce_different() {
    let n1 = resource_next_nonce();
    let n2 = resource_next_nonce();
    assert_ne!(n1, n2);
}

#[test]
fn test_resource_reset_nonce_counter() {
    let _ = resource_next_nonce();
    resource_reset_nonce_counter();
    let n = resource_next_nonce();
    assert!(n > 0);
}

#[test]
fn test_resource_token_material_produces_40_bytes() {
    let q = ResourceQuota::new(1000, 100, None);
    let mat = resource_token_material(1, &q, 12345);
    assert_eq!(mat.len(), 40);
}

#[test]
fn test_resource_token_material_deterministic() {
    let q = ResourceQuota::new(1000, 100, None);
    let mat1 = resource_token_material(1, &q, 12345);
    let mat2 = resource_token_material(1, &q, 12345);
    assert_eq!(mat1, mat2);
}

#[test]
fn test_resource_token_material_different_owners() {
    let q = ResourceQuota::new(1000, 100, None);
    let mat1 = resource_token_material(1, &q, 12345);
    let mat2 = resource_token_material(2, &q, 12345);
    assert_ne!(mat1, mat2);
}

#[test]
fn test_resource_token_material_different_quotas() {
    let q1 = ResourceQuota::new(1000, 100, None);
    let q2 = ResourceQuota::new(2000, 100, None);
    let mat1 = resource_token_material(1, &q1, 12345);
    let mat2 = resource_token_material(1, &q2, 12345);
    assert_ne!(mat1, mat2);
}

#[test]
fn test_resource_token_material_different_nonces() {
    let q = ResourceQuota::new(1000, 100, None);
    let mat1 = resource_token_material(1, &q, 12345);
    let mat2 = resource_token_material(1, &q, 67890);
    assert_ne!(mat1, mat2);
}

#[test]
fn test_resource_compute_signature_produces_64_bytes() {
    let key = [0u8; 32];
    let material = [1u8; 40];
    let sig = resource_compute_signature(&key, &material);
    assert_eq!(sig.len(), 64);
}

#[test]
fn test_resource_compute_signature_deterministic() {
    let key = [1u8; 32];
    let material = [2u8; 40];
    let sig1 = resource_compute_signature(&key, &material);
    let sig2 = resource_compute_signature(&key, &material);
    assert_eq!(sig1, sig2);
}

#[test]
fn test_resource_compute_signature_different_keys() {
    let material = [1u8; 40];
    let sig1 = resource_compute_signature(&[0u8; 32], &material);
    let sig2 = resource_compute_signature(&[1u8; 32], &material);
    assert_ne!(sig1, sig2);
}

#[test]
fn test_resource_compute_signature_different_material() {
    let key = [0u8; 32];
    let sig1 = resource_compute_signature(&key, &[0u8; 40]);
    let sig2 = resource_compute_signature(&key, &[1u8; 40]);
    assert_ne!(sig1, sig2);
}
