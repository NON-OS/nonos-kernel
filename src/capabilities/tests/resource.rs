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

pub(crate) fn test_resource_quota_new() -> TestResult {
    let q = ResourceQuota::new(1000, 100, Some(5000));
    if q.bytes != 1000 { return TestResult::Fail; }
    if q.ops != 100 { return TestResult::Fail; }
    if q.expires_at_ms != Some(5000) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_unlimited() -> TestResult {
    let q = ResourceQuota::unlimited();
    if q.bytes != u64::MAX { return TestResult::Fail; }
    if q.ops != u64::MAX { return TestResult::Fail; }
    if q.expires_at_ms.is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_bytes_only() -> TestResult {
    let q = ResourceQuota::bytes_only(5000);
    if q.bytes != 5000 { return TestResult::Fail; }
    if q.ops != u64::MAX { return TestResult::Fail; }
    if q.expires_at_ms.is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_ops_only() -> TestResult {
    let q = ResourceQuota::ops_only(500);
    if q.bytes != u64::MAX { return TestResult::Fail; }
    if q.ops != 500 { return TestResult::Fail; }
    if q.expires_at_ms.is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_expired_no_expiry() -> TestResult {
    let q = ResourceQuota::new(100, 100, None);
    if q.is_expired() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_expired_future() -> TestResult {
    let q = ResourceQuota::new(100, 100, Some(u64::MAX));
    if q.is_expired() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_expired_past() -> TestResult {
    let q = ResourceQuota::new(100, 100, Some(0));
    if !q.is_expired() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_empty_true() -> TestResult {
    let q = ResourceQuota::new(0, 0, None);
    if !q.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_empty_false_bytes() -> TestResult {
    let q = ResourceQuota::new(1, 0, None);
    if q.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_empty_false_ops() -> TestResult {
    let q = ResourceQuota::new(0, 1, None);
    if q.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_unlimited_true() -> TestResult {
    let q = ResourceQuota::unlimited();
    if !q.is_unlimited() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_unlimited_false_bytes() -> TestResult {
    let q = ResourceQuota::new(100, u64::MAX, None);
    if q.is_unlimited() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_unlimited_false_ops() -> TestResult {
    let q = ResourceQuota::new(u64::MAX, 100, None);
    if q.is_unlimited() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_is_unlimited_false_expiry() -> TestResult {
    let q = ResourceQuota::new(u64::MAX, u64::MAX, Some(1000));
    if q.is_unlimited() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_remaining_ms_none() -> TestResult {
    let q = ResourceQuota::new(100, 100, None);
    if q.remaining_ms().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_remaining_ms_future() -> TestResult {
    let q = ResourceQuota::new(100, 100, Some(u64::MAX));
    let remaining = q.remaining_ms();
    if remaining.is_none() { return TestResult::Fail; }
    if remaining.unwrap() == 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_remaining_ms_past() -> TestResult {
    let q = ResourceQuota::new(100, 100, Some(0));
    let remaining = q.remaining_ms();
    if remaining.is_none() { return TestResult::Fail; }
    if remaining.unwrap() != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_display() -> TestResult {
    let q = ResourceQuota::new(1000, 50, None);
    let display = alloc::format!("{}", q);
    if !display.contains("1000B") { return TestResult::Fail; }
    if !display.contains("50ops") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_display_with_expiry() -> TestResult {
    let q = ResourceQuota::new(1000, 50, Some(5000));
    let display = alloc::format!("{}", q);
    if !display.contains("exp:5000ms") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_quota_default() -> TestResult {
    let q = ResourceQuota::default();
    if q.bytes != 0 { return TestResult::Fail; }
    if q.ops != 0 { return TestResult::Fail; }
    if q.expires_at_ms.is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_missing_signing_key_as_str() -> TestResult {
    let err = ResourceError::MissingSigningKey;
    if err.as_str() != "Signing key not available" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_token_expired_as_str() -> TestResult {
    let err = ResourceError::TokenExpired;
    if err.as_str() != "Token has expired" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_invalid_signature_as_str() -> TestResult {
    let err = ResourceError::InvalidSignature;
    if err.as_str() != "Signature verification failed" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_insufficient_bytes_as_str() -> TestResult {
    let err = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    if err.as_str() != "Insufficient bytes" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_insufficient_ops_as_str() -> TestResult {
    let err = ResourceError::InsufficientOps { requested: 10, available: 5 };
    if err.as_str() != "Insufficient operations" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_zero_quota_as_str() -> TestResult {
    let err = ResourceError::ZeroQuota;
    if err.as_str() != "Zero quota not allowed" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_is_quota_error_bytes() -> TestResult {
    let err = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    if !err.is_quota_error() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_is_quota_error_ops() -> TestResult {
    let err = ResourceError::InsufficientOps { requested: 10, available: 5 };
    if !err.is_quota_error() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_is_quota_error_false() -> TestResult {
    if ResourceError::TokenExpired.is_quota_error() { return TestResult::Fail; }
    if ResourceError::ZeroQuota.is_quota_error() { return TestResult::Fail; }
    if ResourceError::InvalidSignature.is_quota_error() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_display_missing_key() -> TestResult {
    let err = ResourceError::MissingSigningKey;
    let display = alloc::format!("{}", err);
    if !display.contains("Signing key") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_display_insufficient_bytes() -> TestResult {
    let err = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    let display = alloc::format!("{}", err);
    if !display.contains("100") { return TestResult::Fail; }
    if !display.contains("50") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_display_insufficient_ops() -> TestResult {
    let err = ResourceError::InsufficientOps { requested: 10, available: 5 };
    let display = alloc::format!("{}", err);
    if !display.contains("10") { return TestResult::Fail; }
    if !display.contains("5") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_error_equality() -> TestResult {
    if ResourceError::ZeroQuota != ResourceError::ZeroQuota { return TestResult::Fail; }
    if ResourceError::ZeroQuota == ResourceError::TokenExpired { return TestResult::Fail; }
    let e1 = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    let e2 = ResourceError::InsufficientBytes { requested: 100, available: 50 };
    let e3 = ResourceError::InsufficientBytes { requested: 200, available: 50 };
    if e1 != e2 { return TestResult::Fail; }
    if e1 == e3 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_resource_token_zero_quota() -> TestResult {
    let q = ResourceQuota::default();
    let result = create_resource_token(1, q);
    if !matches!(result, Err(ResourceError::ZeroQuota)) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_resource_token_with_nonce_zero_quota() -> TestResult {
    let q = ResourceQuota::default();
    let result = create_resource_token_with_nonce(1, q, 12345);
    if !matches!(result, Err(ResourceError::ZeroQuota)) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_next_nonce_nonzero() -> TestResult {
    let n = resource_next_nonce();
    if n == 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_next_nonce_different() -> TestResult {
    let n1 = resource_next_nonce();
    let n2 = resource_next_nonce();
    if n1 == n2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_reset_nonce_counter() -> TestResult {
    let _ = resource_next_nonce();
    resource_reset_nonce_counter();
    let n = resource_next_nonce();
    if n == 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_token_material_produces_40_bytes() -> TestResult {
    let q = ResourceQuota::new(1000, 100, None);
    let mat = resource_token_material(1, &q, 12345);
    if mat.len() != 40 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_token_material_deterministic() -> TestResult {
    let q = ResourceQuota::new(1000, 100, None);
    let mat1 = resource_token_material(1, &q, 12345);
    let mat2 = resource_token_material(1, &q, 12345);
    if mat1 != mat2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_token_material_different_owners() -> TestResult {
    let q = ResourceQuota::new(1000, 100, None);
    let mat1 = resource_token_material(1, &q, 12345);
    let mat2 = resource_token_material(2, &q, 12345);
    if mat1 == mat2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_token_material_different_quotas() -> TestResult {
    let q1 = ResourceQuota::new(1000, 100, None);
    let q2 = ResourceQuota::new(2000, 100, None);
    let mat1 = resource_token_material(1, &q1, 12345);
    let mat2 = resource_token_material(1, &q2, 12345);
    if mat1 == mat2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_token_material_different_nonces() -> TestResult {
    let q = ResourceQuota::new(1000, 100, None);
    let mat1 = resource_token_material(1, &q, 12345);
    let mat2 = resource_token_material(1, &q, 67890);
    if mat1 == mat2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_compute_signature_produces_64_bytes() -> TestResult {
    let key = [0u8; 32];
    let material = [1u8; 40];
    let sig = resource_compute_signature(&key, &material);
    if sig.len() != 64 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_compute_signature_deterministic() -> TestResult {
    let key = [1u8; 32];
    let material = [2u8; 40];
    let sig1 = resource_compute_signature(&key, &material);
    let sig2 = resource_compute_signature(&key, &material);
    if sig1 != sig2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_compute_signature_different_keys() -> TestResult {
    let material = [1u8; 40];
    let sig1 = resource_compute_signature(&[0u8; 32], &material);
    let sig2 = resource_compute_signature(&[1u8; 32], &material);
    if sig1 == sig2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_resource_compute_signature_different_material() -> TestResult {
    let key = [0u8; 32];
    let sig1 = resource_compute_signature(&key, &[0u8; 40]);
    let sig2 = resource_compute_signature(&key, &[1u8; 40]);
    if sig1 == sig2 { return TestResult::Fail; }
    TestResult::Pass
}
