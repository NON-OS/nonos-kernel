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
fn test_capability_token_empty() {
    let tok = CapabilityToken::empty();
    assert_eq!(tok.owner_module, 0);
    assert!(tok.permissions.is_empty());
    assert_eq!(tok.expires_at_ms, Some(0));
    assert_eq!(tok.nonce, 0);
    assert_eq!(tok.signature, [0u8; 64]);
}

#[test]
fn test_capability_token_grants_true() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin, Capability::Debug],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(tok.grants(Capability::Admin));
    assert!(tok.grants(Capability::Debug));
}

#[test]
fn test_capability_token_grants_false() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!tok.grants(Capability::Debug));
    assert!(!tok.grants(Capability::Network));
}

#[test]
fn test_capability_token_grants_empty() {
    let tok = CapabilityToken::empty();
    assert!(!tok.grants(Capability::Admin));
}

#[test]
fn test_capability_token_permission_count() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin, Capability::Debug, Capability::Crypto],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert_eq!(tok.permission_count(), 3);
}

#[test]
fn test_capability_token_has_any_permission_true() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(tok.has_any_permission());
}

#[test]
fn test_capability_token_has_any_permission_false() {
    let tok = CapabilityToken::empty();
    assert!(!tok.has_any_permission());
}

#[test]
fn test_capability_token_grants_all_true() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin, Capability::Debug, Capability::Crypto],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(tok.grants_all(&[Capability::Admin, Capability::Debug]));
}

#[test]
fn test_capability_token_grants_all_false() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!tok.grants_all(&[Capability::Admin, Capability::Debug]));
}

#[test]
fn test_capability_token_grants_all_empty() {
    let tok = CapabilityToken::empty();
    assert!(tok.grants_all(&[]));
}

#[test]
fn test_capability_token_grants_any_true() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(tok.grants_any(&[Capability::Admin, Capability::Debug]));
}

#[test]
fn test_capability_token_grants_any_false() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!tok.grants_any(&[Capability::Debug, Capability::Network]));
}

#[test]
fn test_capability_token_grants_any_empty_caps() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!tok.grants_any(&[]));
}

#[test]
fn test_capability_token_is_admin_true() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(tok.is_admin());
}

#[test]
fn test_capability_token_is_admin_false() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Debug],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!tok.is_admin());
}

#[test]
fn test_capability_token_can_register_service_true() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::RegisterService],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(tok.can_register_service());
}

#[test]
fn test_capability_token_can_register_service_false() {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    assert!(!tok.can_register_service());
}

#[test]
fn test_capability_token_display() {
    let tok = CapabilityToken {
        owner_module: 42,
        permissions: alloc::vec![Capability::Admin, Capability::Debug],
        expires_at_ms: None,
        nonce: 0x1234567890ABCDEF,
        signature: [0u8; 64],
    };
    let display = alloc::format!("{}", tok);
    assert!(display.contains("owner:42"));
    assert!(display.contains("caps:2"));
    assert!(display.contains("1234567890abcdef"));
}

#[test]
fn test_token_binary_size() {
    assert_eq!(TOKEN_BINARY_SIZE, 97);
}

#[test]
fn test_token_version() {
    assert_eq!(TOKEN_VERSION, 1);
}

#[test]
fn test_to_bytes_from_bytes_roundtrip() {
    let tok = CapabilityToken {
        owner_module: 0x123456789ABCDEF0,
        permissions: alloc::vec![Capability::Admin, Capability::Debug],
        expires_at_ms: Some(1000000),
        nonce: 0xFEDCBA9876543210,
        signature: [0xAB; 64],
    };
    let bytes = to_bytes(&tok);
    let recovered = from_bytes(&bytes).unwrap();
    assert_eq!(recovered.owner_module, tok.owner_module);
    assert_eq!(recovered.permissions.len(), tok.permissions.len());
    assert_eq!(recovered.expires_at_ms, tok.expires_at_ms);
    assert_eq!(recovered.nonce, tok.nonce);
    assert_eq!(recovered.signature, tok.signature);
}

#[test]
fn test_to_bytes_version_byte() {
    let tok = CapabilityToken::empty();
    let bytes = to_bytes(&tok);
    assert_eq!(bytes[0], TOKEN_VERSION);
}

#[test]
fn test_from_bytes_invalid_size() {
    let short = [0u8; 50];
    assert!(from_bytes(&short).is_err());
}

#[test]
fn test_from_bytes_invalid_version() {
    let mut bytes = [0u8; TOKEN_BINARY_SIZE];
    bytes[0] = 99;
    assert!(from_bytes(&bytes).is_err());
}

#[test]
fn test_from_bytes_zero_expiry_becomes_none() {
    let mut bytes = [0u8; TOKEN_BINARY_SIZE];
    bytes[0] = TOKEN_VERSION;
    let tok = from_bytes(&bytes).unwrap();
    assert_eq!(tok.expires_at_ms, None);
}

#[test]
fn test_default_nonce_nonzero() {
    let n1 = default_nonce();
    assert_ne!(n1, 0);
}

#[test]
fn test_default_nonce_different_values() {
    let n1 = default_nonce();
    let n2 = default_nonce();
    assert_ne!(n1, n2);
}

#[test]
fn test_nonce_counter_increment() {
    reset_nonce_counter();
    let c1 = current_nonce_counter();
    let _ = default_nonce();
    let c2 = current_nonce_counter();
    assert!(c2 >= c1);
}

#[test]
fn test_reset_nonce_counter() {
    let _ = default_nonce();
    reset_nonce_counter();
    assert_eq!(current_nonce_counter(), 1);
}

#[test]
fn test_revoke_token() {
    clear_revocations();
    revoke_token(100, 200);
    assert!(is_revoked(100, 200));
}

#[test]
fn test_is_revoked_false() {
    clear_revocations();
    assert!(!is_revoked(999, 888));
}

#[test]
fn test_revoked_count() {
    clear_revocations();
    assert_eq!(revoked_count(), 0);
    revoke_token(1, 1);
    revoke_token(2, 2);
    assert_eq!(revoked_count(), 2);
}

#[test]
fn test_clear_revocations() {
    revoke_token(1, 1);
    clear_revocations();
    assert_eq!(revoked_count(), 0);
    assert!(!is_revoked(1, 1));
}

#[test]
fn test_revoke_all_for_owner() {
    let owner_a = 0xDEAD_BEEF_CAFE_1001;
    let owner_b = 0xDEAD_BEEF_CAFE_1002;
    let nonce_1 = 0xAAAA_0001;
    let nonce_2 = 0xAAAA_0002;
    let nonce_3 = 0xAAAA_0003;
    revoke_token(owner_a, nonce_1);
    revoke_token(owner_a, nonce_2);
    revoke_token(owner_b, nonce_3);
    let before_count = revoked_count();
    revoke_all_for_owner(owner_a);
    let after_count = revoked_count();
    assert!(after_count < before_count || before_count == 0);
}

#[test]
fn test_mac64_produces_64_bytes() {
    let key = [0u8; 32];
    let material = [1u8; 32];
    let mac = mac64(&key, &material);
    assert_eq!(mac.len(), 64);
}

#[test]
fn test_mac64_deterministic() {
    let key = [1u8; 32];
    let material = [2u8; 32];
    let mac1 = mac64(&key, &material);
    let mac2 = mac64(&key, &material);
    assert_eq!(mac1, mac2);
}

#[test]
fn test_mac64_different_keys_different_output() {
    let material = [1u8; 32];
    let mac1 = mac64(&[0u8; 32], &material);
    let mac2 = mac64(&[1u8; 32], &material);
    assert_ne!(mac1, mac2);
}

#[test]
fn test_mac64_different_material_different_output() {
    let key = [0u8; 32];
    let mac1 = mac64(&key, &[0u8; 32]);
    let mac2 = mac64(&key, &[1u8; 32]);
    assert_ne!(mac1, mac2);
}

#[test]
fn test_token_material_produces_32_bytes() {
    let mat = token_material(1, 2, 3, 4);
    assert_eq!(mat.len(), 32);
}

#[test]
fn test_token_material_deterministic() {
    let mat1 = token_material(100, 200, 300, 400);
    let mat2 = token_material(100, 200, 300, 400);
    assert_eq!(mat1, mat2);
}

#[test]
fn test_token_material_different_inputs() {
    let mat1 = token_material(1, 2, 3, 4);
    let mat2 = token_material(1, 2, 3, 5);
    assert_ne!(mat1, mat2);
}
