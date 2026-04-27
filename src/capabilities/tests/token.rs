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

pub(crate) fn test_capability_token_empty() -> TestResult {
    let tok = CapabilityToken::empty();
    if tok.owner_module != 0 {
        return TestResult::Fail;
    }
    if !tok.permissions.is_empty() {
        return TestResult::Fail;
    }
    if tok.expires_at_ms != Some(0) {
        return TestResult::Fail;
    }
    if tok.nonce != 0 {
        return TestResult::Fail;
    }
    if tok.signature != [0u8; 64] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_true() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin, Capability::Debug],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if !tok.grants(Capability::Admin) {
        return TestResult::Fail;
    }
    if !tok.grants(Capability::Debug) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_false() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if tok.grants(Capability::Debug) {
        return TestResult::Fail;
    }
    if tok.grants(Capability::Network) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_empty() -> TestResult {
    let tok = CapabilityToken::empty();
    if tok.grants(Capability::Admin) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_permission_count() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin, Capability::Debug, Capability::Crypto],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if tok.permission_count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_has_any_permission_true() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if !tok.has_any_permission() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_has_any_permission_false() -> TestResult {
    let tok = CapabilityToken::empty();
    if tok.has_any_permission() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_all_true() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin, Capability::Debug, Capability::Crypto],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if !tok.grants_all(&[Capability::Admin, Capability::Debug]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_all_false() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if tok.grants_all(&[Capability::Admin, Capability::Debug]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_all_empty() -> TestResult {
    let tok = CapabilityToken::empty();
    if !tok.grants_all(&[]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_any_true() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if !tok.grants_any(&[Capability::Admin, Capability::Debug]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_any_false() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if tok.grants_any(&[Capability::Debug, Capability::Network]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_grants_any_empty_caps() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if tok.grants_any(&[]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_is_admin_true() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if !tok.is_admin() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_is_admin_false() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Debug],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if tok.is_admin() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_register_service_true() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::RegisterService],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if !tok.can_register_service() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_can_register_service_false() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 1,
        permissions: alloc::vec![Capability::Admin],
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    };
    if tok.can_register_service() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_token_display() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 42,
        permissions: alloc::vec![Capability::Admin, Capability::Debug],
        expires_at_ms: None,
        nonce: 0x1234567890ABCDEF,
        signature: [0u8; 64],
    };
    let display = alloc::format!("{}", tok);
    if !display.contains("owner:42") {
        return TestResult::Fail;
    }
    if !display.contains("caps:2") {
        return TestResult::Fail;
    }
    if !display.contains("1234567890abcdef") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_binary_size() -> TestResult {
    if TOKEN_BINARY_SIZE != 97 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_version() -> TestResult {
    if TOKEN_VERSION != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_to_bytes_from_bytes_roundtrip() -> TestResult {
    let tok = CapabilityToken {
        owner_module: 0x123456789ABCDEF0,
        permissions: alloc::vec![Capability::Admin, Capability::Debug],
        expires_at_ms: Some(1000000),
        nonce: 0xFEDCBA9876543210,
        signature: [0xAB; 64],
    };
    let bytes = to_bytes(&tok);
    let recovered = from_bytes(&bytes).unwrap();
    if recovered.owner_module != tok.owner_module {
        return TestResult::Fail;
    }
    if recovered.permissions.len() != tok.permissions.len() {
        return TestResult::Fail;
    }
    if recovered.expires_at_ms != tok.expires_at_ms {
        return TestResult::Fail;
    }
    if recovered.nonce != tok.nonce {
        return TestResult::Fail;
    }
    if recovered.signature != tok.signature {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_to_bytes_version_byte() -> TestResult {
    let tok = CapabilityToken::empty();
    let bytes = to_bytes(&tok);
    if bytes[0] != TOKEN_VERSION {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_from_bytes_invalid_size() -> TestResult {
    let short = [0u8; 50];
    if from_bytes(&short).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_from_bytes_invalid_version() -> TestResult {
    let mut bytes = [0u8; TOKEN_BINARY_SIZE];
    bytes[0] = 99;
    if from_bytes(&bytes).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_from_bytes_zero_expiry_becomes_none() -> TestResult {
    let mut bytes = [0u8; TOKEN_BINARY_SIZE];
    bytes[0] = TOKEN_VERSION;
    let tok = from_bytes(&bytes).unwrap();
    if tok.expires_at_ms != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_nonce_nonzero() -> TestResult {
    let n1 = default_nonce();
    if n1 == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_nonce_different_values() -> TestResult {
    let n1 = default_nonce();
    let n2 = default_nonce();
    if n1 == n2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nonce_counter_increment() -> TestResult {
    reset_nonce_counter();
    let c1 = current_nonce_counter();
    let _ = default_nonce();
    let c2 = current_nonce_counter();
    if c2 < c1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reset_nonce_counter() -> TestResult {
    let _ = default_nonce();
    reset_nonce_counter();
    if current_nonce_counter() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_revoke_token() -> TestResult {
    clear_revocations();
    revoke_token(100, 200);
    if !is_revoked(100, 200) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_revoked_false() -> TestResult {
    clear_revocations();
    if is_revoked(999, 888) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_revoked_count() -> TestResult {
    clear_revocations();
    if revoked_count() != 0 {
        return TestResult::Fail;
    }
    revoke_token(1, 1);
    revoke_token(2, 2);
    if revoked_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clear_revocations() -> TestResult {
    revoke_token(1, 1);
    clear_revocations();
    if revoked_count() != 0 {
        return TestResult::Fail;
    }
    if is_revoked(1, 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_revoke_all_for_owner() -> TestResult {
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
    if after_count >= before_count && before_count > 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mac64_produces_64_bytes() -> TestResult {
    let key = [0u8; 32];
    let material = [1u8; 32];
    let mac = mac64(&key, &material);
    if mac.len() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mac64_deterministic() -> TestResult {
    let key = [1u8; 32];
    let material = [2u8; 32];
    let mac1 = mac64(&key, &material);
    let mac2 = mac64(&key, &material);
    if mac1 != mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mac64_different_keys_different_output() -> TestResult {
    let material = [1u8; 32];
    let mac1 = mac64(&[0u8; 32], &material);
    let mac2 = mac64(&[1u8; 32], &material);
    if mac1 == mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mac64_different_material_different_output() -> TestResult {
    let key = [0u8; 32];
    let mac1 = mac64(&key, &[0u8; 32]);
    let mac2 = mac64(&key, &[1u8; 32]);
    if mac1 == mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_material_produces_32_bytes() -> TestResult {
    let mat = token_material(1, 2, 3, 4);
    if mat.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_material_deterministic() -> TestResult {
    let mat1 = token_material(100, 200, 300, 400);
    let mat2 = token_material(100, 200, 300, 400);
    if mat1 != mat2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_token_material_different_inputs() -> TestResult {
    let mat1 = token_material(1, 2, 3, 4);
    let mat2 = token_material(1, 2, 3, 5);
    if mat1 == mat2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
