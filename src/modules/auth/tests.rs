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

use super::*;

#[test]
fn test_auth_context_default() {
    let ctx = AuthContext::default();
    assert!(!ctx.verified);
    assert!(!ctx.pqc_verified);
    assert!(!ctx.attestation_valid);
    assert_eq!(ctx.method, AuthMethod::Ed25519);
}

#[test]
fn test_auth_context_builder() {
    let hash = [1u8; 32];
    let ctx = AuthContext::new()
        .with_hash(hash)
        .with_method(AuthMethod::Hybrid);
    assert_eq!(ctx.hash, hash);
    assert_eq!(ctx.method, AuthMethod::Hybrid);
}

#[test]
fn test_auth_method_pqc() {
    assert!(!AuthMethod::Ed25519.requires_pqc());
    assert!(AuthMethod::Dilithium.requires_pqc());
    assert!(AuthMethod::Hybrid.requires_pqc());
}

#[test]
fn test_authenticate_empty_code() {
    let ctx = authenticate_module(&[], None, None, None, None, None);
    assert!(!ctx.is_verified());
}

#[test]
fn test_authenticate_no_signature() {
    let code = b"test module code";
    let ctx = authenticate_module(code, None, None, None, None, None);
    assert!(ctx.verified);
    assert_eq!(ctx.method, AuthMethod::None);
}

#[test]
fn test_erase_auth_context() {
    let mut ctx = AuthContext {
        verified: true,
        pqc_verified: true,
        attestation_valid: true,
        method: AuthMethod::Hybrid,
        hash: [0xFF; 32],
    };

    erase_auth_context(&mut ctx);

    assert!(!ctx.verified);
    assert!(!ctx.pqc_verified);
    assert!(!ctx.attestation_valid);
    assert_eq!(ctx.method, AuthMethod::None);
    assert_eq!(ctx.hash, [0u8; 32]);
}

#[test]
fn test_auth_error_errno() {
    assert_eq!(AuthError::EmptyCode.to_errno(), -22);
    assert_eq!(AuthError::Ed25519VerificationFailed.to_errno(), -1);
    assert_eq!(AuthError::TrustedKeyNotFound.to_errno(), -2);
}

#[test]
fn test_signature_data() {
    let sig = [0xAA; 64];
    let pk = [0xBB; 32];
    let data = SignatureData::new(sig, pk);
    assert_eq!(data.r(), &[0xAA; 32]);
    assert_eq!(data.s(), &[0xAA; 32]);
}
