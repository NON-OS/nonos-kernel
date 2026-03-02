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
fn test_auth_context_new() {
    let ctx = AuthContext::new();
    assert!(!ctx.verified);
    assert!(!ctx.pqc_verified);
    assert!(ctx.attestation_chain.is_none());
    assert!(ctx.failure_reason.is_none());
}

#[test]
fn test_auth_context_is_authenticated() {
    let mut ctx = AuthContext::new();
    assert!(!ctx.is_authenticated());

    ctx.verified = true;
    assert!(ctx.is_authenticated());

    ctx.verified = false;
    ctx.pqc_verified = true;
    assert!(ctx.is_authenticated());
}

#[test]
fn test_auth_context_security_level() {
    let ctx = AuthContext::new();
    assert_eq!(ctx.security_level(), SecurityLevel::None);

    let ctx = AuthContext::new().with_classical_verified();
    assert_eq!(ctx.security_level(), SecurityLevel::Classical);

    let ctx = AuthContext::new().with_pqc_verified();
    assert_eq!(ctx.security_level(), SecurityLevel::PostQuantum);
}

#[test]
fn test_auth_result_is_success() {
    assert!(AuthResult::Verified.is_success());
    assert!(AuthResult::VerifiedPqc.is_success());
    assert!(AuthResult::Attested.is_success());
    assert!(!AuthResult::Failed("test".into()).is_success());
}

#[test]
fn test_auth_result_security_level() {
    assert_eq!(AuthResult::Verified.security_level(), SecurityLevel::Classical);
    assert_eq!(AuthResult::VerifiedPqc.security_level(), SecurityLevel::PostQuantum);
    assert_eq!(AuthResult::Attested.security_level(), SecurityLevel::Attested);
    assert_eq!(AuthResult::Failed("x".into()).security_level(), SecurityLevel::None);
}

#[test]
fn test_authenticate_module_classical_fail() {
    let code = b"module-test";
    let sig = [0u8; 64];
    let pk = [0u8; 32];

    let ctx = authenticate_module(code, &sig, &pk, None, None, None);

    assert!(!ctx.verified);
    assert!(ctx.failure_reason.is_some());
}

#[test]
fn test_erase_auth_context() {
    let mut ctx = AuthContext {
        verified: true,
        pqc_verified: true,
        attestation_chain: None,
        failure_reason: Some("Test failure reason".into()),
    };

    erase_auth_context(&mut ctx);

    assert!(!ctx.verified);
    assert!(!ctx.pqc_verified);
    assert!(ctx.attestation_chain.is_none());
    assert!(ctx.failure_reason.is_none());
}

#[test]
fn test_auth_context_builder_pattern() {
    let ctx = AuthContext::new()
        .with_classical_verified()
        .with_pqc_verified()
        .with_failure("test reason");

    assert!(ctx.verified);
    assert!(ctx.pqc_verified);
    assert_eq!(ctx.failure_reason, Some("test reason".into()));
}

#[test]
fn test_security_level_ordering() {
    assert!(SecurityLevel::None < SecurityLevel::Classical);
    assert!(SecurityLevel::Classical < SecurityLevel::PostQuantum);
    assert!(SecurityLevel::PostQuantum < SecurityLevel::Attested);
}

#[test]
fn test_error_messages() {
    use super::error::AuthError;

    assert_eq!(
        AuthError::InvalidSignatureLength.as_str(),
        "Invalid signature length"
    );
    assert_eq!(
        AuthError::Ed25519VerificationFailed.as_str(),
        "Ed25519 verification failed"
    );
    assert_eq!(
        AuthError::DilithiumVerificationFailed.as_str(),
        "Dilithium verification failed"
    );
    assert_eq!(
        AuthError::AttestationFailed.as_str(),
        "Attestation chain verification failed"
    );
}

#[test]
fn test_verify_signature_constant_time_invalid() {
    let code = b"test code";
    let sig = [0u8; 64];
    let pk = [0u8; 32];

    assert!(!verify_signature_constant_time(code, &sig, &pk));
}
