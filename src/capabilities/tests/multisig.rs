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

fn make_multisig_token(owner: u64, caps: &[Capability], threshold: usize, signers: &[u64]) -> MultiSigToken {
    create_multisig_token_with_nonce(owner, caps, threshold, signers, None, 12345).unwrap()
}

#[test]
fn test_max_signers_constant() {
    assert_eq!(MAX_SIGNERS, 16);
}

#[test]
fn test_max_threshold_constant() {
    assert_eq!(MAX_THRESHOLD, 16);
}

#[test]
fn test_signature_size_constant() {
    assert_eq!(SIGNATURE_SIZE, 32);
}

#[test]
fn test_max_signers_function() {
    assert_eq!(max_signers(), 16);
}

#[test]
fn test_max_threshold_function() {
    assert_eq!(max_threshold(), 16);
}

#[test]
fn test_multisig_token_grants_true() {
    let tok = make_multisig_token(1, &[Capability::Admin, Capability::Debug], 2, &[10, 20]);
    assert!(tok.grants(Capability::Admin));
    assert!(tok.grants(Capability::Debug));
}

#[test]
fn test_multisig_token_grants_false() {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    assert!(!tok.grants(Capability::Debug));
}

#[test]
fn test_multisig_token_signature_count_initial() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    assert_eq!(tok.signature_count(), 0);
}

#[test]
fn test_multisig_token_threshold_met_false() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    assert!(!tok.threshold_met());
}

#[test]
fn test_multisig_token_signatures_needed() {
    let tok = make_multisig_token(1, &[Capability::Admin], 3, &[10, 20, 30]);
    assert_eq!(tok.signatures_needed(), 3);
}

#[test]
fn test_multisig_token_has_signed_false() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    assert!(!tok.has_signed(10));
}

#[test]
fn test_multisig_token_is_authorized_true() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30]);
    assert!(tok.is_authorized(10));
    assert!(tok.is_authorized(20));
    assert!(tok.is_authorized(30));
}

#[test]
fn test_multisig_token_is_authorized_false() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    assert!(!tok.is_authorized(99));
}

#[test]
fn test_multisig_token_signed_by_empty() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    assert!(tok.signed_by().is_empty());
}

#[test]
fn test_multisig_token_pending_signers_all() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30]);
    let pending = tok.pending_signers();
    assert_eq!(pending.len(), 3);
    assert!(pending.contains(&10));
    assert!(pending.contains(&20));
    assert!(pending.contains(&30));
}

#[test]
fn test_multisig_token_is_expired_false() {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    assert!(!tok.is_expired());
}

#[test]
fn test_multisig_token_remaining_ms_none() {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    assert!(tok.remaining_ms().is_none());
}

#[test]
fn test_multisig_token_permission_count() {
    let tok = make_multisig_token(1, &[Capability::Admin, Capability::Debug, Capability::Crypto], 1, &[10]);
    assert_eq!(tok.permission_count(), 3);
}

#[test]
fn test_multisig_token_signer_count() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30, 40]);
    assert_eq!(tok.signer_count(), 4);
}

#[test]
fn test_multisig_token_display() {
    let tok = make_multisig_token(42, &[Capability::Admin, Capability::Debug], 2, &[10, 20, 30]);
    let display = alloc::format!("{}", tok);
    assert!(display.contains("owner:42"));
    assert!(display.contains("caps:2"));
    assert!(display.contains("sigs:0/2"));
    assert!(display.contains("auth:3"));
}

#[test]
fn test_multisig_error_no_signers_as_str() {
    let err = MultiSigError::NoSigners;
    assert_eq!(err.as_str(), "No signers specified");
}

#[test]
fn test_multisig_error_too_many_signers_as_str() {
    let err = MultiSigError::TooManySigners { count: 20, max: 16 };
    assert_eq!(err.as_str(), "Too many signers");
}

#[test]
fn test_multisig_error_threshold_exceeds_signers_as_str() {
    let err = MultiSigError::ThresholdExceedsSigners { threshold: 5, signers: 3 };
    assert_eq!(err.as_str(), "Threshold exceeds signer count");
}

#[test]
fn test_multisig_error_zero_threshold_as_str() {
    let err = MultiSigError::ZeroThreshold;
    assert_eq!(err.as_str(), "Threshold cannot be zero");
}

#[test]
fn test_multisig_error_duplicate_signer_as_str() {
    let err = MultiSigError::DuplicateSigner { signer_id: 10 };
    assert_eq!(err.as_str(), "Signer already signed");
}

#[test]
fn test_multisig_error_unauthorized_signer_as_str() {
    let err = MultiSigError::UnauthorizedSigner { signer_id: 99 };
    assert_eq!(err.as_str(), "Signer not authorized");
}

#[test]
fn test_multisig_error_threshold_not_met_as_str() {
    let err = MultiSigError::ThresholdNotMet { have: 1, need: 3 };
    assert_eq!(err.as_str(), "Insufficient signatures");
}

#[test]
fn test_multisig_error_token_expired_as_str() {
    let err = MultiSigError::TokenExpired;
    assert_eq!(err.as_str(), "Token has expired");
}

#[test]
fn test_multisig_error_invalid_signature_as_str() {
    let err = MultiSigError::InvalidSignature { signer_id: 10 };
    assert_eq!(err.as_str(), "Invalid signature");
}

#[test]
fn test_multisig_error_is_recoverable_duplicate() {
    let err = MultiSigError::DuplicateSigner { signer_id: 10 };
    assert!(err.is_recoverable());
}

#[test]
fn test_multisig_error_is_recoverable_threshold_not_met() {
    let err = MultiSigError::ThresholdNotMet { have: 1, need: 3 };
    assert!(err.is_recoverable());
}

#[test]
fn test_multisig_error_is_recoverable_no_signers() {
    let err = MultiSigError::NoSigners;
    assert!(!err.is_recoverable());
}

#[test]
fn test_multisig_error_display_no_signers() {
    let err = MultiSigError::NoSigners;
    let display = alloc::format!("{}", err);
    assert!(display.contains("No signers"));
}

#[test]
fn test_multisig_error_display_too_many_signers() {
    let err = MultiSigError::TooManySigners { count: 20, max: 16 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("20"));
    assert!(display.contains("16"));
}

#[test]
fn test_multisig_error_display_threshold_exceeds() {
    let err = MultiSigError::ThresholdExceedsSigners { threshold: 5, signers: 3 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("5"));
    assert!(display.contains("3"));
}

#[test]
fn test_multisig_error_display_duplicate_signer() {
    let err = MultiSigError::DuplicateSigner { signer_id: 42 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("42"));
}

#[test]
fn test_multisig_error_display_unauthorized() {
    let err = MultiSigError::UnauthorizedSigner { signer_id: 99 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("99"));
}

#[test]
fn test_multisig_error_display_threshold_not_met() {
    let err = MultiSigError::ThresholdNotMet { have: 2, need: 5 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("2"));
    assert!(display.contains("5"));
}

#[test]
fn test_multisig_error_display_invalid_signature() {
    let err = MultiSigError::InvalidSignature { signer_id: 77 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("77"));
}

#[test]
fn test_multisig_error_equality() {
    assert_eq!(MultiSigError::NoSigners, MultiSigError::NoSigners);
    assert_ne!(MultiSigError::NoSigners, MultiSigError::ZeroThreshold);
    assert_eq!(
        MultiSigError::DuplicateSigner { signer_id: 10 },
        MultiSigError::DuplicateSigner { signer_id: 10 }
    );
    assert_ne!(
        MultiSigError::DuplicateSigner { signer_id: 10 },
        MultiSigError::DuplicateSigner { signer_id: 20 }
    );
}

#[test]
fn test_create_multisig_token_zero_threshold() {
    let result = create_multisig_token(1, &[Capability::Admin], 0, &[10, 20], None);
    assert!(matches!(result, Err(MultiSigError::ZeroThreshold)));
}

#[test]
fn test_create_multisig_token_no_signers() {
    let result = create_multisig_token(1, &[Capability::Admin], 1, &[], None);
    assert!(matches!(result, Err(MultiSigError::NoSigners)));
}

#[test]
fn test_create_multisig_token_threshold_exceeds_signers() {
    let result = create_multisig_token(1, &[Capability::Admin], 5, &[10, 20], None);
    assert!(matches!(result, Err(MultiSigError::ThresholdExceedsSigners { .. })));
}

#[test]
fn test_create_multisig_token_too_many_signers() {
    let signers: alloc::vec::Vec<u64> = (0..20).collect();
    let result = create_multisig_token(1, &[Capability::Admin], 1, &signers, None);
    assert!(matches!(result, Err(MultiSigError::TooManySigners { .. })));
}

#[test]
fn test_create_multisig_token_success() {
    let result = create_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30], None);
    assert!(result.is_ok());
    let tok = result.unwrap();
    assert_eq!(tok.owner_module, 1);
    assert_eq!(tok.threshold, 2);
    assert_eq!(tok.signer_count(), 3);
}

#[test]
fn test_create_multisig_token_with_nonce() {
    let result = create_multisig_token_with_nonce(1, &[Capability::Admin], 1, &[10], None, 99999);
    assert!(result.is_ok());
    let tok = result.unwrap();
    assert_eq!(tok.nonce, 99999);
}

#[test]
fn test_add_signature_unauthorized() {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    let result = add_signature(&mut tok, 99, &key);
    assert!(matches!(result, Err(MultiSigError::UnauthorizedSigner { signer_id: 99 })));
}

#[test]
fn test_add_signature_success() {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    let result = add_signature(&mut tok, 10, &key);
    assert!(result.is_ok());
    assert!(tok.has_signed(10));
    assert_eq!(tok.signature_count(), 1);
}

#[test]
fn test_add_signature_duplicate() {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    add_signature(&mut tok, 10, &key).unwrap();
    let result = add_signature(&mut tok, 10, &key);
    assert!(matches!(result, Err(MultiSigError::DuplicateSigner { signer_id: 10 })));
}

#[test]
fn test_remove_signature_present() {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    add_signature(&mut tok, 10, &key).unwrap();
    assert!(remove_signature(&mut tok, 10));
    assert!(!tok.has_signed(10));
    assert_eq!(tok.signature_count(), 0);
}

#[test]
fn test_remove_signature_not_present() {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    assert!(!remove_signature(&mut tok, 99));
}

#[test]
fn test_clear_signatures() {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    add_signature(&mut tok, 10, &key).unwrap();
    add_signature(&mut tok, 20, &key).unwrap();
    clear_signatures(&mut tok);
    assert_eq!(tok.signature_count(), 0);
    assert!(tok.signed_by().is_empty());
}

#[test]
fn test_signature_material_produces_40_bytes() {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    let mat = signature_material(&tok, 10);
    assert_eq!(mat.len(), 40);
}

#[test]
fn test_signature_material_deterministic() {
    let tok = make_multisig_token(100, &[Capability::Admin, Capability::Debug], 1, &[10]);
    let mat1 = signature_material(&tok, 10);
    let mat2 = signature_material(&tok, 10);
    assert_eq!(mat1, mat2);
}

#[test]
fn test_signature_material_different_signers() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let mat1 = signature_material(&tok, 10);
    let mat2 = signature_material(&tok, 20);
    assert_ne!(mat1, mat2);
}

#[test]
fn test_compute_signature_produces_32_bytes() {
    let key = [0u8; 32];
    let material = [1u8; 40];
    let sig = multisig_compute_signature(&key, &material);
    assert_eq!(sig.len(), 32);
}

#[test]
fn test_compute_signature_deterministic() {
    let key = [1u8; 32];
    let material = [2u8; 40];
    let sig1 = multisig_compute_signature(&key, &material);
    let sig2 = multisig_compute_signature(&key, &material);
    assert_eq!(sig1, sig2);
}

#[test]
fn test_compute_signature_different_keys() {
    let material = [1u8; 40];
    let sig1 = multisig_compute_signature(&[0u8; 32], &material);
    let sig2 = multisig_compute_signature(&[1u8; 32], &material);
    assert_ne!(sig1, sig2);
}

#[test]
fn test_count_valid_signatures_empty() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let keys: alloc::vec::Vec<(&u64, &[u8; 32])> = alloc::vec![];
    assert_eq!(count_valid_signatures(&tok, &keys), 0);
}

#[test]
fn test_verify_multisig_threshold_not_met() {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key10 = [1u8; 32];
    let keys: alloc::vec::Vec<(&u64, &[u8; 32])> = alloc::vec![(&10u64, &key10)];
    let result = verify_multisig(&tok, &keys);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
