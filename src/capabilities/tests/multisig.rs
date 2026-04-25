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

fn make_multisig_token(owner: u64, caps: &[Capability], threshold: usize, signers: &[u64]) -> MultiSigToken {
    create_multisig_token_with_nonce(owner, caps, threshold, signers, None, 12345).unwrap()
}

pub(crate) fn test_max_signers_constant() -> TestResult {
    if MAX_SIGNERS != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_max_threshold_constant() -> TestResult {
    if MAX_THRESHOLD != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_signature_size_constant() -> TestResult {
    if SIGNATURE_SIZE != 32 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_max_signers_function() -> TestResult {
    if max_signers() != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_max_threshold_function() -> TestResult {
    if max_threshold() != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_grants_true() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin, Capability::Debug], 2, &[10, 20]);
    if !tok.grants(Capability::Admin) { return TestResult::Fail; }
    if !tok.grants(Capability::Debug) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_grants_false() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    if tok.grants(Capability::Debug) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_signature_count_initial() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    if tok.signature_count() != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_threshold_met_false() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    if tok.threshold_met() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_signatures_needed() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 3, &[10, 20, 30]);
    if tok.signatures_needed() != 3 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_has_signed_false() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    if tok.has_signed(10) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_is_authorized_true() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30]);
    if !tok.is_authorized(10) { return TestResult::Fail; }
    if !tok.is_authorized(20) { return TestResult::Fail; }
    if !tok.is_authorized(30) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_is_authorized_false() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    if tok.is_authorized(99) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_signed_by_empty() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    if !tok.signed_by().is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_pending_signers_all() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30]);
    let pending = tok.pending_signers();
    if pending.len() != 3 { return TestResult::Fail; }
    if !pending.contains(&10) { return TestResult::Fail; }
    if !pending.contains(&20) { return TestResult::Fail; }
    if !pending.contains(&30) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_is_expired_false() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    if tok.is_expired() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_remaining_ms_none() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    if tok.remaining_ms().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_permission_count() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin, Capability::Debug, Capability::Crypto], 1, &[10]);
    if tok.permission_count() != 3 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_signer_count() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30, 40]);
    if tok.signer_count() != 4 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_token_display() -> TestResult {
    let tok = make_multisig_token(42, &[Capability::Admin, Capability::Debug], 2, &[10, 20, 30]);
    let display = alloc::format!("{}", tok);
    if !display.contains("owner:42") { return TestResult::Fail; }
    if !display.contains("caps:2") { return TestResult::Fail; }
    if !display.contains("sigs:0/2") { return TestResult::Fail; }
    if !display.contains("auth:3") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_no_signers_as_str() -> TestResult {
    let err = MultiSigError::NoSigners;
    if err.as_str() != "No signers specified" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_too_many_signers_as_str() -> TestResult {
    let err = MultiSigError::TooManySigners { count: 20, max: 16 };
    if err.as_str() != "Too many signers" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_threshold_exceeds_signers_as_str() -> TestResult {
    let err = MultiSigError::ThresholdExceedsSigners { threshold: 5, signers: 3 };
    if err.as_str() != "Threshold exceeds signer count" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_zero_threshold_as_str() -> TestResult {
    let err = MultiSigError::ZeroThreshold;
    if err.as_str() != "Threshold cannot be zero" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_duplicate_signer_as_str() -> TestResult {
    let err = MultiSigError::DuplicateSigner { signer_id: 10 };
    if err.as_str() != "Signer already signed" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_unauthorized_signer_as_str() -> TestResult {
    let err = MultiSigError::UnauthorizedSigner { signer_id: 99 };
    if err.as_str() != "Signer not authorized" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_threshold_not_met_as_str() -> TestResult {
    let err = MultiSigError::ThresholdNotMet { have: 1, need: 3 };
    if err.as_str() != "Insufficient signatures" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_token_expired_as_str() -> TestResult {
    let err = MultiSigError::TokenExpired;
    if err.as_str() != "Token has expired" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_invalid_signature_as_str() -> TestResult {
    let err = MultiSigError::InvalidSignature { signer_id: 10 };
    if err.as_str() != "Invalid signature" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_is_recoverable_duplicate() -> TestResult {
    let err = MultiSigError::DuplicateSigner { signer_id: 10 };
    if !err.is_recoverable() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_is_recoverable_threshold_not_met() -> TestResult {
    let err = MultiSigError::ThresholdNotMet { have: 1, need: 3 };
    if !err.is_recoverable() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_is_recoverable_no_signers() -> TestResult {
    let err = MultiSigError::NoSigners;
    if err.is_recoverable() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_display_no_signers() -> TestResult {
    let err = MultiSigError::NoSigners;
    let display = alloc::format!("{}", err);
    if !display.contains("No signers") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_display_too_many_signers() -> TestResult {
    let err = MultiSigError::TooManySigners { count: 20, max: 16 };
    let display = alloc::format!("{}", err);
    if !display.contains("20") { return TestResult::Fail; }
    if !display.contains("16") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_display_threshold_exceeds() -> TestResult {
    let err = MultiSigError::ThresholdExceedsSigners { threshold: 5, signers: 3 };
    let display = alloc::format!("{}", err);
    if !display.contains("5") { return TestResult::Fail; }
    if !display.contains("3") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_display_duplicate_signer() -> TestResult {
    let err = MultiSigError::DuplicateSigner { signer_id: 42 };
    let display = alloc::format!("{}", err);
    if !display.contains("42") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_display_unauthorized() -> TestResult {
    let err = MultiSigError::UnauthorizedSigner { signer_id: 99 };
    let display = alloc::format!("{}", err);
    if !display.contains("99") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_display_threshold_not_met() -> TestResult {
    let err = MultiSigError::ThresholdNotMet { have: 2, need: 5 };
    let display = alloc::format!("{}", err);
    if !display.contains("2") { return TestResult::Fail; }
    if !display.contains("5") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_display_invalid_signature() -> TestResult {
    let err = MultiSigError::InvalidSignature { signer_id: 77 };
    let display = alloc::format!("{}", err);
    if !display.contains("77") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_multisig_error_equality() -> TestResult {
    if MultiSigError::NoSigners != MultiSigError::NoSigners { return TestResult::Fail; }
    if MultiSigError::NoSigners == MultiSigError::ZeroThreshold { return TestResult::Fail; }
    let e1 = MultiSigError::DuplicateSigner { signer_id: 10 };
    let e2 = MultiSigError::DuplicateSigner { signer_id: 10 };
    let e3 = MultiSigError::DuplicateSigner { signer_id: 20 };
    if e1 != e2 { return TestResult::Fail; }
    if e1 == e3 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_multisig_token_zero_threshold() -> TestResult {
    let result = create_multisig_token(1, &[Capability::Admin], 0, &[10, 20], None);
    if !matches!(result, Err(MultiSigError::ZeroThreshold)) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_multisig_token_no_signers() -> TestResult {
    let result = create_multisig_token(1, &[Capability::Admin], 1, &[], None);
    if !matches!(result, Err(MultiSigError::NoSigners)) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_multisig_token_threshold_exceeds_signers() -> TestResult {
    let result = create_multisig_token(1, &[Capability::Admin], 5, &[10, 20], None);
    if !matches!(result, Err(MultiSigError::ThresholdExceedsSigners { .. })) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_multisig_token_too_many_signers() -> TestResult {
    let signers: alloc::vec::Vec<u64> = (0..20).collect();
    let result = create_multisig_token(1, &[Capability::Admin], 1, &signers, None);
    if !matches!(result, Err(MultiSigError::TooManySigners { .. })) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_multisig_token_success() -> TestResult {
    let result = create_multisig_token(1, &[Capability::Admin], 2, &[10, 20, 30], None);
    if result.is_err() { return TestResult::Fail; }
    let tok = result.unwrap();
    if tok.owner_module != 1 { return TestResult::Fail; }
    if tok.threshold != 2 { return TestResult::Fail; }
    if tok.signer_count() != 3 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_create_multisig_token_with_nonce() -> TestResult {
    let result = create_multisig_token_with_nonce(1, &[Capability::Admin], 1, &[10], None, 99999);
    if result.is_err() { return TestResult::Fail; }
    let tok = result.unwrap();
    if tok.nonce != 99999 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_add_signature_unauthorized() -> TestResult {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    let result = add_signature(&mut tok, 99, &key);
    if !matches!(result, Err(MultiSigError::UnauthorizedSigner { signer_id: 99 })) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_add_signature_success() -> TestResult {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    let result = add_signature(&mut tok, 10, &key);
    if result.is_err() { return TestResult::Fail; }
    if !tok.has_signed(10) { return TestResult::Fail; }
    if tok.signature_count() != 1 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_add_signature_duplicate() -> TestResult {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    add_signature(&mut tok, 10, &key).unwrap();
    let result = add_signature(&mut tok, 10, &key);
    if !matches!(result, Err(MultiSigError::DuplicateSigner { signer_id: 10 })) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_remove_signature_present() -> TestResult {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    add_signature(&mut tok, 10, &key).unwrap();
    if !remove_signature(&mut tok, 10) { return TestResult::Fail; }
    if tok.has_signed(10) { return TestResult::Fail; }
    if tok.signature_count() != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_remove_signature_not_present() -> TestResult {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    if remove_signature(&mut tok, 99) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_clear_signatures() -> TestResult {
    let mut tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key = [1u8; 32];
    add_signature(&mut tok, 10, &key).unwrap();
    add_signature(&mut tok, 20, &key).unwrap();
    clear_signatures(&mut tok);
    if tok.signature_count() != 0 { return TestResult::Fail; }
    if !tok.signed_by().is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_signature_material_produces_40_bytes() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 1, &[10]);
    let mat = signature_material(&tok, 10);
    if mat.len() != 40 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_signature_material_deterministic() -> TestResult {
    let tok = make_multisig_token(100, &[Capability::Admin, Capability::Debug], 1, &[10]);
    let mat1 = signature_material(&tok, 10);
    let mat2 = signature_material(&tok, 10);
    if mat1 != mat2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_signature_material_different_signers() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let mat1 = signature_material(&tok, 10);
    let mat2 = signature_material(&tok, 20);
    if mat1 == mat2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_compute_signature_produces_32_bytes() -> TestResult {
    let key = [0u8; 32];
    let material = [1u8; 40];
    let sig = multisig_compute_signature(&key, &material);
    if sig.len() != 32 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_compute_signature_deterministic() -> TestResult {
    let key = [1u8; 32];
    let material = [2u8; 40];
    let sig1 = multisig_compute_signature(&key, &material);
    let sig2 = multisig_compute_signature(&key, &material);
    if sig1 != sig2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_compute_signature_different_keys() -> TestResult {
    let material = [1u8; 40];
    let sig1 = multisig_compute_signature(&[0u8; 32], &material);
    let sig2 = multisig_compute_signature(&[1u8; 32], &material);
    if sig1 == sig2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_count_valid_signatures_empty() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let keys: alloc::vec::Vec<(&u64, &[u8; 32])> = alloc::vec![];
    if count_valid_signatures(&tok, &keys) != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_verify_multisig_threshold_not_met() -> TestResult {
    let tok = make_multisig_token(1, &[Capability::Admin], 2, &[10, 20]);
    let key10 = [1u8; 32];
    let keys: alloc::vec::Vec<(&u64, &[u8; 32])> = alloc::vec![(&10u64, &key10)];
    let result = verify_multisig(&tok, &keys);
    if result.is_err() { return TestResult::Fail; }
    if result.unwrap() { return TestResult::Fail; }
    TestResult::Pass
}
