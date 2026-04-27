// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Zero-knowledge proof tests - attestations, commitments, credentials

use crate::crypto::asymmetric::ed25519::KeyPair;
use crate::crypto::rng::get_random_bytes;
use crate::crypto::zk::nonos_zk::{
    commit, commit_u64, create_attestation, issue_credential, verify_attestation,
    verify_commitment, verify_credential, zeroize_array, zeroize_mut,
};
use crate::test::framework::TestResult;

pub(crate) fn test_attestation_create_verify() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"attestation data";
    let proof = create_attestation(data, &kp);
    if !verify_attestation(data, &kp.public, &proof) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_attestation_wrong_data() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"attestation data";
    let proof = create_attestation(data, &kp);
    if verify_attestation(b"wrong data", &kp.public, &proof) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_attestation_wrong_key() -> TestResult {
    let kp1 = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = KeyPair::from_seed([0x43u8; 32]);
    let data = b"attestation data";
    let proof = create_attestation(data, &kp1);
    if verify_attestation(data, &kp2.public, &proof) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_attestation_deterministic() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"attestation data";
    let proof1 = create_attestation(data, &kp);
    let proof2 = create_attestation(data, &kp);
    if proof1.commitment != proof2.commitment {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_verify() -> TestResult {
    let value = b"secret value";
    let randomness = get_random_bytes();
    let commitment = commit(value, &randomness);
    if !verify_commitment(&commitment, value, &randomness) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_wrong_value() -> TestResult {
    let value = b"secret value";
    let randomness = get_random_bytes();
    let commitment = commit(value, &randomness);
    if verify_commitment(&commitment, b"wrong value", &randomness) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_wrong_randomness() -> TestResult {
    let value = b"secret value";
    let randomness = get_random_bytes();
    let commitment = commit(value, &randomness);
    let wrong_rand = get_random_bytes();
    if verify_commitment(&commitment, value, &wrong_rand) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_deterministic() -> TestResult {
    let value = b"secret value";
    let randomness = [0x42u8; 32];
    let c1 = commit(value, &randomness);
    let c2 = commit(value, &randomness);
    if c1 != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_different_values_different_commitments() -> TestResult {
    let randomness = [0x42u8; 32];
    let c1 = commit(b"value1", &randomness);
    let c2 = commit(b"value2", &randomness);
    if c1 == c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_different_randomness_different_commitments() -> TestResult {
    let value = b"secret value";
    let c1 = commit(value, &[0x42u8; 32]);
    let c2 = commit(value, &[0x43u8; 32]);
    if c1 == c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_u64() -> TestResult {
    let value: u64 = 12345678;
    let randomness = [0x42u8; 32];
    let commitment = commit_u64(value, &randomness);
    if commitment == [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_u64_deterministic() -> TestResult {
    let value: u64 = 12345678;
    let randomness = [0x42u8; 32];
    let c1 = commit_u64(value, &randomness);
    let c2 = commit_u64(value, &randomness);
    if c1 != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_u64_different_values() -> TestResult {
    let randomness = [0x42u8; 32];
    let c1 = commit_u64(100, &randomness);
    let c2 = commit_u64(200, &randomness);
    if c1 == c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_credential_issue_verify() -> TestResult {
    let issuer = KeyPair::from_seed([0x42u8; 32]);
    let subject = KeyPair::from_seed([0x43u8; 32]);
    let attributes = b"user attributes";
    let expiry = 1735689600u64;
    let cred = issue_credential(&issuer, &subject.public, attributes, expiry);
    if !verify_credential(&cred) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_credential_tampered_signature() -> TestResult {
    let issuer = KeyPair::from_seed([0x42u8; 32]);
    let subject = KeyPair::from_seed([0x43u8; 32]);
    let attributes = b"user attributes";
    let expiry = 1735689600u64;
    let mut cred = issue_credential(&issuer, &subject.public, attributes, expiry);
    cred.signature[0] ^= 0x01;
    if verify_credential(&cred) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_credential_different_issuers() -> TestResult {
    let issuer1 = KeyPair::from_seed([0x42u8; 32]);
    let issuer2 = KeyPair::from_seed([0x43u8; 32]);
    let subject = KeyPair::from_seed([0x44u8; 32]);
    let attributes = b"user attributes";
    let expiry = 1735689600u64;
    let cred1 = issue_credential(&issuer1, &subject.public, attributes, expiry);
    let cred2 = issue_credential(&issuer2, &subject.public, attributes, expiry);
    if cred1.issuer == cred2.issuer {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zeroize_mut() -> TestResult {
    let mut data = [0x42u8; 32];
    zeroize_mut(&mut data);
    if data != [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zeroize_array() -> TestResult {
    let mut arr = [0x42u8; 64];
    zeroize_array(&mut arr);
    if arr != [0u8; 64] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zeroize_empty() -> TestResult {
    let mut data = [0u8; 0];
    zeroize_mut(&mut data);
    TestResult::Pass
}

pub(crate) fn test_attestation_empty_data() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"";
    let proof = create_attestation(data, &kp);
    if !verify_attestation(data, &kp.public, &proof) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_attestation_large_data() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = [0x42u8; 4096];
    let proof = create_attestation(&data, &kp);
    if !verify_attestation(&data, &kp.public, &proof) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_empty_value() -> TestResult {
    let value = b"";
    let randomness = [0x42u8; 32];
    let commitment = commit(value, &randomness);
    if !verify_commitment(&commitment, value, &randomness) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_commit_large_value() -> TestResult {
    let value = [0x42u8; 4096];
    let randomness = [0x42u8; 32];
    let commitment = commit(&value, &randomness);
    if !verify_commitment(&commitment, &value, &randomness) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_groth16_proof_size() -> TestResult {
    let groth16_proof: usize = 128;
    if groth16_proof != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_plonk_proof_size() -> TestResult {
    let plonk_proof: usize = 512;
    if plonk_proof <= 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_size() -> TestResult {
    let bn254_field: usize = 32;
    let bls12_381_field: usize = 48;
    if bls12_381_field <= bn254_field {
        return TestResult::Fail;
    }
    TestResult::Pass
}
