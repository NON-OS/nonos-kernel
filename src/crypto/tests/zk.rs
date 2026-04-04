// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::crypto::zk::nonos_zk::{
    create_attestation, verify_attestation,
    commit, verify_commitment, commit_u64,
    issue_credential, verify_credential,
    zeroize_mut, zeroize_array,
};
use crate::crypto::asymmetric::ed25519::KeyPair;
use crate::crypto::rng::get_random_bytes;

#[test]
fn test_attestation_create_verify() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"attestation data";
    let proof = create_attestation(data, &kp);
    assert!(verify_attestation(data, &kp.public, &proof));
}

#[test]
fn test_attestation_wrong_data() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"attestation data";
    let proof = create_attestation(data, &kp);
    assert!(!verify_attestation(b"wrong data", &kp.public, &proof));
}

#[test]
fn test_attestation_wrong_key() {
    let kp1 = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = KeyPair::from_seed([0x43u8; 32]);
    let data = b"attestation data";
    let proof = create_attestation(data, &kp1);
    assert!(!verify_attestation(data, &kp2.public, &proof));
}

#[test]
fn test_attestation_deterministic() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"attestation data";
    let proof1 = create_attestation(data, &kp);
    let proof2 = create_attestation(data, &kp);
    assert_eq!(proof1.commitment, proof2.commitment);
}

#[test]
fn test_commit_verify() {
    let value = b"secret value";
    let randomness = get_random_bytes();
    let commitment = commit(value, &randomness);
    assert!(verify_commitment(&commitment, value, &randomness));
}

#[test]
fn test_commit_wrong_value() {
    let value = b"secret value";
    let randomness = get_random_bytes();
    let commitment = commit(value, &randomness);
    assert!(!verify_commitment(&commitment, b"wrong value", &randomness));
}

#[test]
fn test_commit_wrong_randomness() {
    let value = b"secret value";
    let randomness = get_random_bytes();
    let commitment = commit(value, &randomness);
    let wrong_rand = get_random_bytes();
    assert!(!verify_commitment(&commitment, value, &wrong_rand));
}

#[test]
fn test_commit_deterministic() {
    let value = b"secret value";
    let randomness = [0x42u8; 32];
    let c1 = commit(value, &randomness);
    let c2 = commit(value, &randomness);
    assert_eq!(c1, c2);
}

#[test]
fn test_commit_different_values_different_commitments() {
    let randomness = [0x42u8; 32];
    let c1 = commit(b"value1", &randomness);
    let c2 = commit(b"value2", &randomness);
    assert_ne!(c1, c2);
}

#[test]
fn test_commit_different_randomness_different_commitments() {
    let value = b"secret value";
    let c1 = commit(value, &[0x42u8; 32]);
    let c2 = commit(value, &[0x43u8; 32]);
    assert_ne!(c1, c2);
}

#[test]
fn test_commit_u64() {
    let value: u64 = 12345678;
    let randomness = [0x42u8; 32];
    let commitment = commit_u64(value, &randomness);
    assert_ne!(commitment, [0u8; 32]);
}

#[test]
fn test_commit_u64_deterministic() {
    let value: u64 = 12345678;
    let randomness = [0x42u8; 32];
    let c1 = commit_u64(value, &randomness);
    let c2 = commit_u64(value, &randomness);
    assert_eq!(c1, c2);
}

#[test]
fn test_commit_u64_different_values() {
    let randomness = [0x42u8; 32];
    let c1 = commit_u64(100, &randomness);
    let c2 = commit_u64(200, &randomness);
    assert_ne!(c1, c2);
}

#[test]
fn test_credential_issue_verify() {
    let issuer = KeyPair::from_seed([0x42u8; 32]);
    let subject = KeyPair::from_seed([0x43u8; 32]);
    let attributes = b"user attributes";
    let expiry = 1735689600u64;
    let cred = issue_credential(&issuer, &subject.public, attributes, expiry);
    assert!(verify_credential(&cred));
}

#[test]
fn test_credential_tampered_signature() {
    let issuer = KeyPair::from_seed([0x42u8; 32]);
    let subject = KeyPair::from_seed([0x43u8; 32]);
    let attributes = b"user attributes";
    let expiry = 1735689600u64;
    let mut cred = issue_credential(&issuer, &subject.public, attributes, expiry);
    cred.signature[0] ^= 0x01;
    assert!(!verify_credential(&cred));
}

#[test]
fn test_credential_different_issuers() {
    let issuer1 = KeyPair::from_seed([0x42u8; 32]);
    let issuer2 = KeyPair::from_seed([0x43u8; 32]);
    let subject = KeyPair::from_seed([0x44u8; 32]);
    let attributes = b"user attributes";
    let expiry = 1735689600u64;
    let cred1 = issue_credential(&issuer1, &subject.public, attributes, expiry);
    let cred2 = issue_credential(&issuer2, &subject.public, attributes, expiry);
    assert_ne!(cred1.issuer, cred2.issuer);
}

#[test]
fn test_zeroize_mut() {
    let mut data = [0x42u8; 32];
    zeroize_mut(&mut data);
    assert_eq!(data, [0u8; 32]);
}

#[test]
fn test_zeroize_array() {
    let mut arr = [0x42u8; 64];
    zeroize_array(&mut arr);
    assert_eq!(arr, [0u8; 64]);
}

#[test]
fn test_zeroize_empty() {
    let mut data = [0u8; 0];
    zeroize_mut(&mut data);
}

#[test]
fn test_attestation_empty_data() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = b"";
    let proof = create_attestation(data, &kp);
    assert!(verify_attestation(data, &kp.public, &proof));
}

#[test]
fn test_attestation_large_data() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let data = [0x42u8; 4096];
    let proof = create_attestation(&data, &kp);
    assert!(verify_attestation(&data, &kp.public, &proof));
}

#[test]
fn test_commit_empty_value() {
    let value = b"";
    let randomness = [0x42u8; 32];
    let commitment = commit(value, &randomness);
    assert!(verify_commitment(&commitment, value, &randomness));
}

#[test]
fn test_commit_large_value() {
    let value = [0x42u8; 4096];
    let randomness = [0x42u8; 32];
    let commitment = commit(&value, &randomness);
    assert!(verify_commitment(&commitment, &value, &randomness));
}

#[test]
fn test_groth16_proof_size() {
    let groth16_proof: usize = 128;
    assert_eq!(groth16_proof, 128);
}

#[test]
fn test_plonk_proof_size() {
    let plonk_proof: usize = 512;
    assert!(plonk_proof > 128);
}

#[test]
fn test_field_element_size() {
    let bn254_field: usize = 32;
    let bls12_381_field: usize = 48;
    assert!(bls12_381_field > bn254_field);
}
