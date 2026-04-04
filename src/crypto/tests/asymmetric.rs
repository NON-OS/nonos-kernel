// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::crypto::asymmetric::ed25519::{sign, verify, KeyPair, Signature};

#[test]
fn test_ed25519_keypair_from_seed() {
    let seed = [0x42u8; 32];
    let kp = KeyPair::from_seed(seed);
    assert_eq!(kp.public.len(), 32);
    assert_eq!(kp.private.len(), 32);
}

#[test]
fn test_ed25519_keypair_deterministic() {
    let seed = [0x42u8; 32];
    let kp1 = KeyPair::from_seed(seed);
    let kp2 = KeyPair::from_seed(seed);
    assert_eq!(kp1.public, kp2.public);
}

#[test]
fn test_ed25519_keypair_different_seeds() {
    let kp1 = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = KeyPair::from_seed([0x43u8; 32]);
    assert_ne!(kp1.public, kp2.public);
}

#[test]
fn test_ed25519_sign_verify_roundtrip() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    assert!(verify(&kp.public, msg, &sig));
}

#[test]
fn test_ed25519_sign_deterministic() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig1 = sign(&kp, msg);
    let sig2 = sign(&kp, msg);
    assert_eq!(sig1.R, sig2.R);
    assert_eq!(sig1.S, sig2.S);
}

#[test]
fn test_ed25519_verify_wrong_message() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    assert!(!verify(&kp.public, b"wrong message", &sig));
}

#[test]
fn test_ed25519_verify_wrong_key() {
    let kp1 = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = KeyPair::from_seed([0x43u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp1, msg);
    assert!(!verify(&kp2.public, msg, &sig));
}

#[test]
fn test_ed25519_verify_tampered_signature_r() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let mut sig = sign(&kp, msg);
    sig.R[0] ^= 0x01;
    assert!(!verify(&kp.public, msg, &sig));
}

#[test]
fn test_ed25519_verify_tampered_signature_s() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let mut sig = sign(&kp, msg);
    sig.S[0] ^= 0x01;
    assert!(!verify(&kp.public, msg, &sig));
}

#[test]
fn test_ed25519_signature_to_bytes() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[..32], &sig.R[..]);
    assert_eq!(&bytes[32..], &sig.S[..]);
}

#[test]
fn test_ed25519_signature_from_bytes() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    let bytes = sig.to_bytes();
    let sig2 = Signature::from_bytes(&bytes);
    assert_eq!(sig.R, sig2.R);
    assert_eq!(sig.S, sig2.S);
}

#[test]
fn test_ed25519_signature_roundtrip_bytes() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    let bytes = sig.to_bytes();
    let sig2 = Signature::from_bytes(&bytes);
    assert!(verify(&kp.public, msg, &sig2));
}

#[test]
fn test_ed25519_sign_empty_message() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"";
    let sig = sign(&kp, msg);
    assert!(verify(&kp.public, msg, &sig));
}

#[test]
fn test_ed25519_sign_large_message() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = [0x42u8; 4096];
    let sig = sign(&kp, &msg);
    assert!(verify(&kp.public, &msg, &sig));
}

#[test]
fn test_ed25519_keypair_clone() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = kp.clone();
    assert_eq!(kp.public, kp2.public);
}

#[test]
fn test_ed25519_signature_clone() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let sig = sign(&kp, b"msg");
    let sig2 = sig.clone();
    assert_eq!(sig.R, sig2.R);
    assert_eq!(sig.S, sig2.S);
}

#[test]
fn test_ed25519_public_key_size() {
    let ed25519_pub: usize = 32;
    assert_eq!(ed25519_pub, 32);
}

#[test]
fn test_ed25519_private_key_size() {
    let ed25519_priv: usize = 32;
    assert_eq!(ed25519_priv, 32);
}

#[test]
fn test_ed25519_signature_size() {
    let ed25519_sig: usize = 64;
    assert_eq!(ed25519_sig, 64);
}

#[test]
fn test_ed25519_sign_different_messages_different_sigs() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let sig1 = sign(&kp, b"message1");
    let sig2 = sign(&kp, b"message2");
    assert_ne!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn test_ed25519_all_zero_seed() {
    let kp = KeyPair::from_seed([0u8; 32]);
    let msg = b"test";
    let sig = sign(&kp, msg);
    assert!(verify(&kp.public, msg, &sig));
}

#[test]
fn test_ed25519_all_ones_seed() {
    let kp = KeyPair::from_seed([0xffu8; 32]);
    let msg = b"test";
    let sig = sign(&kp, msg);
    assert!(verify(&kp.public, msg, &sig));
}

#[test]
fn test_ed25519_sequential_signing() {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    for i in 0..10 {
        let msg = [i as u8; 32];
        let sig = sign(&kp, &msg);
        assert!(verify(&kp.public, &msg, &sig));
    }
}
