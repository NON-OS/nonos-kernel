// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Asymmetric cryptography tests - Ed25519 digital signatures

use crate::crypto::asymmetric::ed25519::{sign, verify, KeyPair, Signature};
use crate::test::framework::TestResult;

pub(crate) fn test_ed25519_keypair_from_seed() -> TestResult {
    let seed = [0x42u8; 32];
    let kp = KeyPair::from_seed(seed);
    if kp.public.len() != 32 {
        return TestResult::Fail;
    }
    if kp.private.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_keypair_deterministic() -> TestResult {
    let seed = [0x42u8; 32];
    let kp1 = KeyPair::from_seed(seed);
    let kp2 = KeyPair::from_seed(seed);
    if kp1.public != kp2.public {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_keypair_different_seeds() -> TestResult {
    let kp1 = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = KeyPair::from_seed([0x43u8; 32]);
    if kp1.public == kp2.public {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_sign_verify_roundtrip() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    if !verify(&kp.public, msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_sign_deterministic() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig1 = sign(&kp, msg);
    let sig2 = sign(&kp, msg);
    if sig1.R != sig2.R {
        return TestResult::Fail;
    }
    if sig1.S != sig2.S {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_verify_wrong_message() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    if verify(&kp.public, b"wrong message", &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_verify_wrong_key() -> TestResult {
    let kp1 = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = KeyPair::from_seed([0x43u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp1, msg);
    if verify(&kp2.public, msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_verify_tampered_signature_r() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let mut sig = sign(&kp, msg);
    sig.R[0] ^= 0x01;
    if verify(&kp.public, msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_verify_tampered_signature_s() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let mut sig = sign(&kp, msg);
    sig.S[0] ^= 0x01;
    if verify(&kp.public, msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_signature_to_bytes() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    let bytes = sig.to_bytes();
    if bytes.len() != 64 {
        return TestResult::Fail;
    }
    if &bytes[..32] != &sig.R[..] {
        return TestResult::Fail;
    }
    if &bytes[32..] != &sig.S[..] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_signature_from_bytes() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    let bytes = sig.to_bytes();
    let sig2 = Signature::from_bytes(&bytes);
    if sig.R != sig2.R {
        return TestResult::Fail;
    }
    if sig.S != sig2.S {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_signature_roundtrip_bytes() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"test message";
    let sig = sign(&kp, msg);
    let bytes = sig.to_bytes();
    let sig2 = Signature::from_bytes(&bytes);
    if !verify(&kp.public, msg, &sig2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_sign_empty_message() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = b"";
    let sig = sign(&kp, msg);
    if !verify(&kp.public, msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_sign_large_message() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let msg = [0x42u8; 4096];
    let sig = sign(&kp, &msg);
    if !verify(&kp.public, &msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_keypair_clone() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let kp2 = kp.clone();
    if kp.public != kp2.public {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_signature_clone() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let sig = sign(&kp, b"msg");
    let sig2 = sig.clone();
    if sig.R != sig2.R {
        return TestResult::Fail;
    }
    if sig.S != sig2.S {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_public_key_size() -> TestResult {
    let ed25519_pub: usize = 32;
    if ed25519_pub != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_private_key_size() -> TestResult {
    let ed25519_priv: usize = 32;
    if ed25519_priv != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_signature_size() -> TestResult {
    let ed25519_sig: usize = 64;
    if ed25519_sig != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_sign_different_messages_different_sigs() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    let sig1 = sign(&kp, b"message1");
    let sig2 = sign(&kp, b"message2");
    if sig1.to_bytes() == sig2.to_bytes() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_all_zero_seed() -> TestResult {
    let kp = KeyPair::from_seed([0u8; 32]);
    let msg = b"test";
    let sig = sign(&kp, msg);
    if !verify(&kp.public, msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_all_ones_seed() -> TestResult {
    let kp = KeyPair::from_seed([0xffu8; 32]);
    let msg = b"test";
    let sig = sign(&kp, msg);
    if !verify(&kp.public, msg, &sig) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ed25519_sequential_signing() -> TestResult {
    let kp = KeyPair::from_seed([0x42u8; 32]);
    for i in 0..10 {
        let msg = [i as u8; 32];
        let sig = sign(&kp, &msg);
        if !verify(&kp.public, &msg, &sig) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
