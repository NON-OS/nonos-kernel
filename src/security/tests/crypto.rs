// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::security::crypto::{KeyType, KeyUsage};

#[test]
fn test_key_type_ed25519_signing() {
    let key_type = KeyType::Ed25519Signing;
    assert_eq!(key_type, KeyType::Ed25519Signing);
}

#[test]
fn test_key_type_ed25519_verify() {
    let key_type = KeyType::Ed25519Verify;
    assert_eq!(key_type, KeyType::Ed25519Verify);
}

#[test]
fn test_key_type_x25519_exchange() {
    let key_type = KeyType::X25519Exchange;
    assert_eq!(key_type, KeyType::X25519Exchange);
}

#[test]
fn test_key_type_aes256() {
    let key_type = KeyType::Aes256;
    assert_eq!(key_type, KeyType::Aes256);
}

#[test]
fn test_key_type_chacha20() {
    let key_type = KeyType::ChaCha20;
    assert_eq!(key_type, KeyType::ChaCha20);
}

#[test]
fn test_key_type_hmac() {
    let key_type = KeyType::Hmac;
    assert_eq!(key_type, KeyType::Hmac);
}

#[test]
fn test_key_type_master_key() {
    let key_type = KeyType::MasterKey;
    assert_eq!(key_type, KeyType::MasterKey);
}

#[test]
fn test_key_type_mlkem_encap() {
    let key_type = KeyType::MlKemEncap;
    assert_eq!(key_type, KeyType::MlKemEncap);
}

#[test]
fn test_key_type_mlkem_decap() {
    let key_type = KeyType::MlKemDecap;
    assert_eq!(key_type, KeyType::MlKemDecap);
}

#[test]
fn test_key_type_mldsa_sign() {
    let key_type = KeyType::MlDsaSign;
    assert_eq!(key_type, KeyType::MlDsaSign);
}

#[test]
fn test_key_type_mldsa_verify() {
    let key_type = KeyType::MlDsaVerify;
    assert_eq!(key_type, KeyType::MlDsaVerify);
}

#[test]
fn test_key_type_equality() {
    assert_eq!(KeyType::Ed25519Signing, KeyType::Ed25519Signing);
    assert_ne!(KeyType::Ed25519Signing, KeyType::Ed25519Verify);
}

#[test]
fn test_key_type_clone() {
    let kt1 = KeyType::Aes256;
    let kt2 = kt1.clone();
    assert_eq!(kt1, kt2);
}

#[test]
fn test_key_type_copy() {
    let kt1 = KeyType::ChaCha20;
    let kt2 = kt1;
    assert_eq!(kt1, kt2);
}

#[test]
fn test_key_length_ed25519_signing() {
    assert_eq!(KeyType::Ed25519Signing.key_length(), 32);
}

#[test]
fn test_key_length_ed25519_verify() {
    assert_eq!(KeyType::Ed25519Verify.key_length(), 32);
}

#[test]
fn test_key_length_x25519() {
    assert_eq!(KeyType::X25519Exchange.key_length(), 32);
}

#[test]
fn test_key_length_aes256() {
    assert_eq!(KeyType::Aes256.key_length(), 32);
}

#[test]
fn test_key_length_chacha20() {
    assert_eq!(KeyType::ChaCha20.key_length(), 32);
}

#[test]
fn test_key_length_hmac() {
    assert_eq!(KeyType::Hmac.key_length(), 32);
}

#[test]
fn test_key_length_master_key() {
    assert_eq!(KeyType::MasterKey.key_length(), 32);
}

#[test]
fn test_key_length_mlkem_encap() {
    assert_eq!(KeyType::MlKemEncap.key_length(), 1184);
}

#[test]
fn test_key_length_mlkem_decap() {
    assert_eq!(KeyType::MlKemDecap.key_length(), 2400);
}

#[test]
fn test_key_length_mldsa_sign() {
    assert_eq!(KeyType::MlDsaSign.key_length(), 4032);
}

#[test]
fn test_key_length_mldsa_verify() {
    assert_eq!(KeyType::MlDsaVerify.key_length(), 1952);
}

#[test]
fn test_key_usage_signing() {
    let usage = KeyUsage::signing();
    assert!(!usage.encrypt);
    assert!(!usage.decrypt);
    assert!(usage.sign);
    assert!(!usage.verify);
    assert!(!usage.derive);
    assert!(!usage.exportable);
}

#[test]
fn test_key_usage_verification() {
    let usage = KeyUsage::verification();
    assert!(!usage.encrypt);
    assert!(!usage.decrypt);
    assert!(!usage.sign);
    assert!(usage.verify);
    assert!(!usage.derive);
    assert!(usage.exportable);
}

#[test]
fn test_key_usage_encryption() {
    let usage = KeyUsage::encryption();
    assert!(usage.encrypt);
    assert!(usage.decrypt);
    assert!(!usage.sign);
    assert!(!usage.verify);
    assert!(!usage.derive);
    assert!(!usage.exportable);
}

#[test]
fn test_key_usage_key_exchange() {
    let usage = KeyUsage::key_exchange();
    assert!(!usage.encrypt);
    assert!(!usage.decrypt);
    assert!(!usage.sign);
    assert!(!usage.verify);
    assert!(usage.derive);
    assert!(!usage.exportable);
}

#[test]
fn test_key_usage_master() {
    let usage = KeyUsage::master();
    assert!(!usage.encrypt);
    assert!(!usage.decrypt);
    assert!(!usage.sign);
    assert!(!usage.verify);
    assert!(usage.derive);
    assert!(!usage.exportable);
}

#[test]
fn test_key_usage_clone() {
    let usage1 = KeyUsage::signing();
    let usage2 = usage1.clone();
    assert_eq!(usage1, usage2);
}

#[test]
fn test_key_usage_copy() {
    let usage1 = KeyUsage::encryption();
    let usage2 = usage1;
    assert_eq!(usage1, usage2);
}

#[test]
fn test_key_usage_equality() {
    assert_eq!(KeyUsage::signing(), KeyUsage::signing());
    assert_ne!(KeyUsage::signing(), KeyUsage::verification());
}

#[test]
fn test_key_usage_custom() {
    let usage = KeyUsage {
        encrypt: true,
        decrypt: true,
        sign: true,
        verify: true,
        derive: true,
        exportable: true,
    };
    assert!(usage.encrypt);
    assert!(usage.decrypt);
    assert!(usage.sign);
    assert!(usage.verify);
    assert!(usage.derive);
    assert!(usage.exportable);
}

#[test]
fn test_key_usage_all_false() {
    let usage = KeyUsage {
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        exportable: false,
    };
    assert!(!usage.encrypt);
    assert!(!usage.decrypt);
    assert!(!usage.sign);
    assert!(!usage.verify);
    assert!(!usage.derive);
    assert!(!usage.exportable);
}

#[test]
fn test_key_type_debug() {
    let kt = KeyType::Aes256;
    let debug_str = alloc::format!("{:?}", kt);
    assert!(debug_str.contains("Aes256"));
}

#[test]
fn test_key_usage_debug() {
    let usage = KeyUsage::signing();
    let debug_str = alloc::format!("{:?}", usage);
    assert!(debug_str.contains("sign"));
}

#[test]
fn test_key_type_all_variants() {
    let types = [
        KeyType::Ed25519Signing,
        KeyType::Ed25519Verify,
        KeyType::X25519Exchange,
        KeyType::Aes256,
        KeyType::ChaCha20,
        KeyType::Hmac,
        KeyType::MasterKey,
        KeyType::MlKemEncap,
        KeyType::MlKemDecap,
        KeyType::MlDsaSign,
        KeyType::MlDsaVerify,
    ];
    assert_eq!(types.len(), 11);
}

#[test]
fn test_key_type_all_unique() {
    let types = [
        KeyType::Ed25519Signing,
        KeyType::Ed25519Verify,
        KeyType::X25519Exchange,
        KeyType::Aes256,
        KeyType::ChaCha20,
        KeyType::Hmac,
        KeyType::MasterKey,
        KeyType::MlKemEncap,
        KeyType::MlKemDecap,
        KeyType::MlDsaSign,
        KeyType::MlDsaVerify,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn test_pqc_key_lengths_larger() {
    assert!(KeyType::MlKemEncap.key_length() > KeyType::Ed25519Signing.key_length());
    assert!(KeyType::MlKemDecap.key_length() > KeyType::Ed25519Signing.key_length());
    assert!(KeyType::MlDsaSign.key_length() > KeyType::Ed25519Signing.key_length());
    assert!(KeyType::MlDsaVerify.key_length() > KeyType::Ed25519Signing.key_length());
}

#[test]
fn test_symmetric_key_lengths_equal() {
    assert_eq!(KeyType::Aes256.key_length(), KeyType::ChaCha20.key_length());
    assert_eq!(KeyType::Aes256.key_length(), KeyType::Hmac.key_length());
}

#[test]
fn test_key_usage_preset_functions_const() {
    const _SIGNING: KeyUsage = KeyUsage::signing();
    const _VERIFICATION: KeyUsage = KeyUsage::verification();
    const _ENCRYPTION: KeyUsage = KeyUsage::encryption();
    const _KEY_EXCHANGE: KeyUsage = KeyUsage::key_exchange();
    const _MASTER: KeyUsage = KeyUsage::master();
}

