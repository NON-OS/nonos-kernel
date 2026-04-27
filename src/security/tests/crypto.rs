// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Security crypto key types and usage tests

extern crate alloc;

use crate::security::crypto::{KeyType, KeyUsage};
use crate::test::framework::TestResult;
use alloc::format;

pub(crate) fn test_key_type_ed25519_signing() -> TestResult {
    let key_type = KeyType::Ed25519Signing;
    if key_type != KeyType::Ed25519Signing {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_ed25519_verify() -> TestResult {
    let key_type = KeyType::Ed25519Verify;
    if key_type != KeyType::Ed25519Verify {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_x25519_exchange() -> TestResult {
    let key_type = KeyType::X25519Exchange;
    if key_type != KeyType::X25519Exchange {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_aes256() -> TestResult {
    let key_type = KeyType::Aes256;
    if key_type != KeyType::Aes256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_chacha20() -> TestResult {
    let key_type = KeyType::ChaCha20;
    if key_type != KeyType::ChaCha20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_hmac() -> TestResult {
    let key_type = KeyType::Hmac;
    if key_type != KeyType::Hmac {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_master_key() -> TestResult {
    let key_type = KeyType::MasterKey;
    if key_type != KeyType::MasterKey {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_mlkem_encap() -> TestResult {
    let key_type = KeyType::MlKemEncap;
    if key_type != KeyType::MlKemEncap {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_mlkem_decap() -> TestResult {
    let key_type = KeyType::MlKemDecap;
    if key_type != KeyType::MlKemDecap {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_mldsa_sign() -> TestResult {
    let key_type = KeyType::MlDsaSign;
    if key_type != KeyType::MlDsaSign {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_mldsa_verify() -> TestResult {
    let key_type = KeyType::MlDsaVerify;
    if key_type != KeyType::MlDsaVerify {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_equality() -> TestResult {
    if KeyType::Ed25519Signing != KeyType::Ed25519Signing {
        return TestResult::Fail;
    }
    if KeyType::Ed25519Signing == KeyType::Ed25519Verify {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_clone() -> TestResult {
    let kt1 = KeyType::Aes256;
    let kt2 = kt1.clone();
    if kt1 != kt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_copy() -> TestResult {
    let kt1 = KeyType::ChaCha20;
    let kt2 = kt1;
    if kt1 != kt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_ed25519_signing() -> TestResult {
    if KeyType::Ed25519Signing.key_length() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_ed25519_verify() -> TestResult {
    if KeyType::Ed25519Verify.key_length() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_x25519() -> TestResult {
    if KeyType::X25519Exchange.key_length() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_aes256() -> TestResult {
    if KeyType::Aes256.key_length() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_chacha20() -> TestResult {
    if KeyType::ChaCha20.key_length() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_hmac() -> TestResult {
    if KeyType::Hmac.key_length() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_master_key() -> TestResult {
    if KeyType::MasterKey.key_length() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_mlkem_encap() -> TestResult {
    if KeyType::MlKemEncap.key_length() != 1184 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_mlkem_decap() -> TestResult {
    if KeyType::MlKemDecap.key_length() != 2400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_mldsa_sign() -> TestResult {
    if KeyType::MlDsaSign.key_length() != 4032 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_length_mldsa_verify() -> TestResult {
    if KeyType::MlDsaVerify.key_length() != 1952 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_signing() -> TestResult {
    let usage = KeyUsage::signing();
    if usage.encrypt {
        return TestResult::Fail;
    }
    if usage.decrypt {
        return TestResult::Fail;
    }
    if !usage.sign {
        return TestResult::Fail;
    }
    if usage.verify {
        return TestResult::Fail;
    }
    if usage.derive {
        return TestResult::Fail;
    }
    if usage.exportable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_verification() -> TestResult {
    let usage = KeyUsage::verification();
    if usage.encrypt {
        return TestResult::Fail;
    }
    if usage.decrypt {
        return TestResult::Fail;
    }
    if usage.sign {
        return TestResult::Fail;
    }
    if !usage.verify {
        return TestResult::Fail;
    }
    if usage.derive {
        return TestResult::Fail;
    }
    if !usage.exportable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_encryption() -> TestResult {
    let usage = KeyUsage::encryption();
    if !usage.encrypt {
        return TestResult::Fail;
    }
    if !usage.decrypt {
        return TestResult::Fail;
    }
    if usage.sign {
        return TestResult::Fail;
    }
    if usage.verify {
        return TestResult::Fail;
    }
    if usage.derive {
        return TestResult::Fail;
    }
    if usage.exportable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_key_exchange() -> TestResult {
    let usage = KeyUsage::key_exchange();
    if usage.encrypt {
        return TestResult::Fail;
    }
    if usage.decrypt {
        return TestResult::Fail;
    }
    if usage.sign {
        return TestResult::Fail;
    }
    if usage.verify {
        return TestResult::Fail;
    }
    if !usage.derive {
        return TestResult::Fail;
    }
    if usage.exportable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_master() -> TestResult {
    let usage = KeyUsage::master();
    if usage.encrypt {
        return TestResult::Fail;
    }
    if usage.decrypt {
        return TestResult::Fail;
    }
    if usage.sign {
        return TestResult::Fail;
    }
    if usage.verify {
        return TestResult::Fail;
    }
    if !usage.derive {
        return TestResult::Fail;
    }
    if usage.exportable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_clone() -> TestResult {
    let usage1 = KeyUsage::signing();
    let usage2 = usage1.clone();
    if usage1 != usage2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_copy() -> TestResult {
    let usage1 = KeyUsage::encryption();
    let usage2 = usage1;
    if usage1 != usage2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_equality() -> TestResult {
    if KeyUsage::signing() != KeyUsage::signing() {
        return TestResult::Fail;
    }
    if KeyUsage::signing() == KeyUsage::verification() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_custom() -> TestResult {
    let usage = KeyUsage {
        encrypt: true,
        decrypt: true,
        sign: true,
        verify: true,
        derive: true,
        exportable: true,
    };
    if !usage.encrypt {
        return TestResult::Fail;
    }
    if !usage.decrypt {
        return TestResult::Fail;
    }
    if !usage.sign {
        return TestResult::Fail;
    }
    if !usage.verify {
        return TestResult::Fail;
    }
    if !usage.derive {
        return TestResult::Fail;
    }
    if !usage.exportable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_all_false() -> TestResult {
    let usage = KeyUsage {
        encrypt: false,
        decrypt: false,
        sign: false,
        verify: false,
        derive: false,
        exportable: false,
    };
    if usage.encrypt {
        return TestResult::Fail;
    }
    if usage.decrypt {
        return TestResult::Fail;
    }
    if usage.sign {
        return TestResult::Fail;
    }
    if usage.verify {
        return TestResult::Fail;
    }
    if usage.derive {
        return TestResult::Fail;
    }
    if usage.exportable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_debug() -> TestResult {
    let kt = KeyType::Aes256;
    let debug_str = format!("{:?}", kt);
    if !debug_str.contains("Aes256") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_debug() -> TestResult {
    let usage = KeyUsage::signing();
    let debug_str = format!("{:?}", usage);
    if !debug_str.contains("sign") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_all_variants() -> TestResult {
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
    if types.len() != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_type_all_unique() -> TestResult {
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
            if types[i] == types[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_pqc_key_lengths_larger() -> TestResult {
    if KeyType::MlKemEncap.key_length() <= KeyType::Ed25519Signing.key_length() {
        return TestResult::Fail;
    }
    if KeyType::MlKemDecap.key_length() <= KeyType::Ed25519Signing.key_length() {
        return TestResult::Fail;
    }
    if KeyType::MlDsaSign.key_length() <= KeyType::Ed25519Signing.key_length() {
        return TestResult::Fail;
    }
    if KeyType::MlDsaVerify.key_length() <= KeyType::Ed25519Signing.key_length() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_symmetric_key_lengths_equal() -> TestResult {
    if KeyType::Aes256.key_length() != KeyType::ChaCha20.key_length() {
        return TestResult::Fail;
    }
    if KeyType::Aes256.key_length() != KeyType::Hmac.key_length() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_usage_preset_functions_const() -> TestResult {
    const _SIGNING: KeyUsage = KeyUsage::signing();
    const _VERIFICATION: KeyUsage = KeyUsage::verification();
    const _ENCRYPTION: KeyUsage = KeyUsage::encryption();
    const _KEY_EXCHANGE: KeyUsage = KeyUsage::key_exchange();
    const _MASTER: KeyUsage = KeyUsage::master();
    TestResult::Pass
}
