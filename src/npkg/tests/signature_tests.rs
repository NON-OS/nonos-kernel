use crate::npkg::signature::{
    add_trusted_key, get_trusted_key, list_trusted_keys, remove_trusted_key, PackageSignature,
    VerifyingKey, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE,
};
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_signature_size_constant() -> TestResult {
    if SIGNATURE_SIZE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_public_key_size_constant() -> TestResult {
    if PUBLIC_KEY_SIZE != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secret_key_size_constant() -> TestResult {
    if SECRET_KEY_SIZE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_signature_from_bytes_valid() -> TestResult {
    let mut data = [0u8; SIGNATURE_SIZE + 8 + 8];
    for i in 0..SIGNATURE_SIZE {
        data[i] = i as u8;
    }
    data[SIGNATURE_SIZE..SIGNATURE_SIZE + 8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    data[SIGNATURE_SIZE + 8..].copy_from_slice(&100u64.to_le_bytes());

    let sig = PackageSignature::from_bytes(&data);
    if sig.is_none() {
        return TestResult::Fail;
    }
    let sig = sig.unwrap();
    if sig.bytes[0] != 0 {
        return TestResult::Fail;
    }
    if sig.key_id[0] != 1 {
        return TestResult::Fail;
    }
    if sig.timestamp != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_signature_from_bytes_too_short() -> TestResult {
    let data = [0u8; 10];
    let sig = PackageSignature::from_bytes(&data);
    if sig.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_signature_from_bytes_exact_minimum() -> TestResult {
    let data = [0u8; SIGNATURE_SIZE + 8 + 8];
    let sig = PackageSignature::from_bytes(&data);
    if sig.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_signature_to_bytes() -> TestResult {
    let sig = PackageSignature {
        bytes: [42u8; SIGNATURE_SIZE],
        key_id: [1, 2, 3, 4, 5, 6, 7, 8],
        timestamp: 12345,
    };
    let bytes = sig.to_bytes();
    if bytes.len() != SIGNATURE_SIZE + 8 + 8 {
        return TestResult::Fail;
    }
    if bytes[0] != 42 {
        return TestResult::Fail;
    }
    if bytes[SIGNATURE_SIZE] != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_signature_roundtrip() -> TestResult {
    let original = PackageSignature {
        bytes: [0xAB; SIGNATURE_SIZE],
        key_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        timestamp: 9999999,
    };
    let bytes = original.to_bytes();
    let restored = PackageSignature::from_bytes(&bytes).unwrap();
    if original.bytes != restored.bytes {
        return TestResult::Fail;
    }
    if original.key_id != restored.key_id {
        return TestResult::Fail;
    }
    if original.timestamp != restored.timestamp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_signature_clone() -> TestResult {
    let sig = PackageSignature { bytes: [1u8; SIGNATURE_SIZE], key_id: [2u8; 8], timestamp: 500 };
    let cloned = sig.clone();
    if sig.bytes != cloned.bytes {
        return TestResult::Fail;
    }
    if sig.key_id != cloned.key_id {
        return TestResult::Fail;
    }
    if sig.timestamp != cloned.timestamp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_signature_debug_format() -> TestResult {
    let sig = PackageSignature { bytes: [0u8; SIGNATURE_SIZE], key_id: [0u8; 8], timestamp: 0 };
    let debug_str = alloc::format!("{:?}", sig);
    if !debug_str.contains("PackageSignature") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_from_bytes_valid() -> TestResult {
    let data = [0x55u8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data);
    if key.is_none() {
        return TestResult::Fail;
    }
    let key = key.unwrap();
    if key.bytes[0] != 0x55 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_from_bytes_too_short() -> TestResult {
    let data = [0u8; 16];
    let key = VerifyingKey::from_bytes(&data);
    if key.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_from_bytes_too_long() -> TestResult {
    let data = [0u8; 64];
    let key = VerifyingKey::from_bytes(&data);
    if key.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_key_id() -> TestResult {
    let data = [0xAAu8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data).unwrap();
    let id = key.key_id();
    if id.len() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_clone() -> TestResult {
    let data = [0x33u8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data).unwrap();
    let cloned = key.clone();
    if key.bytes != cloned.bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_debug_format() -> TestResult {
    let data = [0u8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data).unwrap();
    let debug_str = alloc::format!("{:?}", key);
    if !debug_str.contains("VerifyingKey") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_generate_signing_keypair() -> TestResult {
    let (signing, verifying) = generate_signing_keypair();
    if verifying.bytes.len() != PUBLIC_KEY_SIZE {
        return TestResult::Fail;
    }
    let id1 = signing.key_id();
    let id2 = verifying.key_id();
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_signing_key_public_key() -> TestResult {
    let (signing, verifying) = generate_signing_keypair();
    let pub_from_signing = signing.public_key();
    if pub_from_signing.bytes != verifying.bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sign_package() -> TestResult {
    let (signing, _verifying) = generate_signing_keypair();
    let data = b"test package data";
    let sig = sign_package(data, &signing);
    if sig.bytes.len() != SIGNATURE_SIZE {
        return TestResult::Fail;
    }
    if sig.key_id != signing.key_id() {
        return TestResult::Fail;
    }
    if sig.timestamp <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_checksum() -> TestResult {
    use crate::npkg::signature::compute_checksum;
    let data = b"hello world";
    let checksum = compute_checksum(data);
    if checksum.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_checksum_deterministic() -> TestResult {
    use crate::npkg::signature::compute_checksum;
    let data = b"same data";
    let checksum1 = compute_checksum(data);
    let checksum2 = compute_checksum(data);
    if checksum1 != checksum2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_checksum_different_data() -> TestResult {
    use crate::npkg::signature::compute_checksum;
    let checksum1 = compute_checksum(b"data1");
    let checksum2 = compute_checksum(b"data2");
    if checksum1 == checksum2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_checksum_valid() -> TestResult {
    use crate::npkg::download::verify_checksum;
    use crate::npkg::signature::compute_checksum;
    let data = b"test data for checksum";
    let checksum = compute_checksum(data);
    if !verify_checksum(data, &checksum) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_checksum_invalid() -> TestResult {
    use crate::npkg::download::verify_checksum;
    let data = b"test data";
    let wrong_checksum = [0u8; 32];
    if verify_checksum(data, &wrong_checksum) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_checksum_empty_data() -> TestResult {
    use crate::npkg::download::verify_checksum;
    use crate::npkg::signature::compute_checksum;
    let data = b"";
    let checksum = compute_checksum(data);
    if !verify_checksum(data, &checksum) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_trusted_keys() -> TestResult {
    let keys = list_trusted_keys();
    let _ = keys.len();
    TestResult::Pass
}

pub(crate) fn test_add_trusted_key() -> TestResult {
    let (_, verifying) = generate_signing_keypair();
    add_trusted_key(verifying.clone());
    let key_id = verifying.key_id();
    let found = get_trusted_key(&key_id);
    if found.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_add_trusted_key_duplicate() -> TestResult {
    let (_, verifying) = generate_signing_keypair();
    let initial_count = list_trusted_keys().len();
    add_trusted_key(verifying.clone());
    add_trusted_key(verifying.clone());
    let new_count = list_trusted_keys().len();
    if new_count > initial_count + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_trusted_key() -> TestResult {
    let (_, verifying) = generate_signing_keypair();
    add_trusted_key(verifying.clone());
    let key_id = verifying.key_id();
    remove_trusted_key(&key_id);
    let found = get_trusted_key(&key_id);
    if found.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_trusted_key_not_found() -> TestResult {
    let fake_id = [0xFF; 8];
    let found = get_trusted_key(&fake_id);
    if found.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
