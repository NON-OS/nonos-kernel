use crate::npkg::*;
use crate::npkg::signature::{
    PackageSignature, VerifyingKey, SIGNATURE_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE,
    list_trusted_keys, add_trusted_key, get_trusted_key, remove_trusted_key,
};

#[test]
fn test_signature_size_constant() {
    assert_eq!(SIGNATURE_SIZE, 64);
}

#[test]
fn test_public_key_size_constant() {
    assert_eq!(PUBLIC_KEY_SIZE, 32);
}

#[test]
fn test_secret_key_size_constant() {
    assert_eq!(SECRET_KEY_SIZE, 64);
}

#[test]
fn test_package_signature_from_bytes_valid() {
    let mut data = [0u8; SIGNATURE_SIZE + 8 + 8];
    for i in 0..SIGNATURE_SIZE {
        data[i] = i as u8;
    }
    data[SIGNATURE_SIZE..SIGNATURE_SIZE + 8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    data[SIGNATURE_SIZE + 8..].copy_from_slice(&100u64.to_le_bytes());

    let sig = PackageSignature::from_bytes(&data);
    assert!(sig.is_some());
    let sig = sig.unwrap();
    assert_eq!(sig.bytes[0], 0);
    assert_eq!(sig.key_id[0], 1);
    assert_eq!(sig.timestamp, 100);
}

#[test]
fn test_package_signature_from_bytes_too_short() {
    let data = [0u8; 10];
    let sig = PackageSignature::from_bytes(&data);
    assert!(sig.is_none());
}

#[test]
fn test_package_signature_from_bytes_exact_minimum() {
    let data = [0u8; SIGNATURE_SIZE + 8 + 8];
    let sig = PackageSignature::from_bytes(&data);
    assert!(sig.is_some());
}

#[test]
fn test_package_signature_to_bytes() {
    let sig = PackageSignature {
        bytes: [42u8; SIGNATURE_SIZE],
        key_id: [1, 2, 3, 4, 5, 6, 7, 8],
        timestamp: 12345,
    };
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), SIGNATURE_SIZE + 8 + 8);
    assert_eq!(bytes[0], 42);
    assert_eq!(bytes[SIGNATURE_SIZE], 1);
}

#[test]
fn test_package_signature_roundtrip() {
    let original = PackageSignature {
        bytes: [0xAB; SIGNATURE_SIZE],
        key_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        timestamp: 9999999,
    };
    let bytes = original.to_bytes();
    let restored = PackageSignature::from_bytes(&bytes).unwrap();
    assert_eq!(original.bytes, restored.bytes);
    assert_eq!(original.key_id, restored.key_id);
    assert_eq!(original.timestamp, restored.timestamp);
}

#[test]
fn test_package_signature_clone() {
    let sig = PackageSignature {
        bytes: [1u8; SIGNATURE_SIZE],
        key_id: [2u8; 8],
        timestamp: 500,
    };
    let cloned = sig.clone();
    assert_eq!(sig.bytes, cloned.bytes);
    assert_eq!(sig.key_id, cloned.key_id);
    assert_eq!(sig.timestamp, cloned.timestamp);
}

#[test]
fn test_package_signature_debug_format() {
    let sig = PackageSignature {
        bytes: [0u8; SIGNATURE_SIZE],
        key_id: [0u8; 8],
        timestamp: 0,
    };
    let debug_str = alloc::format!("{:?}", sig);
    assert!(debug_str.contains("PackageSignature"));
}

#[test]
fn test_verifying_key_from_bytes_valid() {
    let data = [0x55u8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data);
    assert!(key.is_some());
    let key = key.unwrap();
    assert_eq!(key.bytes[0], 0x55);
}

#[test]
fn test_verifying_key_from_bytes_too_short() {
    let data = [0u8; 16];
    let key = VerifyingKey::from_bytes(&data);
    assert!(key.is_none());
}

#[test]
fn test_verifying_key_from_bytes_too_long() {
    let data = [0u8; 64];
    let key = VerifyingKey::from_bytes(&data);
    assert!(key.is_none());
}

#[test]
fn test_verifying_key_key_id() {
    let data = [0xAAu8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data).unwrap();
    let id = key.key_id();
    assert_eq!(id.len(), 8);
}

#[test]
fn test_verifying_key_clone() {
    let data = [0x33u8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data).unwrap();
    let cloned = key.clone();
    assert_eq!(key.bytes, cloned.bytes);
}

#[test]
fn test_verifying_key_debug_format() {
    let data = [0u8; PUBLIC_KEY_SIZE];
    let key = VerifyingKey::from_bytes(&data).unwrap();
    let debug_str = alloc::format!("{:?}", key);
    assert!(debug_str.contains("VerifyingKey"));
}

#[test]
fn test_generate_signing_keypair() {
    let (signing, verifying) = generate_signing_keypair();
    assert_eq!(verifying.bytes.len(), PUBLIC_KEY_SIZE);
    let id1 = signing.key_id();
    let id2 = verifying.key_id();
    assert_eq!(id1, id2);
}

#[test]
fn test_signing_key_public_key() {
    let (signing, verifying) = generate_signing_keypair();
    let pub_from_signing = signing.public_key();
    assert_eq!(pub_from_signing.bytes, verifying.bytes);
}

#[test]
fn test_sign_package() {
    let (signing, _verifying) = generate_signing_keypair();
    let data = b"test package data";
    let sig = sign_package(data, &signing);
    assert_eq!(sig.bytes.len(), SIGNATURE_SIZE);
    assert_eq!(sig.key_id, signing.key_id());
    assert!(sig.timestamp > 0);
}

#[test]
fn test_compute_checksum() {
    use crate::npkg::signature::compute_checksum;
    let data = b"hello world";
    let checksum = compute_checksum(data);
    assert_eq!(checksum.len(), 32);
}

#[test]
fn test_compute_checksum_deterministic() {
    use crate::npkg::signature::compute_checksum;
    let data = b"same data";
    let checksum1 = compute_checksum(data);
    let checksum2 = compute_checksum(data);
    assert_eq!(checksum1, checksum2);
}

#[test]
fn test_compute_checksum_different_data() {
    use crate::npkg::signature::compute_checksum;
    let checksum1 = compute_checksum(b"data1");
    let checksum2 = compute_checksum(b"data2");
    assert_ne!(checksum1, checksum2);
}

#[test]
fn test_verify_checksum_valid() {
    use crate::npkg::download::verify_checksum;
    use crate::npkg::signature::compute_checksum;
    let data = b"test data for checksum";
    let checksum = compute_checksum(data);
    assert!(verify_checksum(data, &checksum));
}

#[test]
fn test_verify_checksum_invalid() {
    use crate::npkg::download::verify_checksum;
    let data = b"test data";
    let wrong_checksum = [0u8; 32];
    assert!(!verify_checksum(data, &wrong_checksum));
}

#[test]
fn test_verify_checksum_empty_data() {
    use crate::npkg::download::verify_checksum;
    use crate::npkg::signature::compute_checksum;
    let data = b"";
    let checksum = compute_checksum(data);
    assert!(verify_checksum(data, &checksum));
}

#[test]
fn test_list_trusted_keys() {
    let keys = list_trusted_keys();
    let _ = keys.len();
}

#[test]
fn test_add_trusted_key() {
    let (_, verifying) = generate_signing_keypair();
    add_trusted_key(verifying.clone());
    let key_id = verifying.key_id();
    let found = get_trusted_key(&key_id);
    assert!(found.is_some());
}

#[test]
fn test_add_trusted_key_duplicate() {
    let (_, verifying) = generate_signing_keypair();
    let initial_count = list_trusted_keys().len();
    add_trusted_key(verifying.clone());
    add_trusted_key(verifying.clone());
    let new_count = list_trusted_keys().len();
    assert!(new_count <= initial_count + 1);
}

#[test]
fn test_remove_trusted_key() {
    let (_, verifying) = generate_signing_keypair();
    add_trusted_key(verifying.clone());
    let key_id = verifying.key_id();
    remove_trusted_key(&key_id);
    let found = get_trusted_key(&key_id);
    assert!(found.is_none());
}

#[test]
fn test_get_trusted_key_not_found() {
    let fake_id = [0xFF; 8];
    let found = get_trusted_key(&fake_id);
    assert!(found.is_none());
}
