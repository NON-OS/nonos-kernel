use crate::security::*;
use alloc::string::String;
use alloc::vec::Vec;

#[test]
fn test_trusted_key_struct_fields() {
    let key = trusted_keys::TrustedKey {
        name: String::from("test.key"),
        key: vec![1, 2, 3, 4],
    };
    assert_eq!(key.name, "test.key");
    assert_eq!(key.key, vec![1, 2, 3, 4]);
}

#[test]
fn test_trusted_key_equality() {
    let key1 = trusted_keys::TrustedKey {
        name: String::from("key1"),
        key: vec![1, 2, 3],
    };
    let key2 = trusted_keys::TrustedKey {
        name: String::from("key1"),
        key: vec![1, 2, 3],
    };
    assert_eq!(key1, key2);
}

#[test]
fn test_trusted_key_inequality_name() {
    let key1 = trusted_keys::TrustedKey {
        name: String::from("key1"),
        key: vec![1, 2, 3],
    };
    let key2 = trusted_keys::TrustedKey {
        name: String::from("key2"),
        key: vec![1, 2, 3],
    };
    assert_ne!(key1, key2);
}

#[test]
fn test_trusted_key_inequality_data() {
    let key1 = trusted_keys::TrustedKey {
        name: String::from("key"),
        key: vec![1, 2, 3],
    };
    let key2 = trusted_keys::TrustedKey {
        name: String::from("key"),
        key: vec![4, 5, 6],
    };
    assert_ne!(key1, key2);
}

#[test]
fn test_trusted_key_clone() {
    let key1 = trusted_keys::TrustedKey {
        name: String::from("cloneable"),
        key: vec![0xAB, 0xCD],
    };
    let key2 = key1.clone();
    assert_eq!(key1, key2);
}

#[test]
fn test_trusted_key_empty_key_data() {
    let key = trusted_keys::TrustedKey {
        name: String::from("empty"),
        key: Vec::new(),
    };
    assert!(key.key.is_empty());
}

#[test]
fn test_trusted_key_32_byte_key() {
    let key = trusted_keys::TrustedKey {
        name: String::from("standard"),
        key: vec![0u8; 32],
    };
    assert_eq!(key.key.len(), 32);
}

#[test]
fn test_trusted_key_name_with_dots() {
    let key = trusted_keys::TrustedKey {
        name: String::from("nonos.kernel.root"),
        key: vec![1],
    };
    assert!(key.name.contains('.'));
}

#[test]
fn test_trusted_hash_db_empty() {
    let hashes = list_trusted_hashes();
    let _ = hashes;
}

#[test]
fn test_add_trusted_hash() {
    let hash = [0xABu8; 32];
    add_trusted_hash("test_module", hash);
}

#[test]
fn test_get_trusted_hash_not_found() {
    let result = get_trusted_hash("nonexistent_hash_12345");
    assert!(result.is_none());
}

#[test]
fn test_verify_integrity_with_matching_hash() {
    let hash = [0xCDu8; 32];
    add_trusted_hash("integrity_test", hash);
    assert!(verify_integrity("integrity_test", &hash));
}

#[test]
fn test_verify_integrity_with_mismatched_hash() {
    let stored_hash = [0x11u8; 32];
    let check_hash = [0x22u8; 32];
    add_trusted_hash("mismatch_test", stored_hash);
    assert!(!verify_integrity("mismatch_test", &check_hash));
}

#[test]
fn test_verify_integrity_unknown_name() {
    let hash = [0u8; 32];
    assert!(!verify_integrity("unknown_name_xyz", &hash));
}

#[test]
fn test_list_trusted_hashes_returns_vec() {
    let hashes = list_trusted_hashes();
    let _ = hashes.len();
}

#[test]
fn test_trusted_key_db_add_and_get() {
    add_trusted_key("test_key_add", &[1, 2, 3, 4]);
    let result = get_trusted_key("test_key_add");
    assert!(result.is_some());
    assert_eq!(result.unwrap(), vec![1, 2, 3, 4]);
}

#[test]
fn test_trusted_key_db_get_nonexistent() {
    let result = get_trusted_key("nonexistent_key_xyz123");
    assert!(result.is_none());
}

#[test]
fn test_list_trusted_keys_returns_vec() {
    let keys = crypto_list_trusted_keys();
    let _ = keys.len();
}

#[test]
fn test_get_trusted_keys_returns_vec() {
    let keys = get_trusted_keys();
    let _ = keys.len();
}

#[test]
fn test_add_trusted_key_overwrites() {
    add_trusted_key("overwrite_test", &[1, 2, 3]);
    add_trusted_key("overwrite_test", &[4, 5, 6]);
    let result = get_trusted_key("overwrite_test");
    assert_eq!(result, Some(vec![4, 5, 6]));
}

#[test]
fn test_add_trusted_key_empty_data() {
    add_trusted_key("empty_data_key", &[]);
    let result = get_trusted_key("empty_data_key");
    assert_eq!(result, Some(Vec::new()));
}

#[test]
fn test_add_trusted_key_large_data() {
    let large_key = vec![0xFFu8; 1024];
    add_trusted_key("large_key", &large_key);
    let result = get_trusted_key("large_key");
    assert_eq!(result.unwrap().len(), 1024);
}

#[test]
fn test_trusted_key_db_multiple_keys() {
    add_trusted_key("multi_key_1", &[1]);
    add_trusted_key("multi_key_2", &[2]);
    add_trusted_key("multi_key_3", &[3]);
    assert_eq!(get_trusted_key("multi_key_1"), Some(vec![1]));
    assert_eq!(get_trusted_key("multi_key_2"), Some(vec![2]));
    assert_eq!(get_trusted_key("multi_key_3"), Some(vec![3]));
}

#[test]
fn test_trusted_hash_32_bytes() {
    let hash = [0x55u8; 32];
    add_trusted_hash("hash_32", hash);
    let retrieved = get_trusted_hash("hash_32");
    assert_eq!(retrieved, Some(hash));
}

#[test]
fn test_list_trusted_hashes_contains_added() {
    let hash = [0x77u8; 32];
    add_trusted_hash("list_test_hash", hash);
    let hashes = list_trusted_hashes();
    let found = hashes.iter().any(|(name, _)| name == "list_test_hash");
    assert!(found);
}

#[test]
fn test_trusted_key_debug_format() {
    let key = trusted_keys::TrustedKey {
        name: String::from("debug_key"),
        key: vec![1, 2, 3],
    };
    let debug_str = alloc::format!("{:?}", key);
    assert!(debug_str.contains("debug_key"));
}
