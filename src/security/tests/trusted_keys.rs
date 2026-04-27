// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Trusted key management tests

extern crate alloc;

use crate::security::*;
use crate::test::framework::TestResult;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn test_trusted_key_struct_fields() -> TestResult {
    let key = trusted_keys::TrustedKey { name: String::from("test.key"), key: vec![1, 2, 3, 4] };
    if key.name != "test.key" {
        return TestResult::Fail;
    }
    if key.key != vec![1, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_equality() -> TestResult {
    let key1 = trusted_keys::TrustedKey { name: String::from("key1"), key: vec![1, 2, 3] };
    let key2 = trusted_keys::TrustedKey { name: String::from("key1"), key: vec![1, 2, 3] };
    if key1 != key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_inequality_name() -> TestResult {
    let key1 = trusted_keys::TrustedKey { name: String::from("key1"), key: vec![1, 2, 3] };
    let key2 = trusted_keys::TrustedKey { name: String::from("key2"), key: vec![1, 2, 3] };
    if key1 == key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_inequality_data() -> TestResult {
    let key1 = trusted_keys::TrustedKey { name: String::from("key"), key: vec![1, 2, 3] };
    let key2 = trusted_keys::TrustedKey { name: String::from("key"), key: vec![4, 5, 6] };
    if key1 == key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_clone() -> TestResult {
    let key1 = trusted_keys::TrustedKey { name: String::from("cloneable"), key: vec![0xAB, 0xCD] };
    let key2 = key1.clone();
    if key1 != key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_empty_key_data() -> TestResult {
    let key = trusted_keys::TrustedKey { name: String::from("empty"), key: Vec::new() };
    if !key.key.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_32_byte_key() -> TestResult {
    let key = trusted_keys::TrustedKey { name: String::from("standard"), key: vec![0u8; 32] };
    if key.key.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_name_with_dots() -> TestResult {
    let key = trusted_keys::TrustedKey { name: String::from("nonos.kernel.root"), key: vec![1] };
    if !key.name.contains('.') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_hash_db_empty() -> TestResult {
    let hashes = list_trusted_hashes();
    let _ = hashes;
    TestResult::Pass
}

pub(crate) fn test_add_trusted_hash() -> TestResult {
    let hash = [0xABu8; 32];
    add_trusted_hash("test_module", hash);
    TestResult::Pass
}

pub(crate) fn test_get_trusted_hash_not_found() -> TestResult {
    let result = get_trusted_hash("nonexistent_hash_12345");
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_integrity_with_matching_hash() -> TestResult {
    let hash = [0xCDu8; 32];
    add_trusted_hash("integrity_test", hash);
    if !verify_integrity("integrity_test", &hash) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_integrity_with_mismatched_hash() -> TestResult {
    let stored_hash = [0x11u8; 32];
    let check_hash = [0x22u8; 32];
    add_trusted_hash("mismatch_test", stored_hash);
    if verify_integrity("mismatch_test", &check_hash) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_integrity_unknown_name() -> TestResult {
    let hash = [0u8; 32];
    if verify_integrity("unknown_name_xyz", &hash) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_trusted_hashes_returns_vec() -> TestResult {
    let hashes = list_trusted_hashes();
    let _ = hashes.len();
    TestResult::Pass
}

pub(crate) fn test_trusted_key_db_add_and_get() -> TestResult {
    add_trusted_key("test_key_add", &[1, 2, 3, 4]);
    let result = get_trusted_key("test_key_add");
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != vec![1, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_db_get_nonexistent() -> TestResult {
    let result = get_trusted_key("nonexistent_key_xyz123");
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_trusted_keys_returns_vec() -> TestResult {
    let keys = crypto_list_trusted_keys();
    let _ = keys.len();
    TestResult::Pass
}

pub(crate) fn test_get_trusted_keys_returns_vec() -> TestResult {
    let keys = get_trusted_keys();
    let _ = keys.len();
    TestResult::Pass
}

pub(crate) fn test_add_trusted_key_overwrites() -> TestResult {
    add_trusted_key("overwrite_test", &[1, 2, 3]);
    add_trusted_key("overwrite_test", &[4, 5, 6]);
    let result = get_trusted_key("overwrite_test");
    if result != Some(vec![4, 5, 6]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_add_trusted_key_empty_data() -> TestResult {
    add_trusted_key("empty_data_key", &[]);
    let result = get_trusted_key("empty_data_key");
    if result != Some(Vec::new()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_add_trusted_key_large_data() -> TestResult {
    let large_key = vec![0xFFu8; 1024];
    add_trusted_key("large_key", &large_key);
    let result = get_trusted_key("large_key");
    if result.unwrap().len() != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_db_multiple_keys() -> TestResult {
    add_trusted_key("multi_key_1", &[1]);
    add_trusted_key("multi_key_2", &[2]);
    add_trusted_key("multi_key_3", &[3]);
    if get_trusted_key("multi_key_1") != Some(vec![1]) {
        return TestResult::Fail;
    }
    if get_trusted_key("multi_key_2") != Some(vec![2]) {
        return TestResult::Fail;
    }
    if get_trusted_key("multi_key_3") != Some(vec![3]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_hash_32_bytes() -> TestResult {
    let hash = [0x55u8; 32];
    add_trusted_hash("hash_32", hash);
    let retrieved = get_trusted_hash("hash_32");
    if retrieved != Some(hash) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_trusted_hashes_contains_added() -> TestResult {
    let hash = [0x77u8; 32];
    add_trusted_hash("list_test_hash", hash);
    let hashes = list_trusted_hashes();
    let found = hashes.iter().any(|(name, _)| name == "list_test_hash");
    if !found {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trusted_key_debug_format() -> TestResult {
    let key = trusted_keys::TrustedKey { name: String::from("debug_key"), key: vec![1, 2, 3] };
    let debug_str = format!("{:?}", key);
    if !debug_str.contains("debug_key") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
