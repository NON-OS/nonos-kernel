// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::commands::builtins::alias::{
    Alias, AliasTable, MAX_ALIASES, MAX_ALIAS_NAME, MAX_ALIAS_VALUE,
};
use crate::test::framework::TestResult;

pub(crate) fn test_max_aliases_constant() -> TestResult {
    if MAX_ALIASES != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_alias_name_constant() -> TestResult {
    if MAX_ALIAS_NAME != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_alias_value_constant() -> TestResult {
    if MAX_ALIAS_VALUE != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_empty() -> TestResult {
    let alias = Alias::empty();
    if alias.name_len != 0 {
        return TestResult::Fail;
    }
    if alias.value_len != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_empty_name_array() -> TestResult {
    let alias = Alias::empty();
    if !alias.name.iter().all(|&b| b == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_empty_value_array() -> TestResult {
    let alias = Alias::empty();
    if !alias.value.iter().all(|&b| b == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_new() -> TestResult {
    let table = AliasTable::new();
    if table.count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_set_single() -> TestResult {
    let mut table = AliasTable::new();
    let result = table.set(b"ll", b"ls -la");
    if !result {
        return TestResult::Fail;
    }
    if table.count != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_get_existing() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let value = table.get(b"ll");
    if value.is_none() {
        return TestResult::Fail;
    }
    if value.unwrap() != b"ls -la" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_get_nonexistent() -> TestResult {
    let table = AliasTable::new();
    if table.get(b"nonexistent").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_set_multiple() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    table.set(b"la", b"ls -a");
    table.set(b"cls", b"clear");
    if table.count != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_set_update_existing() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -l");
    table.set(b"ll", b"ls -la");
    if table.count != 1 {
        return TestResult::Fail;
    }
    if table.get(b"ll").unwrap() != b"ls -la" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_unset_existing() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.unset(b"ll");
    if !result {
        return TestResult::Fail;
    }
    if table.count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_unset_nonexistent() -> TestResult {
    let mut table = AliasTable::new();
    let result = table.unset(b"nonexistent");
    if result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_unset_middle() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"a", b"1");
    table.set(b"b", b"2");
    table.set(b"c", b"3");
    table.unset(b"b");
    if table.count != 2 {
        return TestResult::Fail;
    }
    if table.get(b"a").is_none() {
        return TestResult::Fail;
    }
    if table.get(b"b").is_some() {
        return TestResult::Fail;
    }
    if table.get(b"c").is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_expand_simple() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.expand(b"ll");
    if result.is_none() {
        return TestResult::Fail;
    }
    let (buf, len) = result.unwrap();
    if &buf[..len] != b"ls -la" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_expand_with_args() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.expand(b"ll /home");
    if result.is_none() {
        return TestResult::Fail;
    }
    let (buf, len) = result.unwrap();
    if &buf[..len] != b"ls -la /home" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_expand_nonexistent() -> TestResult {
    let table = AliasTable::new();
    if table.expand(b"nonexistent").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_init_defaults() -> TestResult {
    let mut table = AliasTable::new();
    table.init_defaults();
    if table.count <= 0 {
        return TestResult::Fail;
    }
    if table.get(b"ll").is_none() {
        return TestResult::Fail;
    }
    if table.get(b"cls").is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_secure_erase() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"secret", b"password123");
    table.secure_erase();
    if table.count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_secure_erase_clears_all() -> TestResult {
    let mut table = AliasTable::new();
    table.init_defaults();
    table.secure_erase();
    if table.get(b"ll").is_some() {
        return TestResult::Fail;
    }
    if table.get(b"cls").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_max_capacity() -> TestResult {
    let mut table = AliasTable::new();
    for i in 0..MAX_ALIASES {
        let name = [b'a' + (i % 26) as u8, b'0' + (i / 26) as u8];
        table.set(&name, b"value");
    }
    if table.count != MAX_ALIASES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_over_capacity() -> TestResult {
    let mut table = AliasTable::new();
    for i in 0..MAX_ALIASES {
        let name = [b'a' + (i % 26) as u8, b'0' + (i / 26) as u8];
        table.set(&name, b"value");
    }
    let result = table.set(b"overflow", b"value");
    if result {
        return TestResult::Fail;
    }
    if table.count != MAX_ALIASES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_truncates_long_name() -> TestResult {
    let mut table = AliasTable::new();
    let long_name = [b'x'; MAX_ALIAS_NAME + 10];
    table.set(&long_name, b"value");
    if table.count != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_truncates_long_value() -> TestResult {
    let mut table = AliasTable::new();
    let long_value = [b'x'; MAX_ALIAS_VALUE + 10];
    table.set(b"name", &long_value);
    if table.count != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_empty_name() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"", b"value");
    if table.get(b"").is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_empty_value() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"name", b"");
    let value = table.get(b"name");
    if value.is_none() {
        return TestResult::Fail;
    }
    if value.unwrap() != b"" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_copy() -> TestResult {
    let alias1 = Alias::empty();
    let alias2 = alias1;
    if alias1.name_len != alias2.name_len {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_clone() -> TestResult {
    let alias1 = Alias::empty();
    let alias2 = alias1.clone();
    if alias1.name_len != alias2.name_len {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_expand_preserves_whitespace() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.expand(b"ll  /home  /var");
    if result.is_none() {
        return TestResult::Fail;
    }
    let (buf, len) = result.unwrap();
    if &buf[..len] != b"ls -la  /home  /var" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_get_after_unset_others() -> TestResult {
    let mut table = AliasTable::new();
    table.set(b"a", b"1");
    table.set(b"b", b"2");
    table.set(b"c", b"3");
    table.unset(b"a");
    table.unset(b"b");
    if table.get(b"c").unwrap() != b"3" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_table_const_new() -> TestResult {
    const TABLE: AliasTable = AliasTable::new();
    if TABLE.count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alias_const_empty() -> TestResult {
    const ALIAS: Alias = Alias::empty();
    if ALIAS.name_len != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
