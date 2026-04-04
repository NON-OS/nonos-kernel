// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::commands::builtins::alias::{
    Alias, AliasTable, MAX_ALIASES, MAX_ALIAS_NAME, MAX_ALIAS_VALUE,
};

#[test]
fn test_max_aliases_constant() {
    assert_eq!(MAX_ALIASES, 32);
}

#[test]
fn test_max_alias_name_constant() {
    assert_eq!(MAX_ALIAS_NAME, 16);
}

#[test]
fn test_max_alias_value_constant() {
    assert_eq!(MAX_ALIAS_VALUE, 128);
}

#[test]
fn test_alias_empty() {
    let alias = Alias::empty();
    assert_eq!(alias.name_len, 0);
    assert_eq!(alias.value_len, 0);
}

#[test]
fn test_alias_empty_name_array() {
    let alias = Alias::empty();
    assert!(alias.name.iter().all(|&b| b == 0));
}

#[test]
fn test_alias_empty_value_array() {
    let alias = Alias::empty();
    assert!(alias.value.iter().all(|&b| b == 0));
}

#[test]
fn test_alias_table_new() {
    let table = AliasTable::new();
    assert_eq!(table.count, 0);
}

#[test]
fn test_alias_table_set_single() {
    let mut table = AliasTable::new();
    let result = table.set(b"ll", b"ls -la");
    assert!(result);
    assert_eq!(table.count, 1);
}

#[test]
fn test_alias_table_get_existing() {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let value = table.get(b"ll");
    assert!(value.is_some());
    assert_eq!(value.unwrap(), b"ls -la");
}

#[test]
fn test_alias_table_get_nonexistent() {
    let table = AliasTable::new();
    assert!(table.get(b"nonexistent").is_none());
}

#[test]
fn test_alias_table_set_multiple() {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    table.set(b"la", b"ls -a");
    table.set(b"cls", b"clear");
    assert_eq!(table.count, 3);
}

#[test]
fn test_alias_table_set_update_existing() {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -l");
    table.set(b"ll", b"ls -la");
    assert_eq!(table.count, 1);
    assert_eq!(table.get(b"ll").unwrap(), b"ls -la");
}

#[test]
fn test_alias_table_unset_existing() {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.unset(b"ll");
    assert!(result);
    assert_eq!(table.count, 0);
}

#[test]
fn test_alias_table_unset_nonexistent() {
    let mut table = AliasTable::new();
    let result = table.unset(b"nonexistent");
    assert!(!result);
}

#[test]
fn test_alias_table_unset_middle() {
    let mut table = AliasTable::new();
    table.set(b"a", b"1");
    table.set(b"b", b"2");
    table.set(b"c", b"3");
    table.unset(b"b");
    assert_eq!(table.count, 2);
    assert!(table.get(b"a").is_some());
    assert!(table.get(b"b").is_none());
    assert!(table.get(b"c").is_some());
}

#[test]
fn test_alias_table_expand_simple() {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.expand(b"ll");
    assert!(result.is_some());
    let (buf, len) = result.unwrap();
    assert_eq!(&buf[..len], b"ls -la");
}

#[test]
fn test_alias_table_expand_with_args() {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.expand(b"ll /home");
    assert!(result.is_some());
    let (buf, len) = result.unwrap();
    assert_eq!(&buf[..len], b"ls -la /home");
}

#[test]
fn test_alias_table_expand_nonexistent() {
    let table = AliasTable::new();
    assert!(table.expand(b"nonexistent").is_none());
}

#[test]
fn test_alias_table_init_defaults() {
    let mut table = AliasTable::new();
    table.init_defaults();
    assert!(table.count > 0);
    assert!(table.get(b"ll").is_some());
    assert!(table.get(b"cls").is_some());
}

#[test]
fn test_alias_table_secure_erase() {
    let mut table = AliasTable::new();
    table.set(b"secret", b"password123");
    table.secure_erase();
    assert_eq!(table.count, 0);
}

#[test]
fn test_alias_table_secure_erase_clears_all() {
    let mut table = AliasTable::new();
    table.init_defaults();
    table.secure_erase();
    assert!(table.get(b"ll").is_none());
    assert!(table.get(b"cls").is_none());
}

#[test]
fn test_alias_table_max_capacity() {
    let mut table = AliasTable::new();
    for i in 0..MAX_ALIASES {
        let name = [b'a' + (i % 26) as u8, b'0' + (i / 26) as u8];
        table.set(&name, b"value");
    }
    assert_eq!(table.count, MAX_ALIASES);
}

#[test]
fn test_alias_table_over_capacity() {
    let mut table = AliasTable::new();
    for i in 0..MAX_ALIASES {
        let name = [b'a' + (i % 26) as u8, b'0' + (i / 26) as u8];
        table.set(&name, b"value");
    }
    let result = table.set(b"overflow", b"value");
    assert!(!result);
    assert_eq!(table.count, MAX_ALIASES);
}

#[test]
fn test_alias_truncates_long_name() {
    let mut table = AliasTable::new();
    let long_name = [b'x'; MAX_ALIAS_NAME + 10];
    table.set(&long_name, b"value");
    assert_eq!(table.count, 1);
}

#[test]
fn test_alias_truncates_long_value() {
    let mut table = AliasTable::new();
    let long_value = [b'x'; MAX_ALIAS_VALUE + 10];
    table.set(b"name", &long_value);
    assert_eq!(table.count, 1);
}

#[test]
fn test_alias_table_empty_name() {
    let mut table = AliasTable::new();
    table.set(b"", b"value");
    assert!(table.get(b"").is_some());
}

#[test]
fn test_alias_table_empty_value() {
    let mut table = AliasTable::new();
    table.set(b"name", b"");
    let value = table.get(b"name");
    assert!(value.is_some());
    assert_eq!(value.unwrap(), b"");
}

#[test]
fn test_alias_copy() {
    let alias1 = Alias::empty();
    let alias2 = alias1;
    assert_eq!(alias1.name_len, alias2.name_len);
}

#[test]
fn test_alias_clone() {
    let alias1 = Alias::empty();
    let alias2 = alias1.clone();
    assert_eq!(alias1.name_len, alias2.name_len);
}

#[test]
fn test_alias_table_expand_preserves_whitespace() {
    let mut table = AliasTable::new();
    table.set(b"ll", b"ls -la");
    let result = table.expand(b"ll  /home  /var");
    assert!(result.is_some());
    let (buf, len) = result.unwrap();
    assert_eq!(&buf[..len], b"ls -la  /home  /var");
}

#[test]
fn test_alias_table_get_after_unset_others() {
    let mut table = AliasTable::new();
    table.set(b"a", b"1");
    table.set(b"b", b"2");
    table.set(b"c", b"3");
    table.unset(b"a");
    table.unset(b"b");
    assert_eq!(table.get(b"c").unwrap(), b"3");
}

#[test]
fn test_alias_table_const_new() {
    const TABLE: AliasTable = AliasTable::new();
    assert_eq!(TABLE.count, 0);
}

#[test]
fn test_alias_const_empty() {
    const ALIAS: Alias = Alias::empty();
    assert_eq!(ALIAS.name_len, 0);
}

