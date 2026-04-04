// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for apps/context

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use crate::apps::context::{AppContext, AppPermissions, PermissionLevel};
use crate::apps::types::AppType;

#[test_case]
fn test_permission_level_denied() {
    let level = PermissionLevel::Denied;
    assert!(!level.can_read());
    assert!(!level.can_write());
    assert!(!level.is_full());
}

#[test_case]
fn test_permission_level_readonly() {
    let level = PermissionLevel::ReadOnly;
    assert!(level.can_read());
    assert!(!level.can_write());
    assert!(!level.is_full());
}

#[test_case]
fn test_permission_level_readwrite() {
    let level = PermissionLevel::ReadWrite;
    assert!(level.can_read());
    assert!(level.can_write());
    assert!(!level.is_full());
}

#[test_case]
fn test_permission_level_full() {
    let level = PermissionLevel::Full;
    assert!(level.can_read());
    assert!(level.can_write());
    assert!(level.is_full());
}

#[test_case]
fn test_permission_level_default() {
    let level: PermissionLevel = Default::default();
    assert_eq!(level, PermissionLevel::Denied);
}

#[test_case]
fn test_permission_level_ordering() {
    assert!(PermissionLevel::Denied < PermissionLevel::ReadOnly);
    assert!(PermissionLevel::ReadOnly < PermissionLevel::ReadWrite);
    assert!(PermissionLevel::ReadWrite < PermissionLevel::Full);
}

#[test_case]
fn test_permission_level_repr() {
    assert_eq!(PermissionLevel::Denied as u8, 0);
    assert_eq!(PermissionLevel::ReadOnly as u8, 1);
    assert_eq!(PermissionLevel::ReadWrite as u8, 2);
    assert_eq!(PermissionLevel::Full as u8, 3);
}

#[test_case]
fn test_app_permissions_none() {
    let perms = AppPermissions::NONE;
    assert!(perms.is_empty());
}

#[test_case]
fn test_app_permissions_individual() {
    assert!(AppPermissions::NETWORK.contains(AppPermissions::NETWORK));
    assert!(AppPermissions::FILESYSTEM.contains(AppPermissions::FILESYSTEM));
    assert!(AppPermissions::CRYPTO.contains(AppPermissions::CRYPTO));
    assert!(AppPermissions::WALLET.contains(AppPermissions::WALLET));
}

#[test_case]
fn test_app_permissions_browser_preset() {
    let browser = AppPermissions::BROWSER;
    assert!(browser.contains(AppPermissions::NETWORK));
    assert!(browser.contains(AppPermissions::DISPLAY));
    assert!(browser.contains(AppPermissions::INPUT));
    assert!(browser.contains(AppPermissions::CLIPBOARD));
    assert!(!browser.contains(AppPermissions::CRYPTO));
}

#[test_case]
fn test_app_permissions_wallet_preset() {
    let wallet = AppPermissions::WALLET_APP;
    assert!(wallet.contains(AppPermissions::CRYPTO));
    assert!(wallet.contains(AppPermissions::WALLET));
    assert!(wallet.contains(AppPermissions::DISPLAY));
    assert!(wallet.contains(AppPermissions::INPUT));
    assert!(wallet.contains(AppPermissions::FILESYSTEM));
}

#[test_case]
fn test_app_permissions_ecosystem_preset() {
    let eco = AppPermissions::ECOSYSTEM;
    assert!(eco.contains(AppPermissions::NETWORK));
    assert!(eco.contains(AppPermissions::CRYPTO));
    assert!(eco.contains(AppPermissions::WALLET));
    assert!(eco.contains(AppPermissions::NOTIFICATIONS));
}

#[test_case]
fn test_app_permissions_combine() {
    let perms = AppPermissions::NETWORK | AppPermissions::CRYPTO;
    assert!(perms.contains(AppPermissions::NETWORK));
    assert!(perms.contains(AppPermissions::CRYPTO));
    assert!(!perms.contains(AppPermissions::FILESYSTEM));
}

#[test_case]
fn test_app_permissions_default() {
    let perms: AppPermissions = Default::default();
    assert_eq!(perms, AppPermissions::NONE);
}

#[test_case]
fn test_app_context_new() {
    let ctx = AppContext::new(
        String::from("TestApp"),
        AppType::Utility,
        AppPermissions::NONE,
    );
    assert_eq!(ctx.name(), "TestApp");
    assert_eq!(ctx.app_type(), AppType::Utility);
}

#[test_case]
fn test_app_context_with_permissions() {
    let ctx = AppContext::new(
        String::from("Browser"),
        AppType::Browser,
        AppPermissions::BROWSER,
    );
    assert!(ctx.has_permission(AppPermissions::NETWORK));
    assert!(ctx.has_permission(AppPermissions::DISPLAY));
    assert!(!ctx.has_permission(AppPermissions::CRYPTO));
}

#[test_case]
fn test_app_context_id_unique() {
    let ctx1 = AppContext::new(String::from("App1"), AppType::Utility, AppPermissions::NONE);
    let ctx2 = AppContext::new(String::from("App2"), AppType::Utility, AppPermissions::NONE);
    assert_ne!(ctx1.id(), ctx2.id());
}

#[test_case]
fn test_app_context_mark_started() {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    assert_eq!(ctx.started_at(), 0);
    ctx.mark_started();
    assert!(ctx.started_at() > 0);
    assert!(ctx.last_active() > 0);
}

#[test_case]
fn test_app_context_mark_active() {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.mark_started();
    let first = ctx.last_active();
    ctx.mark_active();
    assert!(ctx.last_active() >= first);
}

#[test_case]
fn test_app_context_memory_tracking() {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    assert_eq!(ctx.memory_used(), 0);

    ctx.add_memory(1024);
    assert_eq!(ctx.memory_used(), 1024);

    ctx.add_memory(2048);
    assert_eq!(ctx.memory_used(), 3072);

    ctx.free_memory(1024);
    assert_eq!(ctx.memory_used(), 2048);
}

#[test_case]
fn test_app_context_memory_free_overflow() {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.add_memory(100);
    ctx.free_memory(200);
    assert_eq!(ctx.memory_used(), 0);
}

#[test_case]
fn test_app_context_state() {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);

    ctx.set_state(String::from("key1"), vec![1, 2, 3]);
    ctx.set_state(String::from("key2"), vec![4, 5, 6]);

    assert_eq!(ctx.get_state("key1"), Some(&vec![1, 2, 3]));
    assert_eq!(ctx.get_state("key2"), Some(&vec![4, 5, 6]));
    assert_eq!(ctx.get_state("key3"), None);
}

#[test_case]
fn test_app_context_state_update() {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);

    ctx.set_state(String::from("key"), vec![1]);
    ctx.set_state(String::from("key"), vec![2]);

    assert_eq!(ctx.get_state("key"), Some(&vec![2]));
}

#[test_case]
fn test_app_context_remove_state() {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);

    ctx.set_state(String::from("key"), vec![1, 2, 3]);
    let removed = ctx.remove_state("key");

    assert_eq!(removed, Some(vec![1, 2, 3]));
    assert_eq!(ctx.get_state("key"), None);
}

#[test_case]
fn test_app_context_clear_state() {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);

    ctx.set_state(String::from("key1"), vec![1]);
    ctx.set_state(String::from("key2"), vec![2]);
    ctx.clear_state();

    assert_eq!(ctx.get_state("key1"), None);
    assert_eq!(ctx.get_state("key2"), None);
}

#[test_case]
fn test_app_context_state_keys() {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);

    ctx.set_state(String::from("alpha"), vec![1]);
    ctx.set_state(String::from("beta"), vec![2]);

    let keys: alloc::vec::Vec<_> = ctx.state_keys().collect();
    assert_eq!(keys.len(), 2);
}

#[test_case]
fn test_app_context_uptime() {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    assert_eq!(ctx.uptime_ms(), 0);

    ctx.mark_started();
    assert!(ctx.uptime_ms() >= 0);
}

#[test_case]
fn test_app_context_idle() {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    assert_eq!(ctx.idle_ms(), 0);

    ctx.mark_started();
    assert!(ctx.idle_ms() >= 0);
}

#[test_case]
fn test_permission_level_clone() {
    let level = PermissionLevel::Full;
    let cloned = level.clone();
    assert_eq!(level, cloned);
}

#[test_case]
fn test_app_permissions_clone() {
    let perms = AppPermissions::NETWORK | AppPermissions::CRYPTO;
    let cloned = perms.clone();
    assert_eq!(perms, cloned);
}
