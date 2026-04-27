// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::context::{AppContext, AppPermissions, PermissionLevel};
use crate::apps::types::AppType;
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;

pub(crate) fn test_permission_level_denied() -> TestResult {
    let level = PermissionLevel::Denied;
    if level.can_read() {
        return TestResult::Fail;
    }
    if level.can_write() {
        return TestResult::Fail;
    }
    if level.is_full() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_level_readonly() -> TestResult {
    let level = PermissionLevel::ReadOnly;
    if !level.can_read() {
        return TestResult::Fail;
    }
    if level.can_write() {
        return TestResult::Fail;
    }
    if level.is_full() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_level_readwrite() -> TestResult {
    let level = PermissionLevel::ReadWrite;
    if !level.can_read() {
        return TestResult::Fail;
    }
    if !level.can_write() {
        return TestResult::Fail;
    }
    if level.is_full() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_level_full() -> TestResult {
    let level = PermissionLevel::Full;
    if !level.can_read() {
        return TestResult::Fail;
    }
    if !level.can_write() {
        return TestResult::Fail;
    }
    if !level.is_full() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_level_default() -> TestResult {
    let level: PermissionLevel = Default::default();
    if level != PermissionLevel::Denied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_level_ordering() -> TestResult {
    if !(PermissionLevel::Denied < PermissionLevel::ReadOnly) {
        return TestResult::Fail;
    }
    if !(PermissionLevel::ReadOnly < PermissionLevel::ReadWrite) {
        return TestResult::Fail;
    }
    if !(PermissionLevel::ReadWrite < PermissionLevel::Full) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_level_repr() -> TestResult {
    if (PermissionLevel::Denied as u8) != 0 {
        return TestResult::Fail;
    }
    if (PermissionLevel::ReadOnly as u8) != 1 {
        return TestResult::Fail;
    }
    if (PermissionLevel::ReadWrite as u8) != 2 {
        return TestResult::Fail;
    }
    if (PermissionLevel::Full as u8) != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_none() -> TestResult {
    let perms = AppPermissions::NONE;
    if !perms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_individual() -> TestResult {
    if !AppPermissions::NETWORK.contains(AppPermissions::NETWORK) {
        return TestResult::Fail;
    }
    if !AppPermissions::FILESYSTEM.contains(AppPermissions::FILESYSTEM) {
        return TestResult::Fail;
    }
    if !AppPermissions::CRYPTO.contains(AppPermissions::CRYPTO) {
        return TestResult::Fail;
    }
    if !AppPermissions::WALLET.contains(AppPermissions::WALLET) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_browser_preset() -> TestResult {
    let browser = AppPermissions::BROWSER;
    if !browser.contains(AppPermissions::NETWORK) {
        return TestResult::Fail;
    }
    if !browser.contains(AppPermissions::DISPLAY) {
        return TestResult::Fail;
    }
    if !browser.contains(AppPermissions::INPUT) {
        return TestResult::Fail;
    }
    if !browser.contains(AppPermissions::CLIPBOARD) {
        return TestResult::Fail;
    }
    if browser.contains(AppPermissions::CRYPTO) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_wallet_preset() -> TestResult {
    let wallet = AppPermissions::WALLET_APP;
    if !wallet.contains(AppPermissions::CRYPTO) {
        return TestResult::Fail;
    }
    if !wallet.contains(AppPermissions::WALLET) {
        return TestResult::Fail;
    }
    if !wallet.contains(AppPermissions::DISPLAY) {
        return TestResult::Fail;
    }
    if !wallet.contains(AppPermissions::INPUT) {
        return TestResult::Fail;
    }
    if !wallet.contains(AppPermissions::FILESYSTEM) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_ecosystem_preset() -> TestResult {
    let eco = AppPermissions::ECOSYSTEM;
    if !eco.contains(AppPermissions::NETWORK) {
        return TestResult::Fail;
    }
    if !eco.contains(AppPermissions::CRYPTO) {
        return TestResult::Fail;
    }
    if !eco.contains(AppPermissions::WALLET) {
        return TestResult::Fail;
    }
    if !eco.contains(AppPermissions::NOTIFICATIONS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_combine() -> TestResult {
    let perms = AppPermissions::NETWORK | AppPermissions::CRYPTO;
    if !perms.contains(AppPermissions::NETWORK) {
        return TestResult::Fail;
    }
    if !perms.contains(AppPermissions::CRYPTO) {
        return TestResult::Fail;
    }
    if perms.contains(AppPermissions::FILESYSTEM) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_default() -> TestResult {
    let perms: AppPermissions = Default::default();
    if perms != AppPermissions::NONE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_new() -> TestResult {
    let ctx = AppContext::new(String::from("TestApp"), AppType::Utility, AppPermissions::NONE);
    if ctx.name() != "TestApp" {
        return TestResult::Fail;
    }
    if ctx.app_type() != AppType::Utility {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_with_permissions() -> TestResult {
    let ctx = AppContext::new(String::from("Browser"), AppType::Browser, AppPermissions::BROWSER);
    if !ctx.has_permission(AppPermissions::NETWORK) {
        return TestResult::Fail;
    }
    if !ctx.has_permission(AppPermissions::DISPLAY) {
        return TestResult::Fail;
    }
    if ctx.has_permission(AppPermissions::CRYPTO) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_id_unique() -> TestResult {
    let ctx1 = AppContext::new(String::from("App1"), AppType::Utility, AppPermissions::NONE);
    let ctx2 = AppContext::new(String::from("App2"), AppType::Utility, AppPermissions::NONE);
    if ctx1.id() == ctx2.id() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_mark_started() -> TestResult {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    if ctx.started_at() != 0 {
        return TestResult::Fail;
    }
    ctx.mark_started();
    if ctx.started_at() == 0 {
        return TestResult::Fail;
    }
    if ctx.last_active() == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_mark_active() -> TestResult {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.mark_started();
    let first = ctx.last_active();
    ctx.mark_active();
    if ctx.last_active() < first {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_memory_tracking() -> TestResult {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    if ctx.memory_used() != 0 {
        return TestResult::Fail;
    }
    ctx.add_memory(1024);
    if ctx.memory_used() != 1024 {
        return TestResult::Fail;
    }
    ctx.add_memory(2048);
    if ctx.memory_used() != 3072 {
        return TestResult::Fail;
    }
    ctx.free_memory(1024);
    if ctx.memory_used() != 2048 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_memory_free_overflow() -> TestResult {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.add_memory(100);
    ctx.free_memory(200);
    if ctx.memory_used() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_state() -> TestResult {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.set_state(String::from("key1"), vec![1, 2, 3]);
    ctx.set_state(String::from("key2"), vec![4, 5, 6]);
    if ctx.get_state("key1") != Some(&vec![1, 2, 3]) {
        return TestResult::Fail;
    }
    if ctx.get_state("key2") != Some(&vec![4, 5, 6]) {
        return TestResult::Fail;
    }
    if ctx.get_state("key3").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_state_update() -> TestResult {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.set_state(String::from("key"), vec![1]);
    ctx.set_state(String::from("key"), vec![2]);
    if ctx.get_state("key") != Some(&vec![2]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_remove_state() -> TestResult {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.set_state(String::from("key"), vec![1, 2, 3]);
    let removed = ctx.remove_state("key");
    if removed != Some(vec![1, 2, 3]) {
        return TestResult::Fail;
    }
    if ctx.get_state("key").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_clear_state() -> TestResult {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.set_state(String::from("key1"), vec![1]);
    ctx.set_state(String::from("key2"), vec![2]);
    ctx.clear_state();
    if ctx.get_state("key1").is_some() {
        return TestResult::Fail;
    }
    if ctx.get_state("key2").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_state_keys() -> TestResult {
    let mut ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    ctx.set_state(String::from("alpha"), vec![1]);
    ctx.set_state(String::from("beta"), vec![2]);
    let keys: alloc::vec::Vec<_> = ctx.state_keys().collect();
    if keys.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_uptime() -> TestResult {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    if ctx.uptime_ms() != 0 {
        return TestResult::Fail;
    }
    ctx.mark_started();
    if ctx.uptime_ms() < 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_context_idle() -> TestResult {
    let ctx = AppContext::new(String::from("App"), AppType::Utility, AppPermissions::NONE);
    if ctx.idle_ms() != 0 {
        return TestResult::Fail;
    }
    ctx.mark_started();
    if ctx.idle_ms() < 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_permission_level_clone() -> TestResult {
    let level = PermissionLevel::Full;
    let cloned = level.clone();
    if level != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_permissions_clone() -> TestResult {
    let perms = AppPermissions::NETWORK | AppPermissions::CRYPTO;
    let cloned = perms.clone();
    if perms != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}
