// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::apps::context::AppPermissions;
use crate::apps::lifecycle::LifecycleState;
use crate::apps::registry::{AppEntry, AppInfo};
use crate::apps::types::AppType;
use crate::test::framework::TestResult;

fn make_test_info(name: &'static str) -> AppInfo {
    AppInfo::new(name, "1.0.0", "Test application", "NONOS", AppType::Utility, AppPermissions::NONE)
}

pub(crate) fn test_app_info_new() -> TestResult {
    let info = AppInfo::new(
        "TestApp",
        "2.0.0",
        "A test app",
        "Developer",
        AppType::Browser,
        AppPermissions::BROWSER,
    );
    if info.name != "TestApp" {
        return TestResult::Fail;
    }
    if info.version != "2.0.0" {
        return TestResult::Fail;
    }
    if info.description != "A test app" {
        return TestResult::Fail;
    }
    if info.author != "Developer" {
        return TestResult::Fail;
    }
    if info.app_type != AppType::Browser {
        return TestResult::Fail;
    }
    if !info.permissions.contains(AppPermissions::NETWORK) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_new() -> TestResult {
    let info = make_test_info("EntryTest");
    let entry = AppEntry::new(info);
    if entry.name() != "EntryTest" {
        return TestResult::Fail;
    }
    if entry.version() != "1.0.0" {
        return TestResult::Fail;
    }
    if entry.state() != LifecycleState::Stopped {
        return TestResult::Fail;
    }
    if entry.context().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_info_accessors() -> TestResult {
    let info = AppInfo::new(
        "Wallet",
        "3.5.1",
        "Crypto wallet",
        "NONOS Team",
        AppType::Wallet,
        AppPermissions::WALLET_APP,
    );
    let entry = AppEntry::new(info);
    if entry.name() != "Wallet" {
        return TestResult::Fail;
    }
    if entry.version() != "3.5.1" {
        return TestResult::Fail;
    }
    if entry.description() != "Crypto wallet" {
        return TestResult::Fail;
    }
    if entry.app_type() != AppType::Wallet {
        return TestResult::Fail;
    }
    if !entry.permissions().contains(AppPermissions::CRYPTO) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_state() -> TestResult {
    let info = make_test_info("StateTest");
    let mut entry = AppEntry::new(info);
    if entry.state() != LifecycleState::Stopped {
        return TestResult::Fail;
    }
    entry.set_state(LifecycleState::Running);
    if entry.state() != LifecycleState::Running {
        return TestResult::Fail;
    }
    entry.set_state(LifecycleState::Suspended);
    if entry.state() != LifecycleState::Suspended {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_is_running() -> TestResult {
    let info = make_test_info("RunningTest");
    let mut entry = AppEntry::new(info);
    if entry.is_running() {
        return TestResult::Fail;
    }
    entry.set_state(LifecycleState::Running);
    if !entry.is_running() {
        return TestResult::Fail;
    }
    entry.set_state(LifecycleState::Suspended);
    if !entry.is_running() {
        return TestResult::Fail;
    }
    entry.set_state(LifecycleState::Stopped);
    if entry.is_running() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_create_context() -> TestResult {
    let info = make_test_info("ContextTest");
    let mut entry = AppEntry::new(info);
    if entry.context().is_some() {
        return TestResult::Fail;
    }
    if entry.id().is_some() {
        return TestResult::Fail;
    }
    entry.create_context();
    if entry.context().is_none() {
        return TestResult::Fail;
    }
    if entry.id().is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_context_properties() -> TestResult {
    let info = AppInfo::new(
        "PropTest",
        "1.0.0",
        "Test",
        "Author",
        AppType::Browser,
        AppPermissions::BROWSER,
    );
    let mut entry = AppEntry::new(info);
    entry.create_context();
    let ctx = entry.context().unwrap();
    if ctx.name() != "PropTest" {
        return TestResult::Fail;
    }
    if ctx.app_type() != AppType::Browser {
        return TestResult::Fail;
    }
    if !ctx.has_permission(AppPermissions::NETWORK) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_destroy_context() -> TestResult {
    let info = make_test_info("DestroyTest");
    let mut entry = AppEntry::new(info);
    entry.create_context();
    if entry.context().is_none() {
        return TestResult::Fail;
    }
    entry.destroy_context();
    if entry.context().is_some() {
        return TestResult::Fail;
    }
    if entry.id().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_context_mut() -> TestResult {
    let info = make_test_info("MutTest");
    let mut entry = AppEntry::new(info);
    entry.create_context();
    let ctx_mut = entry.context_mut().unwrap();
    ctx_mut.mark_started();
    let ctx = entry.context().unwrap();
    if ctx.started_at() == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_registered_at() -> TestResult {
    let info = make_test_info("TimeTest");
    let entry = AppEntry::new(info);
    if entry.registered_at() == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_uptime_no_context() -> TestResult {
    let info = make_test_info("UptimeTest");
    let entry = AppEntry::new(info);
    if entry.uptime_ms() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_uptime_with_context() -> TestResult {
    let info = make_test_info("UptimeTest2");
    let mut entry = AppEntry::new(info);
    entry.create_context();
    let ctx_mut = entry.context_mut().unwrap();
    ctx_mut.mark_started();
    if entry.uptime_ms() < 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_info_fields() -> TestResult {
    let info = AppInfo::new(
        "FieldsTest",
        "0.1.0",
        "Description here",
        "AuthorName",
        AppType::Privacy,
        AppPermissions::CRYPTO | AppPermissions::FILESYSTEM,
    );
    if info.name != "FieldsTest" {
        return TestResult::Fail;
    }
    if info.version != "0.1.0" {
        return TestResult::Fail;
    }
    if info.description != "Description here" {
        return TestResult::Fail;
    }
    if info.author != "AuthorName" {
        return TestResult::Fail;
    }
    if info.app_type != AppType::Privacy {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_entries() -> TestResult {
    let info1 = make_test_info("App1");
    let info2 = make_test_info("App2");
    let mut entry1 = AppEntry::new(info1);
    let mut entry2 = AppEntry::new(info2);
    entry1.create_context();
    entry2.create_context();
    if entry1.id() == entry2.id() {
        return TestResult::Fail;
    }
    if entry1.name() != "App1" {
        return TestResult::Fail;
    }
    if entry2.name() != "App2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_transitions() -> TestResult {
    let info = make_test_info("TransitionTest");
    let mut entry = AppEntry::new(info);
    let states = [
        LifecycleState::Starting,
        LifecycleState::Running,
        LifecycleState::Suspended,
        LifecycleState::Stopping,
        LifecycleState::Stopped,
        LifecycleState::Failed,
    ];
    for state in states {
        entry.set_state(state);
        if entry.state() != state {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_app_entry_info_reference() -> TestResult {
    let info = make_test_info("RefTest");
    let entry = AppEntry::new(info);
    let info_ref = entry.info();
    if info_ref.name != "RefTest" {
        return TestResult::Fail;
    }
    if info_ref.version != "1.0.0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
