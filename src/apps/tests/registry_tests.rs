// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for apps/registry

use crate::apps::registry::{AppEntry, AppInfo};
use crate::apps::context::AppPermissions;
use crate::apps::lifecycle::LifecycleState;
use crate::apps::types::AppType;

fn make_test_info(name: &'static str) -> AppInfo {
    AppInfo::new(
        name,
        "1.0.0",
        "Test application",
        "NONOS",
        AppType::Utility,
        AppPermissions::NONE,
    )
}

#[test_case]
fn test_app_info_new() {
    let info = AppInfo::new(
        "TestApp",
        "2.0.0",
        "A test app",
        "Developer",
        AppType::Browser,
        AppPermissions::BROWSER,
    );

    assert_eq!(info.name, "TestApp");
    assert_eq!(info.version, "2.0.0");
    assert_eq!(info.description, "A test app");
    assert_eq!(info.author, "Developer");
    assert_eq!(info.app_type, AppType::Browser);
    assert!(info.permissions.contains(AppPermissions::NETWORK));
}

#[test_case]
fn test_app_entry_new() {
    let info = make_test_info("EntryTest");
    let entry = AppEntry::new(info);

    assert_eq!(entry.name(), "EntryTest");
    assert_eq!(entry.version(), "1.0.0");
    assert_eq!(entry.state(), LifecycleState::Stopped);
    assert!(entry.context().is_none());
}

#[test_case]
fn test_app_entry_info_accessors() {
    let info = AppInfo::new(
        "Wallet",
        "3.5.1",
        "Crypto wallet",
        "NONOS Team",
        AppType::Wallet,
        AppPermissions::WALLET_APP,
    );
    let entry = AppEntry::new(info);

    assert_eq!(entry.name(), "Wallet");
    assert_eq!(entry.version(), "3.5.1");
    assert_eq!(entry.description(), "Crypto wallet");
    assert_eq!(entry.app_type(), AppType::Wallet);
    assert!(entry.permissions().contains(AppPermissions::CRYPTO));
}

#[test_case]
fn test_app_entry_state() {
    let info = make_test_info("StateTest");
    let mut entry = AppEntry::new(info);

    assert_eq!(entry.state(), LifecycleState::Stopped);

    entry.set_state(LifecycleState::Running);
    assert_eq!(entry.state(), LifecycleState::Running);

    entry.set_state(LifecycleState::Suspended);
    assert_eq!(entry.state(), LifecycleState::Suspended);
}

#[test_case]
fn test_app_entry_is_running() {
    let info = make_test_info("RunningTest");
    let mut entry = AppEntry::new(info);

    assert!(!entry.is_running());

    entry.set_state(LifecycleState::Running);
    assert!(entry.is_running());

    entry.set_state(LifecycleState::Suspended);
    assert!(entry.is_running());

    entry.set_state(LifecycleState::Stopped);
    assert!(!entry.is_running());
}

#[test_case]
fn test_app_entry_create_context() {
    let info = make_test_info("ContextTest");
    let mut entry = AppEntry::new(info);

    assert!(entry.context().is_none());
    assert!(entry.id().is_none());

    entry.create_context();

    assert!(entry.context().is_some());
    assert!(entry.id().is_some());
}

#[test_case]
fn test_app_entry_context_properties() {
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
    assert_eq!(ctx.name(), "PropTest");
    assert_eq!(ctx.app_type(), AppType::Browser);
    assert!(ctx.has_permission(AppPermissions::NETWORK));
}

#[test_case]
fn test_app_entry_destroy_context() {
    let info = make_test_info("DestroyTest");
    let mut entry = AppEntry::new(info);

    entry.create_context();
    assert!(entry.context().is_some());

    entry.destroy_context();
    assert!(entry.context().is_none());
    assert!(entry.id().is_none());
}

#[test_case]
fn test_app_entry_context_mut() {
    let info = make_test_info("MutTest");
    let mut entry = AppEntry::new(info);
    entry.create_context();

    let ctx_mut = entry.context_mut().unwrap();
    ctx_mut.mark_started();

    let ctx = entry.context().unwrap();
    assert!(ctx.started_at() > 0);
}

#[test_case]
fn test_app_entry_registered_at() {
    let info = make_test_info("TimeTest");
    let entry = AppEntry::new(info);

    assert!(entry.registered_at() > 0);
}

#[test_case]
fn test_app_entry_uptime_no_context() {
    let info = make_test_info("UptimeTest");
    let entry = AppEntry::new(info);

    assert_eq!(entry.uptime_ms(), 0);
}

#[test_case]
fn test_app_entry_uptime_with_context() {
    let info = make_test_info("UptimeTest2");
    let mut entry = AppEntry::new(info);
    entry.create_context();

    let ctx_mut = entry.context_mut().unwrap();
    ctx_mut.mark_started();

    assert!(entry.uptime_ms() >= 0);
}

#[test_case]
fn test_app_info_fields() {
    let info = AppInfo::new(
        "FieldsTest",
        "0.1.0",
        "Description here",
        "AuthorName",
        AppType::Privacy,
        AppPermissions::CRYPTO | AppPermissions::FILESYSTEM,
    );

    assert_eq!(info.name, "FieldsTest");
    assert_eq!(info.version, "0.1.0");
    assert_eq!(info.description, "Description here");
    assert_eq!(info.author, "AuthorName");
    assert_eq!(info.app_type, AppType::Privacy);
}

#[test_case]
fn test_multiple_entries() {
    let info1 = make_test_info("App1");
    let info2 = make_test_info("App2");

    let mut entry1 = AppEntry::new(info1);
    let mut entry2 = AppEntry::new(info2);

    entry1.create_context();
    entry2.create_context();

    assert_ne!(entry1.id(), entry2.id());
    assert_eq!(entry1.name(), "App1");
    assert_eq!(entry2.name(), "App2");
}

#[test_case]
fn test_lifecycle_state_transitions() {
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
        assert_eq!(entry.state(), state);
    }
}

#[test_case]
fn test_app_entry_info_reference() {
    let info = make_test_info("RefTest");
    let entry = AppEntry::new(info);

    let info_ref = entry.info();
    assert_eq!(info_ref.name, "RefTest");
    assert_eq!(info_ref.version, "1.0.0");
}
