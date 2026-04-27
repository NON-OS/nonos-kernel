// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::lifecycle::events::{
    clear_events, emit_event, event_count, peek_event, poll_event, AppEvent,
};
use crate::apps::lifecycle::state::LifecycleState;
use crate::apps::types::AppId;
use crate::test::framework::TestResult;
use alloc::string::String;

pub(crate) fn test_lifecycle_state_as_str() -> TestResult {
    if LifecycleState::Stopped.as_str() != "Stopped" {
        return TestResult::Fail;
    }
    if LifecycleState::Starting.as_str() != "Starting" {
        return TestResult::Fail;
    }
    if LifecycleState::Running.as_str() != "Running" {
        return TestResult::Fail;
    }
    if LifecycleState::Suspended.as_str() != "Suspended" {
        return TestResult::Fail;
    }
    if LifecycleState::Stopping.as_str() != "Stopping" {
        return TestResult::Fail;
    }
    if LifecycleState::Failed.as_str() != "Failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_is_active() -> TestResult {
    if LifecycleState::Stopped.is_active() {
        return TestResult::Fail;
    }
    if LifecycleState::Starting.is_active() {
        return TestResult::Fail;
    }
    if !LifecycleState::Running.is_active() {
        return TestResult::Fail;
    }
    if !LifecycleState::Suspended.is_active() {
        return TestResult::Fail;
    }
    if LifecycleState::Stopping.is_active() {
        return TestResult::Fail;
    }
    if LifecycleState::Failed.is_active() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_can_start() -> TestResult {
    if !LifecycleState::Stopped.can_start() {
        return TestResult::Fail;
    }
    if !LifecycleState::Failed.can_start() {
        return TestResult::Fail;
    }
    if LifecycleState::Starting.can_start() {
        return TestResult::Fail;
    }
    if LifecycleState::Running.can_start() {
        return TestResult::Fail;
    }
    if LifecycleState::Suspended.can_start() {
        return TestResult::Fail;
    }
    if LifecycleState::Stopping.can_start() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_can_stop() -> TestResult {
    if LifecycleState::Stopped.can_stop() {
        return TestResult::Fail;
    }
    if LifecycleState::Starting.can_stop() {
        return TestResult::Fail;
    }
    if !LifecycleState::Running.can_stop() {
        return TestResult::Fail;
    }
    if !LifecycleState::Suspended.can_stop() {
        return TestResult::Fail;
    }
    if LifecycleState::Stopping.can_stop() {
        return TestResult::Fail;
    }
    if LifecycleState::Failed.can_stop() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_can_suspend() -> TestResult {
    if LifecycleState::Stopped.can_suspend() {
        return TestResult::Fail;
    }
    if LifecycleState::Starting.can_suspend() {
        return TestResult::Fail;
    }
    if !LifecycleState::Running.can_suspend() {
        return TestResult::Fail;
    }
    if LifecycleState::Suspended.can_suspend() {
        return TestResult::Fail;
    }
    if LifecycleState::Stopping.can_suspend() {
        return TestResult::Fail;
    }
    if LifecycleState::Failed.can_suspend() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_can_resume() -> TestResult {
    if LifecycleState::Stopped.can_resume() {
        return TestResult::Fail;
    }
    if LifecycleState::Starting.can_resume() {
        return TestResult::Fail;
    }
    if LifecycleState::Running.can_resume() {
        return TestResult::Fail;
    }
    if !LifecycleState::Suspended.can_resume() {
        return TestResult::Fail;
    }
    if LifecycleState::Stopping.can_resume() {
        return TestResult::Fail;
    }
    if LifecycleState::Failed.can_resume() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_default() -> TestResult {
    let default: LifecycleState = Default::default();
    if default != LifecycleState::Stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_display() -> TestResult {
    let state = LifecycleState::Running;
    let s = alloc::format!("{}", state);
    if s != "Running" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_equality() -> TestResult {
    if LifecycleState::Running != LifecycleState::Running {
        return TestResult::Fail;
    }
    if LifecycleState::Running == LifecycleState::Stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_clone() -> TestResult {
    let s1 = LifecycleState::Suspended;
    let s2 = s1.clone();
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_copy() -> TestResult {
    let s1 = LifecycleState::Starting;
    let s2 = s1;
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lifecycle_state_repr() -> TestResult {
    if (LifecycleState::Stopped as u8) != 0 {
        return TestResult::Fail;
    }
    if (LifecycleState::Starting as u8) != 1 {
        return TestResult::Fail;
    }
    if (LifecycleState::Running as u8) != 2 {
        return TestResult::Fail;
    }
    if (LifecycleState::Suspended as u8) != 3 {
        return TestResult::Fail;
    }
    if (LifecycleState::Stopping as u8) != 4 {
        return TestResult::Fail;
    }
    if (LifecycleState::Failed as u8) != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_started_app_id() -> TestResult {
    let event = AppEvent::Started { app_id: AppId::from_raw(42), name: String::from("TestApp") };
    if event.app_id().as_u64() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_stopped_app_id() -> TestResult {
    let event = AppEvent::Stopped { app_id: AppId::from_raw(43), name: String::from("TestApp") };
    if event.app_id().as_u64() != 43 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_suspended_app_id() -> TestResult {
    let event = AppEvent::Suspended { app_id: AppId::from_raw(44), name: String::from("TestApp") };
    if event.app_id().as_u64() != 44 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_resumed_app_id() -> TestResult {
    let event = AppEvent::Resumed { app_id: AppId::from_raw(45), name: String::from("TestApp") };
    if event.app_id().as_u64() != 45 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_failed_app_id() -> TestResult {
    let event = AppEvent::Failed {
        app_id: AppId::from_raw(46),
        name: String::from("TestApp"),
        reason: String::from("Error"),
    };
    if event.app_id().as_u64() != 46 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_permission_granted_app_id() -> TestResult {
    let event = AppEvent::PermissionGranted { app_id: AppId::from_raw(47), permission: 1 };
    if event.app_id().as_u64() != 47 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_permission_revoked_app_id() -> TestResult {
    let event = AppEvent::PermissionRevoked { app_id: AppId::from_raw(48), permission: 2 };
    if event.app_id().as_u64() != 48 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_name_started() -> TestResult {
    let event = AppEvent::Started { app_id: AppId::from_raw(1), name: String::from("Browser") };
    if event.name() != Some("Browser") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_name_stopped() -> TestResult {
    let event = AppEvent::Stopped { app_id: AppId::from_raw(1), name: String::from("Editor") };
    if event.name() != Some("Editor") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_name_suspended() -> TestResult {
    let event = AppEvent::Suspended { app_id: AppId::from_raw(1), name: String::from("Wallet") };
    if event.name() != Some("Wallet") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_name_resumed() -> TestResult {
    let event = AppEvent::Resumed { app_id: AppId::from_raw(1), name: String::from("Terminal") };
    if event.name() != Some("Terminal") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_name_failed() -> TestResult {
    let event = AppEvent::Failed {
        app_id: AppId::from_raw(1),
        name: String::from("Settings"),
        reason: String::from("Crash"),
    };
    if event.name() != Some("Settings") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_name_permission_granted_is_none() -> TestResult {
    let event = AppEvent::PermissionGranted { app_id: AppId::from_raw(1), permission: 1 };
    if event.name().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_name_permission_revoked_is_none() -> TestResult {
    let event = AppEvent::PermissionRevoked { app_id: AppId::from_raw(1), permission: 1 };
    if event.name().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_event_queue_emit_and_poll() -> TestResult {
    clear_events();
    let event = AppEvent::Started { app_id: AppId::from_raw(100), name: String::from("TestApp") };
    emit_event(event);
    let polled = poll_event();
    if polled.is_none() {
        return TestResult::Fail;
    }
    let e = polled.unwrap();
    if e.app_id().as_u64() != 100 {
        return TestResult::Fail;
    }
    clear_events();
    TestResult::Pass
}

pub(crate) fn test_event_queue_peek() -> TestResult {
    clear_events();
    let event = AppEvent::Stopped { app_id: AppId::from_raw(101), name: String::from("TestApp") };
    emit_event(event);
    let peeked1 = peek_event();
    let peeked2 = peek_event();
    if peeked1.is_none() {
        return TestResult::Fail;
    }
    if peeked2.is_none() {
        return TestResult::Fail;
    }
    if peeked1.unwrap().app_id().as_u64() != peeked2.unwrap().app_id().as_u64() {
        return TestResult::Fail;
    }
    clear_events();
    TestResult::Pass
}

pub(crate) fn test_event_queue_count() -> TestResult {
    clear_events();
    if event_count() != 0 {
        return TestResult::Fail;
    }
    emit_event(AppEvent::Started { app_id: AppId::from_raw(1), name: String::from("App1") });
    if event_count() != 1 {
        return TestResult::Fail;
    }
    emit_event(AppEvent::Stopped { app_id: AppId::from_raw(2), name: String::from("App2") });
    if event_count() != 2 {
        return TestResult::Fail;
    }
    clear_events();
    TestResult::Pass
}

pub(crate) fn test_event_queue_clear() -> TestResult {
    clear_events();
    emit_event(AppEvent::Started { app_id: AppId::from_raw(1), name: String::from("App") });
    emit_event(AppEvent::Stopped { app_id: AppId::from_raw(1), name: String::from("App") });
    if event_count() == 0 {
        return TestResult::Fail;
    }
    clear_events();
    if event_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_event_queue_poll_empty() -> TestResult {
    clear_events();
    if poll_event().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_event_queue_peek_empty() -> TestResult {
    clear_events();
    if peek_event().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_event_fifo_order() -> TestResult {
    clear_events();
    emit_event(AppEvent::Started { app_id: AppId::from_raw(1), name: String::from("First") });
    emit_event(AppEvent::Started { app_id: AppId::from_raw(2), name: String::from("Second") });
    emit_event(AppEvent::Started { app_id: AppId::from_raw(3), name: String::from("Third") });
    if poll_event().unwrap().app_id().as_u64() != 1 {
        return TestResult::Fail;
    }
    if poll_event().unwrap().app_id().as_u64() != 2 {
        return TestResult::Fail;
    }
    if poll_event().unwrap().app_id().as_u64() != 3 {
        return TestResult::Fail;
    }
    if poll_event().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_app_event_clone() -> TestResult {
    let event = AppEvent::Failed {
        app_id: AppId::from_raw(99),
        name: String::from("Crasher"),
        reason: String::from("Segfault"),
    };
    let cloned = event.clone();
    if event.app_id().as_u64() != cloned.app_id().as_u64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
