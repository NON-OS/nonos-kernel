extern crate alloc;

use alloc::string::String;
use crate::apps::lifecycle::state::LifecycleState;
use crate::apps::lifecycle::events::{AppEvent, emit_event, poll_event, peek_event, event_count, clear_events};
use crate::apps::types::AppId;

#[test]
fn test_lifecycle_state_as_str() {
    assert_eq!(LifecycleState::Stopped.as_str(), "Stopped");
    assert_eq!(LifecycleState::Starting.as_str(), "Starting");
    assert_eq!(LifecycleState::Running.as_str(), "Running");
    assert_eq!(LifecycleState::Suspended.as_str(), "Suspended");
    assert_eq!(LifecycleState::Stopping.as_str(), "Stopping");
    assert_eq!(LifecycleState::Failed.as_str(), "Failed");
}

#[test]
fn test_lifecycle_state_is_active() {
    assert!(!LifecycleState::Stopped.is_active());
    assert!(!LifecycleState::Starting.is_active());
    assert!(LifecycleState::Running.is_active());
    assert!(LifecycleState::Suspended.is_active());
    assert!(!LifecycleState::Stopping.is_active());
    assert!(!LifecycleState::Failed.is_active());
}

#[test]
fn test_lifecycle_state_can_start() {
    assert!(LifecycleState::Stopped.can_start());
    assert!(LifecycleState::Failed.can_start());
    assert!(!LifecycleState::Starting.can_start());
    assert!(!LifecycleState::Running.can_start());
    assert!(!LifecycleState::Suspended.can_start());
    assert!(!LifecycleState::Stopping.can_start());
}

#[test]
fn test_lifecycle_state_can_stop() {
    assert!(!LifecycleState::Stopped.can_stop());
    assert!(!LifecycleState::Starting.can_stop());
    assert!(LifecycleState::Running.can_stop());
    assert!(LifecycleState::Suspended.can_stop());
    assert!(!LifecycleState::Stopping.can_stop());
    assert!(!LifecycleState::Failed.can_stop());
}

#[test]
fn test_lifecycle_state_can_suspend() {
    assert!(!LifecycleState::Stopped.can_suspend());
    assert!(!LifecycleState::Starting.can_suspend());
    assert!(LifecycleState::Running.can_suspend());
    assert!(!LifecycleState::Suspended.can_suspend());
    assert!(!LifecycleState::Stopping.can_suspend());
    assert!(!LifecycleState::Failed.can_suspend());
}

#[test]
fn test_lifecycle_state_can_resume() {
    assert!(!LifecycleState::Stopped.can_resume());
    assert!(!LifecycleState::Starting.can_resume());
    assert!(!LifecycleState::Running.can_resume());
    assert!(LifecycleState::Suspended.can_resume());
    assert!(!LifecycleState::Stopping.can_resume());
    assert!(!LifecycleState::Failed.can_resume());
}

#[test]
fn test_lifecycle_state_default() {
    let default: LifecycleState = Default::default();
    assert_eq!(default, LifecycleState::Stopped);
}

#[test]
fn test_lifecycle_state_display() {
    let state = LifecycleState::Running;
    let s = alloc::format!("{}", state);
    assert_eq!(s, "Running");
}

#[test]
fn test_lifecycle_state_equality() {
    assert_eq!(LifecycleState::Running, LifecycleState::Running);
    assert_ne!(LifecycleState::Running, LifecycleState::Stopped);
}

#[test]
fn test_lifecycle_state_clone() {
    let s1 = LifecycleState::Suspended;
    let s2 = s1.clone();
    assert_eq!(s1, s2);
}

#[test]
fn test_lifecycle_state_copy() {
    let s1 = LifecycleState::Starting;
    let s2 = s1;
    assert_eq!(s1, s2);
}

#[test]
fn test_lifecycle_state_repr() {
    assert_eq!(LifecycleState::Stopped as u8, 0);
    assert_eq!(LifecycleState::Starting as u8, 1);
    assert_eq!(LifecycleState::Running as u8, 2);
    assert_eq!(LifecycleState::Suspended as u8, 3);
    assert_eq!(LifecycleState::Stopping as u8, 4);
    assert_eq!(LifecycleState::Failed as u8, 5);
}

#[test]
fn test_app_event_started_app_id() {
    let event = AppEvent::Started {
        app_id: AppId::from_raw(42),
        name: String::from("TestApp"),
    };
    assert_eq!(event.app_id().as_u64(), 42);
}

#[test]
fn test_app_event_stopped_app_id() {
    let event = AppEvent::Stopped {
        app_id: AppId::from_raw(43),
        name: String::from("TestApp"),
    };
    assert_eq!(event.app_id().as_u64(), 43);
}

#[test]
fn test_app_event_suspended_app_id() {
    let event = AppEvent::Suspended {
        app_id: AppId::from_raw(44),
        name: String::from("TestApp"),
    };
    assert_eq!(event.app_id().as_u64(), 44);
}

#[test]
fn test_app_event_resumed_app_id() {
    let event = AppEvent::Resumed {
        app_id: AppId::from_raw(45),
        name: String::from("TestApp"),
    };
    assert_eq!(event.app_id().as_u64(), 45);
}

#[test]
fn test_app_event_failed_app_id() {
    let event = AppEvent::Failed {
        app_id: AppId::from_raw(46),
        name: String::from("TestApp"),
        reason: String::from("Error"),
    };
    assert_eq!(event.app_id().as_u64(), 46);
}

#[test]
fn test_app_event_permission_granted_app_id() {
    let event = AppEvent::PermissionGranted {
        app_id: AppId::from_raw(47),
        permission: 1,
    };
    assert_eq!(event.app_id().as_u64(), 47);
}

#[test]
fn test_app_event_permission_revoked_app_id() {
    let event = AppEvent::PermissionRevoked {
        app_id: AppId::from_raw(48),
        permission: 2,
    };
    assert_eq!(event.app_id().as_u64(), 48);
}

#[test]
fn test_app_event_name_started() {
    let event = AppEvent::Started {
        app_id: AppId::from_raw(1),
        name: String::from("Browser"),
    };
    assert_eq!(event.name(), Some("Browser"));
}

#[test]
fn test_app_event_name_stopped() {
    let event = AppEvent::Stopped {
        app_id: AppId::from_raw(1),
        name: String::from("Editor"),
    };
    assert_eq!(event.name(), Some("Editor"));
}

#[test]
fn test_app_event_name_suspended() {
    let event = AppEvent::Suspended {
        app_id: AppId::from_raw(1),
        name: String::from("Wallet"),
    };
    assert_eq!(event.name(), Some("Wallet"));
}

#[test]
fn test_app_event_name_resumed() {
    let event = AppEvent::Resumed {
        app_id: AppId::from_raw(1),
        name: String::from("Terminal"),
    };
    assert_eq!(event.name(), Some("Terminal"));
}

#[test]
fn test_app_event_name_failed() {
    let event = AppEvent::Failed {
        app_id: AppId::from_raw(1),
        name: String::from("Settings"),
        reason: String::from("Crash"),
    };
    assert_eq!(event.name(), Some("Settings"));
}

#[test]
fn test_app_event_name_permission_granted_is_none() {
    let event = AppEvent::PermissionGranted {
        app_id: AppId::from_raw(1),
        permission: 1,
    };
    assert_eq!(event.name(), None);
}

#[test]
fn test_app_event_name_permission_revoked_is_none() {
    let event = AppEvent::PermissionRevoked {
        app_id: AppId::from_raw(1),
        permission: 1,
    };
    assert_eq!(event.name(), None);
}

#[test]
fn test_event_queue_emit_and_poll() {
    clear_events();
    let event = AppEvent::Started {
        app_id: AppId::from_raw(100),
        name: String::from("TestApp"),
    };
    emit_event(event);
    let polled = poll_event();
    assert!(polled.is_some());
    let e = polled.unwrap();
    assert_eq!(e.app_id().as_u64(), 100);
    clear_events();
}

#[test]
fn test_event_queue_peek() {
    clear_events();
    let event = AppEvent::Stopped {
        app_id: AppId::from_raw(101),
        name: String::from("TestApp"),
    };
    emit_event(event);
    let peeked1 = peek_event();
    let peeked2 = peek_event();
    assert!(peeked1.is_some());
    assert!(peeked2.is_some());
    assert_eq!(peeked1.unwrap().app_id().as_u64(), peeked2.unwrap().app_id().as_u64());
    clear_events();
}

#[test]
fn test_event_queue_count() {
    clear_events();
    assert_eq!(event_count(), 0);
    emit_event(AppEvent::Started {
        app_id: AppId::from_raw(1),
        name: String::from("App1"),
    });
    assert_eq!(event_count(), 1);
    emit_event(AppEvent::Stopped {
        app_id: AppId::from_raw(2),
        name: String::from("App2"),
    });
    assert_eq!(event_count(), 2);
    clear_events();
}

#[test]
fn test_event_queue_clear() {
    clear_events();
    emit_event(AppEvent::Started {
        app_id: AppId::from_raw(1),
        name: String::from("App"),
    });
    emit_event(AppEvent::Stopped {
        app_id: AppId::from_raw(1),
        name: String::from("App"),
    });
    assert!(event_count() > 0);
    clear_events();
    assert_eq!(event_count(), 0);
}

#[test]
fn test_event_queue_poll_empty() {
    clear_events();
    assert!(poll_event().is_none());
}

#[test]
fn test_event_queue_peek_empty() {
    clear_events();
    assert!(peek_event().is_none());
}

#[test]
fn test_event_fifo_order() {
    clear_events();
    emit_event(AppEvent::Started {
        app_id: AppId::from_raw(1),
        name: String::from("First"),
    });
    emit_event(AppEvent::Started {
        app_id: AppId::from_raw(2),
        name: String::from("Second"),
    });
    emit_event(AppEvent::Started {
        app_id: AppId::from_raw(3),
        name: String::from("Third"),
    });
    assert_eq!(poll_event().unwrap().app_id().as_u64(), 1);
    assert_eq!(poll_event().unwrap().app_id().as_u64(), 2);
    assert_eq!(poll_event().unwrap().app_id().as_u64(), 3);
    assert!(poll_event().is_none());
}

#[test]
fn test_app_event_clone() {
    let event = AppEvent::Failed {
        app_id: AppId::from_raw(99),
        name: String::from("Crasher"),
        reason: String::from("Segfault"),
    };
    let cloned = event.clone();
    assert_eq!(event.app_id().as_u64(), cloned.app_id().as_u64());
}
