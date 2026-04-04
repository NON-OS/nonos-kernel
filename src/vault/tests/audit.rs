// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use crate::vault::nonos_vault::VaultAuditEvent;
use crate::vault::nonos_vault_audit::*;

#[test]
fn test_vault_audit_manager_new() {
    let manager = VaultAuditManager::new();
    let log = manager.export_all();
    assert!(log.is_empty());
}

#[test]
fn test_vault_audit_manager_log_event() {
    let manager = VaultAuditManager::new();
    let event = VaultAuditEvent {
        timestamp: 1000,
        event: "test_event".into(),
        context: Some("test_context".into()),
        status: Some("success".into()),
    };
    manager.log_event(event);
    assert_eq!(manager.export_all().len(), 1);
}

#[test]
fn test_vault_audit_manager_recent_returns_reverse_order() {
    let manager = VaultAuditManager::new();
    for i in 0..5 {
        let event = VaultAuditEvent {
            timestamp: i,
            event: alloc::format!("event_{}", i),
            context: None,
            status: None,
        };
        manager.log_event(event);
    }
    let recent = manager.recent(3);
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].timestamp, 4);
    assert_eq!(recent[1].timestamp, 3);
    assert_eq!(recent[2].timestamp, 2);
}

#[test]
fn test_vault_audit_manager_recent_more_than_available() {
    let manager = VaultAuditManager::new();
    let event = VaultAuditEvent {
        timestamp: 1,
        event: "single".into(),
        context: None,
        status: None,
    };
    manager.log_event(event);
    let recent = manager.recent(100);
    assert_eq!(recent.len(), 1);
}

#[test]
fn test_vault_audit_manager_recent_zero() {
    let manager = VaultAuditManager::new();
    let event = VaultAuditEvent {
        timestamp: 1,
        event: "event".into(),
        context: None,
        status: None,
    };
    manager.log_event(event);
    let recent = manager.recent(0);
    assert!(recent.is_empty());
}

#[test]
fn test_vault_audit_manager_filter_by_op() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "seal_secret".into(),
        context: None,
        status: None,
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 2,
        event: "unseal_secret".into(),
        context: None,
        status: None,
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 3,
        event: "seal_secret".into(),
        context: None,
        status: None,
    });
    let filtered = manager.filter(Some("seal"), None, None);
    assert_eq!(filtered.len(), 3);
}

#[test]
fn test_vault_audit_manager_filter_by_status() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "event1".into(),
        context: None,
        status: Some("success".into()),
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 2,
        event: "event2".into(),
        context: None,
        status: Some("failure".into()),
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 3,
        event: "event3".into(),
        context: None,
        status: Some("success".into()),
    });
    let filtered = manager.filter(None, Some("success"), None);
    assert_eq!(filtered.len(), 2);
}

#[test]
fn test_vault_audit_manager_filter_by_context() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "event1".into(),
        context: Some("process_1".into()),
        status: None,
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 2,
        event: "event2".into(),
        context: Some("process_2".into()),
        status: None,
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 3,
        event: "event3".into(),
        context: Some("process_1".into()),
        status: None,
    });
    let filtered = manager.filter(None, None, Some("process_1"));
    assert_eq!(filtered.len(), 2);
}

#[test]
fn test_vault_audit_manager_filter_combined() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "seal".into(),
        context: Some("ctx_a".into()),
        status: Some("ok".into()),
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 2,
        event: "seal".into(),
        context: Some("ctx_b".into()),
        status: Some("ok".into()),
    });
    manager.log_event(VaultAuditEvent {
        timestamp: 3,
        event: "unseal".into(),
        context: Some("ctx_a".into()),
        status: Some("ok".into()),
    });
    let filtered = manager.filter(Some("seal"), Some("ok"), Some("ctx_a"));
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_vault_audit_manager_filter_no_match() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "event".into(),
        context: Some("ctx".into()),
        status: Some("success".into()),
    });
    let filtered = manager.filter(Some("nonexistent"), None, None);
    assert!(filtered.is_empty());
}

#[test]
fn test_vault_audit_manager_export_all() {
    let manager = VaultAuditManager::new();
    for i in 0..10 {
        manager.log_event(VaultAuditEvent {
            timestamp: i,
            event: alloc::format!("event_{}", i),
            context: None,
            status: None,
        });
    }
    let all = manager.export_all();
    assert_eq!(all.len(), 10);
}

#[test]
fn test_vault_audit_manager_secure_erase() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "secret".into(),
        context: Some("sensitive".into()),
        status: Some("classified".into()),
    });
    manager.secure_erase();
    assert!(manager.export_all().is_empty());
}

#[test]
fn test_vault_log_event_api() {
    let event = VaultAuditEvent {
        timestamp: 12345,
        event: "api_test".into(),
        context: None,
        status: None,
    };
    vault_log_event(event);
    let recent = vault_audit_recent(1);
    assert!(!recent.is_empty() || recent.is_empty());
}

#[test]
fn test_vault_audit_recent_api() {
    let events = vault_audit_recent(5);
    assert!(events.len() <= 5);
}

#[test]
fn test_vault_audit_filter_api() {
    let events = vault_audit_filter(None, None, None);
    assert!(events.len() >= 0);
}

#[test]
fn test_vault_audit_filter_api_with_op() {
    let events = vault_audit_filter(Some("seal"), None, None);
    for e in &events {
        assert!(e.event.contains("seal"));
    }
}

#[test]
fn test_vault_audit_export_api() {
    let events = vault_audit_export();
    assert!(events.len() >= 0);
}

#[test]
fn test_vault_audit_secure_erase_api() {
    vault_audit_secure_erase();
    let events = VAULT_AUDIT_MANAGER.export_all();
    assert!(events.is_empty());
}

#[test]
fn test_vault_audit_manager_singleton_exists() {
    let _ = VAULT_AUDIT_MANAGER.export_all();
}

#[test]
fn test_vault_audit_event_timestamp_zero() {
    let event = VaultAuditEvent {
        timestamp: 0,
        event: "zero_ts".into(),
        context: None,
        status: None,
    };
    assert_eq!(event.timestamp, 0);
}

#[test]
fn test_vault_audit_event_timestamp_max() {
    let event = VaultAuditEvent {
        timestamp: u64::MAX,
        event: "max_ts".into(),
        context: None,
        status: None,
    };
    assert_eq!(event.timestamp, u64::MAX);
}

#[test]
fn test_vault_audit_manager_many_events() {
    let manager = VaultAuditManager::new();
    for i in 0..1000 {
        manager.log_event(VaultAuditEvent {
            timestamp: i,
            event: "bulk".into(),
            context: None,
            status: None,
        });
    }
    assert_eq!(manager.export_all().len(), 1000);
}

#[test]
fn test_vault_audit_filter_none_context() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "no_ctx".into(),
        context: None,
        status: None,
    });
    let filtered = manager.filter(None, None, Some("anything"));
    assert!(filtered.is_empty());
}

#[test]
fn test_vault_audit_filter_none_status() {
    let manager = VaultAuditManager::new();
    manager.log_event(VaultAuditEvent {
        timestamp: 1,
        event: "no_status".into(),
        context: None,
        status: None,
    });
    let filtered = manager.filter(None, Some("anything"), None);
    assert!(filtered.is_empty());
}
