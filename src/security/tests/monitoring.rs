// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::security::monitoring::monitor::{
    SecurityEventType, SecurityEvent, MonitorStats, log_event, get_recent_events,
    get_stats, set_enabled, is_enabled,
};
use alloc::string::String;
use alloc::vec;

#[test]
fn test_security_event_type_suspicious_memory() {
    let event_type = SecurityEventType::SuspiciousMemoryAccess;
    assert_eq!(event_type, SecurityEventType::SuspiciousMemoryAccess);
}

#[test]
fn test_security_event_type_unauthorized_network() {
    let event_type = SecurityEventType::UnauthorizedNetworkAccess;
    assert_eq!(event_type, SecurityEventType::UnauthorizedNetworkAccess);
}

#[test]
fn test_security_event_type_process_anomaly() {
    let event_type = SecurityEventType::ProcessAnomaly;
    assert_eq!(event_type, SecurityEventType::ProcessAnomaly);
}

#[test]
fn test_security_event_type_hardware_tamper() {
    let event_type = SecurityEventType::HardwareTamper;
    assert_eq!(event_type, SecurityEventType::HardwareTamper);
}

#[test]
fn test_security_event_type_privilege_escalation() {
    let event_type = SecurityEventType::PrivilegeEscalation;
    assert_eq!(event_type, SecurityEventType::PrivilegeEscalation);
}

#[test]
fn test_security_event_type_syscall_anomaly() {
    let event_type = SecurityEventType::SyscallAnomaly;
    assert_eq!(event_type, SecurityEventType::SyscallAnomaly);
}

#[test]
fn test_security_event_type_filesystem_violation() {
    let event_type = SecurityEventType::FilesystemViolation;
    assert_eq!(event_type, SecurityEventType::FilesystemViolation);
}

#[test]
fn test_security_event_type_capability_abuse() {
    let event_type = SecurityEventType::CapabilityAbuse;
    assert_eq!(event_type, SecurityEventType::CapabilityAbuse);
}

#[test]
fn test_security_event_type_privacy_violation() {
    let event_type = SecurityEventType::PrivacyViolation;
    assert_eq!(event_type, SecurityEventType::PrivacyViolation);
}

#[test]
fn test_security_event_type_rootkit_detection() {
    let event_type = SecurityEventType::RootkitDetection;
    assert_eq!(event_type, SecurityEventType::RootkitDetection);
}

#[test]
fn test_security_event_type_integrity_breach() {
    let event_type = SecurityEventType::IntegrityBreach;
    assert_eq!(event_type, SecurityEventType::IntegrityBreach);
}

#[test]
fn test_security_event_type_equality() {
    assert_eq!(SecurityEventType::SuspiciousMemoryAccess, SecurityEventType::SuspiciousMemoryAccess);
    assert_ne!(SecurityEventType::SuspiciousMemoryAccess, SecurityEventType::RootkitDetection);
}

#[test]
fn test_security_event_type_clone() {
    let et1 = SecurityEventType::ProcessAnomaly;
    let et2 = et1.clone();
    assert_eq!(et1, et2);
}

#[test]
fn test_security_event_type_copy() {
    let et1 = SecurityEventType::HardwareTamper;
    let et2 = et1;
    assert_eq!(et1, et2);
}

#[test]
fn test_security_event_fields() {
    let event = SecurityEvent {
        timestamp: 1000,
        event_type: SecurityEventType::SuspiciousMemoryAccess,
        severity: 3,
        description: String::from("Test event"),
        process_id: Some(123),
        module: Some(String::from("test_module")),
        extra_tags: Some(vec![String::from("tag1")]),
    };
    assert_eq!(event.timestamp, 1000);
    assert_eq!(event.event_type, SecurityEventType::SuspiciousMemoryAccess);
    assert_eq!(event.severity, 3);
    assert_eq!(event.description, "Test event");
    assert_eq!(event.process_id, Some(123));
}

#[test]
fn test_security_event_minimal() {
    let event = SecurityEvent {
        timestamp: 0,
        event_type: SecurityEventType::IntegrityBreach,
        severity: 0,
        description: String::new(),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    assert!(event.process_id.is_none());
    assert!(event.module.is_none());
    assert!(event.extra_tags.is_none());
}

#[test]
fn test_security_event_clone() {
    let event = SecurityEvent {
        timestamp: 500,
        event_type: SecurityEventType::PrivilegeEscalation,
        severity: 4,
        description: String::from("Clone test"),
        process_id: Some(456),
        module: None,
        extra_tags: None,
    };
    let cloned = event.clone();
    assert_eq!(event.timestamp, cloned.timestamp);
    assert_eq!(event.event_type, cloned.event_type);
    assert_eq!(event.severity, cloned.severity);
}

#[test]
fn test_log_event() {
    log_event(
        SecurityEventType::SuspiciousMemoryAccess,
        1,
        String::from("Test log event"),
        Some(1),
        Some(String::from("test")),
        None,
    );
}

#[test]
fn test_log_event_minimal() {
    log_event(
        SecurityEventType::IntegrityBreach,
        0,
        String::from("Minimal"),
        None,
        None,
        None,
    );
}

#[test]
fn test_log_event_high_severity() {
    log_event(
        SecurityEventType::RootkitDetection,
        4,
        String::from("Critical event"),
        Some(999),
        Some(String::from("security")),
        Some(vec![String::from("rootkit"), String::from("alert")]),
    );
}

#[test]
fn test_get_recent_events() {
    let events = get_recent_events(10);
    let _ = events.len();
}

#[test]
fn test_get_recent_events_zero() {
    let events = get_recent_events(0);
    assert!(events.is_empty());
}

#[test]
fn test_get_stats() {
    let stats = get_stats();
    let _ = stats.total_events.load(core::sync::atomic::Ordering::Relaxed);
}

#[test]
fn test_set_enabled_true() {
    set_enabled(true);
    assert!(is_enabled());
}

#[test]
fn test_set_enabled_false() {
    set_enabled(false);
    assert!(!is_enabled());
    set_enabled(true);
}

#[test]
fn test_is_enabled() {
    let _ = is_enabled();
}

#[test]
fn test_security_event_type_all_variants() {
    let types = [
        SecurityEventType::SuspiciousMemoryAccess,
        SecurityEventType::UnauthorizedNetworkAccess,
        SecurityEventType::ProcessAnomaly,
        SecurityEventType::HardwareTamper,
        SecurityEventType::PrivilegeEscalation,
        SecurityEventType::SyscallAnomaly,
        SecurityEventType::FilesystemViolation,
        SecurityEventType::CapabilityAbuse,
        SecurityEventType::PrivacyViolation,
        SecurityEventType::RootkitDetection,
        SecurityEventType::IntegrityBreach,
    ];
    assert_eq!(types.len(), 11);
}

#[test]
fn test_security_event_type_all_unique() {
    let types = [
        SecurityEventType::SuspiciousMemoryAccess,
        SecurityEventType::UnauthorizedNetworkAccess,
        SecurityEventType::ProcessAnomaly,
        SecurityEventType::HardwareTamper,
        SecurityEventType::PrivilegeEscalation,
        SecurityEventType::SyscallAnomaly,
        SecurityEventType::FilesystemViolation,
        SecurityEventType::CapabilityAbuse,
        SecurityEventType::PrivacyViolation,
        SecurityEventType::RootkitDetection,
        SecurityEventType::IntegrityBreach,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn test_security_event_type_debug() {
    let et = SecurityEventType::RootkitDetection;
    let debug_str = alloc::format!("{:?}", et);
    assert!(debug_str.contains("RootkitDetection"));
}

#[test]
fn test_security_event_debug() {
    let event = SecurityEvent {
        timestamp: 100,
        event_type: SecurityEventType::ProcessAnomaly,
        severity: 2,
        description: String::from("Debug test"),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    let debug_str = alloc::format!("{:?}", event);
    assert!(debug_str.contains("SecurityEvent"));
}

#[test]
fn test_security_event_severity_range() {
    for severity in 0..=4 {
        log_event(
            SecurityEventType::IntegrityBreach,
            severity,
            String::from("Severity test"),
            None,
            None,
            None,
        );
    }
}

#[test]
fn test_log_multiple_events() {
    for i in 0..5 {
        log_event(
            SecurityEventType::SuspiciousMemoryAccess,
            1,
            alloc::format!("Event {}", i),
            Some(i as u64),
            None,
            None,
        );
    }
}

#[test]
fn test_security_event_with_all_tags() {
    let event = SecurityEvent {
        timestamp: 200,
        event_type: SecurityEventType::CapabilityAbuse,
        severity: 3,
        description: String::from("With tags"),
        process_id: Some(100),
        module: Some(String::from("capabilities")),
        extra_tags: Some(vec![
            String::from("abuse"),
            String::from("violation"),
            String::from("critical"),
        ]),
    };
    assert_eq!(event.extra_tags.as_ref().unwrap().len(), 3);
}

#[test]
fn test_enabled_toggle() {
    let original = is_enabled();
    set_enabled(!original);
    assert_ne!(is_enabled(), original);
    set_enabled(original);
    assert_eq!(is_enabled(), original);
}

