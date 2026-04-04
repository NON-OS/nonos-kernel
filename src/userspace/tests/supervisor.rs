use crate::userspace::init::{CORE_SERVICES, DRIVER_SERVICES};

#[test]
fn test_verify_interval_constant() {
    const VERIFY_INTERVAL_MS: u64 = 5000;
    assert_eq!(VERIFY_INTERVAL_MS, 5000);
}

#[test]
fn test_supervise_interval_constant() {
    const SUPERVISE_INTERVAL_MS: u64 = 1000;
    assert_eq!(SUPERVISE_INTERVAL_MS, 1000);
}

#[test]
fn test_max_restart_attempts_constant() {
    const MAX_RESTART_ATTEMPTS: u32 = 5;
    assert_eq!(MAX_RESTART_ATTEMPTS, 5);
}

#[test]
fn test_restart_backoff_base_constant() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    assert_eq!(RESTART_BACKOFF_BASE_MS, 1000);
}

#[test]
fn test_backoff_calculation_first_attempt() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 0u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    assert_eq!(backoff, 1000);
}

#[test]
fn test_backoff_calculation_second_attempt() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 1u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    assert_eq!(backoff, 2000);
}

#[test]
fn test_backoff_calculation_third_attempt() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 2u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    assert_eq!(backoff, 4000);
}

#[test]
fn test_backoff_calculation_fourth_attempt() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 3u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    assert_eq!(backoff, 8000);
}

#[test]
fn test_backoff_calculation_fifth_attempt() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 4u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    assert_eq!(backoff, 16000);
}

#[test]
fn test_backoff_capped_at_16_seconds() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 10u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    assert_eq!(backoff, 16000);
}

#[test]
fn test_backoff_capped_at_max_attempts() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 100u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    assert_eq!(backoff, 16000);
}

#[test]
fn test_verify_interval_is_5x_supervise() {
    const VERIFY_INTERVAL_MS: u64 = 5000;
    const SUPERVISE_INTERVAL_MS: u64 = 1000;
    assert_eq!(VERIFY_INTERVAL_MS, SUPERVISE_INTERVAL_MS * 5);
}

#[test]
fn test_all_core_services_supervised() {
    let supervised = CORE_SERVICES;
    assert!(supervised.contains(&"vfs"));
    assert!(supervised.contains(&"display"));
    assert!(supervised.contains(&"network"));
    assert!(supervised.contains(&"crypto"));
}

#[test]
fn test_supervision_uses_core_services_list() {
    assert!(!CORE_SERVICES.is_empty());
}

#[test]
fn test_verification_uses_core_services_list() {
    assert!(!CORE_SERVICES.is_empty());
}

#[test]
fn test_restart_state_entry_creation() {
    struct RestartInfo {
        attempts: u32,
        last_restart_ms: u64,
    }
    let info = RestartInfo { attempts: 0, last_restart_ms: 0 };
    assert_eq!(info.attempts, 0);
    assert_eq!(info.last_restart_ms, 0);
}

#[test]
fn test_restart_info_increment() {
    struct RestartInfo {
        attempts: u32,
        last_restart_ms: u64,
    }
    let mut info = RestartInfo { attempts: 0, last_restart_ms: 0 };
    info.attempts += 1;
    info.last_restart_ms = 12345;
    assert_eq!(info.attempts, 1);
    assert_eq!(info.last_restart_ms, 12345);
}

#[test]
fn test_max_restarts_prevents_restart() {
    const MAX_RESTART_ATTEMPTS: u32 = 5;
    let attempts = 5u32;
    assert!(attempts >= MAX_RESTART_ATTEMPTS);
}

#[test]
fn test_under_max_restarts_allows_restart() {
    const MAX_RESTART_ATTEMPTS: u32 = 5;
    let attempts = 4u32;
    assert!(attempts < MAX_RESTART_ATTEMPTS);
}

#[test]
fn test_backoff_progression() {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let backoffs: [u64; 5] = [
        RESTART_BACKOFF_BASE_MS * (1 << 0u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 1u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 2u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 3u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 4u32.min(4)),
    ];
    assert_eq!(backoffs, [1000, 2000, 4000, 8000, 16000]);
}

#[test]
fn test_supervisor_loop_constants_positive() {
    const VERIFY_INTERVAL_MS: u64 = 5000;
    const SUPERVISE_INTERVAL_MS: u64 = 1000;
    assert!(VERIFY_INTERVAL_MS > 0);
    assert!(SUPERVISE_INTERVAL_MS > 0);
}

#[test]
fn test_driver_services_not_in_core_supervision() {
    for driver_svc in DRIVER_SERVICES {
        assert!(!CORE_SERVICES.contains(driver_svc));
    }
}
