use crate::userspace::*;
use crate::userspace::init::{CORE_SERVICES, DRIVER_SERVICES};

#[test]
fn test_core_services_not_empty() {
    assert!(!CORE_SERVICES.is_empty());
}

#[test]
fn test_driver_services_not_empty() {
    assert!(!DRIVER_SERVICES.is_empty());
}

#[test]
fn test_core_services_contains_vfs() {
    assert!(CORE_SERVICES.contains(&"vfs"));
}

#[test]
fn test_core_services_contains_display() {
    assert!(CORE_SERVICES.contains(&"display"));
}

#[test]
fn test_core_services_contains_input() {
    assert!(CORE_SERVICES.contains(&"input"));
}

#[test]
fn test_core_services_contains_network() {
    assert!(CORE_SERVICES.contains(&"network"));
}

#[test]
fn test_core_services_contains_crypto() {
    assert!(CORE_SERVICES.contains(&"crypto"));
}

#[test]
fn test_core_services_contains_zk() {
    assert!(CORE_SERVICES.contains(&"zk"));
}

#[test]
fn test_core_services_contains_audio() {
    assert!(CORE_SERVICES.contains(&"audio"));
}

#[test]
fn test_core_services_contains_gpu() {
    assert!(CORE_SERVICES.contains(&"gpu"));
}

#[test]
fn test_core_services_contains_apps() {
    assert!(CORE_SERVICES.contains(&"apps"));
}

#[test]
fn test_core_services_contains_agents() {
    assert!(CORE_SERVICES.contains(&"agents"));
}

#[test]
fn test_core_services_contains_shell() {
    assert!(CORE_SERVICES.contains(&"shell"));
}

#[test]
fn test_core_services_contains_desktop() {
    assert!(CORE_SERVICES.contains(&"desktop"));
}

#[test]
fn test_driver_services_contains_drivers() {
    assert!(DRIVER_SERVICES.contains(&"drivers"));
}

#[test]
fn test_core_services_count() {
    assert_eq!(CORE_SERVICES.len(), 12);
}

#[test]
fn test_driver_services_count() {
    assert_eq!(DRIVER_SERVICES.len(), 1);
}

#[test]
fn test_run_init_exported() {
    let _: fn() -> ! = run_init;
}
