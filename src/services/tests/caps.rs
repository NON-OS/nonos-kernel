use crate::services::*;
use crate::services::caps::{CAP_PROCESS, CAP_MEMORY};

#[test]
fn test_cap_vfs_bit_value() {
    assert_eq!(CAP_VFS, 1 << 0);
}

#[test]
fn test_cap_net_bit_value() {
    assert_eq!(CAP_NET, 1 << 1);
}

#[test]
fn test_cap_display_bit_value() {
    assert_eq!(CAP_DISPLAY, 1 << 2);
}

#[test]
fn test_cap_driver_bit_value() {
    assert_eq!(CAP_DRIVER, 1 << 3);
}

#[test]
fn test_cap_crypto_bit_value() {
    assert_eq!(CAP_CRYPTO, 1 << 4);
}

#[test]
fn test_cap_process_bit_value() {
    assert_eq!(CAP_PROCESS, 1 << 5);
}

#[test]
fn test_cap_memory_bit_value() {
    assert_eq!(CAP_MEMORY, 1 << 6);
}

#[test]
fn test_cap_input_bit_value() {
    assert_eq!(CAP_INPUT, 1 << 7);
}

#[test]
fn test_cap_audio_bit_value() {
    assert_eq!(CAP_AUDIO, 1 << 8);
}

#[test]
fn test_cap_zk_bit_value() {
    assert_eq!(CAP_ZK, 1 << 9);
}

#[test]
fn test_cap_gpu_bit_value() {
    assert_eq!(CAP_GPU, 1 << 10);
}

#[test]
fn test_cap_apps_bit_value() {
    assert_eq!(CAP_APPS, 1 << 11);
}

#[test]
fn test_cap_agents_bit_value() {
    assert_eq!(CAP_AGENTS, 1 << 12);
}

#[test]
fn test_cap_shell_bit_value() {
    assert_eq!(CAP_SHELL, 1 << 13);
}

#[test]
fn test_cap_admin_bit_value() {
    assert_eq!(CAP_ADMIN, 1 << 63);
}

#[test]
fn test_cap_bits_are_powers_of_two() {
    assert!(CAP_VFS.is_power_of_two());
    assert!(CAP_NET.is_power_of_two());
    assert!(CAP_DISPLAY.is_power_of_two());
    assert!(CAP_DRIVER.is_power_of_two());
    assert!(CAP_CRYPTO.is_power_of_two());
    assert!(CAP_INPUT.is_power_of_two());
    assert!(CAP_AUDIO.is_power_of_two());
    assert!(CAP_ZK.is_power_of_two());
    assert!(CAP_GPU.is_power_of_two());
    assert!(CAP_APPS.is_power_of_two());
    assert!(CAP_AGENTS.is_power_of_two());
    assert!(CAP_SHELL.is_power_of_two());
    assert!(CAP_ADMIN.is_power_of_two());
}

#[test]
fn test_cap_bits_are_unique() {
    let caps = [
        CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO,
        CAP_PROCESS, CAP_MEMORY, CAP_INPUT, CAP_AUDIO, CAP_ZK,
        CAP_GPU, CAP_APPS, CAP_AGENTS, CAP_SHELL, CAP_ADMIN,
    ];
    for i in 0..caps.len() {
        for j in (i + 1)..caps.len() {
            assert_ne!(caps[i], caps[j]);
        }
    }
}

#[test]
fn test_service_cap_new() {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 42);
    assert_eq!(cap.bits, CAP_VFS | CAP_NET);
    assert_eq!(cap.owner_pid, 42);
    assert_eq!(cap.expires_ms, 0);
}

#[test]
fn test_service_cap_with_expiry() {
    let cap = ServiceCap::with_expiry(CAP_CRYPTO, 100, 5000);
    assert_eq!(cap.bits, CAP_CRYPTO);
    assert_eq!(cap.owner_pid, 100);
    assert_eq!(cap.expires_ms, 5000);
}

#[test]
fn test_service_cap_has_single_cap() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    assert!(cap.has(CAP_VFS));
    assert!(!cap.has(CAP_NET));
}

#[test]
fn test_service_cap_has_multiple_caps() {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET | CAP_CRYPTO, 1);
    assert!(cap.has(CAP_VFS));
    assert!(cap.has(CAP_NET));
    assert!(cap.has(CAP_CRYPTO));
    assert!(!cap.has(CAP_INPUT));
}

#[test]
fn test_service_cap_has_combined_caps() {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    assert!(cap.has(CAP_VFS | CAP_NET));
}

#[test]
fn test_service_cap_has_zero_cap_always_true() {
    let cap = ServiceCap::new(0, 1);
    assert!(cap.has(0));
}

#[test]
fn test_service_cap_has_partial_caps_fails() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    assert!(!cap.has(CAP_VFS | CAP_NET));
}

#[test]
fn test_service_cap_is_expired_zero_never_expires() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    assert!(!cap.is_expired(0));
    assert!(!cap.is_expired(u64::MAX));
}

#[test]
fn test_service_cap_is_expired_before_expiry() {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 1000);
    assert!(!cap.is_expired(500));
    assert!(!cap.is_expired(999));
    assert!(!cap.is_expired(1000));
}

#[test]
fn test_service_cap_is_expired_after_expiry() {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 1000);
    assert!(cap.is_expired(1001));
    assert!(cap.is_expired(2000));
}

#[test]
fn test_service_cap_clone() {
    let cap = ServiceCap::new(CAP_NET, 42);
    let cloned = cap.clone();
    assert_eq!(cap.bits, cloned.bits);
    assert_eq!(cap.owner_pid, cloned.owner_pid);
    assert_eq!(cap.expires_ms, cloned.expires_ms);
}

#[test]
fn test_service_cap_copy() {
    let cap = ServiceCap::new(CAP_CRYPTO, 99);
    let copied: ServiceCap = cap;
    assert_eq!(cap.bits, copied.bits);
}

#[test]
fn test_service_cap_equality() {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_VFS, 1);
    let cap3 = ServiceCap::new(CAP_NET, 1);
    assert_eq!(cap1, cap2);
    assert_ne!(cap1, cap3);
}

#[test]
fn test_service_cap_debug_format() {
    let cap = ServiceCap::new(CAP_VFS, 42);
    let debug_str = alloc::format!("{:?}", cap);
    assert!(debug_str.contains("ServiceCap"));
    assert!(debug_str.contains("bits"));
    assert!(debug_str.contains("owner_pid"));
}

#[test]
fn test_cap_error_variants_exist() {
    let _no_cap = CapError::NoCap;
    let _insufficient = CapError::InsufficientCaps;
    let _expired = CapError::Expired;
    let _not_found = CapError::ServiceNotFound;
}

#[test]
fn test_cap_error_equality() {
    assert_eq!(CapError::NoCap, CapError::NoCap);
    assert_eq!(CapError::InsufficientCaps, CapError::InsufficientCaps);
    assert_eq!(CapError::Expired, CapError::Expired);
    assert_eq!(CapError::ServiceNotFound, CapError::ServiceNotFound);
    assert_ne!(CapError::NoCap, CapError::Expired);
}

#[test]
fn test_cap_error_clone() {
    let err = CapError::InsufficientCaps;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_cap_error_copy() {
    let err = CapError::Expired;
    let copied: CapError = err;
    assert_eq!(err, copied);
}

#[test]
fn test_cap_error_debug_format() {
    let err = CapError::ServiceNotFound;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("ServiceNotFound"));
}

#[test]
fn test_caps_can_be_combined_with_or() {
    let combined = CAP_VFS | CAP_NET | CAP_CRYPTO;
    assert_eq!(combined, (1 << 0) | (1 << 1) | (1 << 4));
}

#[test]
fn test_caps_can_be_checked_with_and() {
    let combined = CAP_VFS | CAP_NET;
    assert_eq!(combined & CAP_VFS, CAP_VFS);
    assert_eq!(combined & CAP_CRYPTO, 0);
}

#[test]
fn test_service_cap_with_all_standard_caps() {
    let all = CAP_VFS | CAP_NET | CAP_DISPLAY | CAP_DRIVER | CAP_CRYPTO |
              CAP_INPUT | CAP_AUDIO | CAP_ZK | CAP_GPU | CAP_APPS |
              CAP_AGENTS | CAP_SHELL;
    let cap = ServiceCap::new(all, 1);
    assert!(cap.has(CAP_VFS));
    assert!(cap.has(CAP_NET));
    assert!(cap.has(CAP_DISPLAY));
    assert!(cap.has(CAP_DRIVER));
    assert!(cap.has(CAP_CRYPTO));
    assert!(cap.has(CAP_INPUT));
    assert!(cap.has(CAP_AUDIO));
    assert!(cap.has(CAP_ZK));
    assert!(cap.has(CAP_GPU));
    assert!(cap.has(CAP_APPS));
    assert!(cap.has(CAP_AGENTS));
    assert!(cap.has(CAP_SHELL));
    assert!(!cap.has(CAP_ADMIN));
}

#[test]
fn test_service_cap_admin_is_separate() {
    let cap = ServiceCap::new(CAP_ADMIN, 1);
    assert!(cap.has(CAP_ADMIN));
    assert!(!cap.has(CAP_VFS));
    assert!(!cap.has(CAP_NET));
}

#[test]
fn test_service_cap_zero_bits_has_nothing() {
    let cap = ServiceCap::new(0, 1);
    assert!(!cap.has(CAP_VFS));
    assert!(!cap.has(CAP_NET));
    assert!(!cap.has(CAP_ADMIN));
}

#[test]
fn test_service_cap_max_bits() {
    let cap = ServiceCap::new(u64::MAX, 1);
    assert!(cap.has(CAP_VFS));
    assert!(cap.has(CAP_ADMIN));
    assert!(cap.has(u64::MAX));
}
