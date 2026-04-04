use crate::userspace::init::spawner::cap_for_service;
use crate::services::caps::{
    ServiceCap, CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO,
    CAP_PROCESS, CAP_MEMORY, CAP_INPUT, CAP_AUDIO, CAP_ZK, CAP_GPU,
    CAP_APPS, CAP_AGENTS, CAP_SHELL, CAP_ADMIN,
};

#[test]
fn test_cap_vfs_is_bit_0() {
    assert_eq!(CAP_VFS, 1 << 0);
}

#[test]
fn test_cap_net_is_bit_1() {
    assert_eq!(CAP_NET, 1 << 1);
}

#[test]
fn test_cap_display_is_bit_2() {
    assert_eq!(CAP_DISPLAY, 1 << 2);
}

#[test]
fn test_cap_driver_is_bit_3() {
    assert_eq!(CAP_DRIVER, 1 << 3);
}

#[test]
fn test_cap_crypto_is_bit_4() {
    assert_eq!(CAP_CRYPTO, 1 << 4);
}

#[test]
fn test_cap_process_is_bit_5() {
    assert_eq!(CAP_PROCESS, 1 << 5);
}

#[test]
fn test_cap_memory_is_bit_6() {
    assert_eq!(CAP_MEMORY, 1 << 6);
}

#[test]
fn test_cap_input_is_bit_7() {
    assert_eq!(CAP_INPUT, 1 << 7);
}

#[test]
fn test_cap_audio_is_bit_8() {
    assert_eq!(CAP_AUDIO, 1 << 8);
}

#[test]
fn test_cap_zk_is_bit_9() {
    assert_eq!(CAP_ZK, 1 << 9);
}

#[test]
fn test_cap_gpu_is_bit_10() {
    assert_eq!(CAP_GPU, 1 << 10);
}

#[test]
fn test_cap_apps_is_bit_11() {
    assert_eq!(CAP_APPS, 1 << 11);
}

#[test]
fn test_cap_agents_is_bit_12() {
    assert_eq!(CAP_AGENTS, 1 << 12);
}

#[test]
fn test_cap_shell_is_bit_13() {
    assert_eq!(CAP_SHELL, 1 << 13);
}

#[test]
fn test_cap_admin_is_bit_63() {
    assert_eq!(CAP_ADMIN, 1 << 63);
}

#[test]
fn test_all_caps_unique() {
    let caps = [
        CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO,
        CAP_PROCESS, CAP_MEMORY, CAP_INPUT, CAP_AUDIO, CAP_ZK,
        CAP_GPU, CAP_APPS, CAP_AGENTS, CAP_SHELL, CAP_ADMIN,
    ];
    for (i, &cap1) in caps.iter().enumerate() {
        for (j, &cap2) in caps.iter().enumerate() {
            if i != j {
                assert_ne!(cap1, cap2);
            }
        }
    }
}

#[test]
fn test_caps_are_powers_of_two() {
    let caps = [
        CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO,
        CAP_PROCESS, CAP_MEMORY, CAP_INPUT, CAP_AUDIO, CAP_ZK,
        CAP_GPU, CAP_APPS, CAP_AGENTS, CAP_SHELL, CAP_ADMIN,
    ];
    for cap in caps {
        assert!(cap.is_power_of_two());
    }
}

#[test]
fn test_caps_no_overlap() {
    let caps = [
        CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO,
        CAP_PROCESS, CAP_MEMORY, CAP_INPUT, CAP_AUDIO, CAP_ZK,
        CAP_GPU, CAP_APPS, CAP_AGENTS, CAP_SHELL, CAP_ADMIN,
    ];
    for (i, &cap1) in caps.iter().enumerate() {
        for (j, &cap2) in caps.iter().enumerate() {
            if i != j {
                assert_eq!(cap1 & cap2, 0);
            }
        }
    }
}

#[test]
fn test_service_cap_new() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    assert_eq!(cap.bits, CAP_VFS);
    assert_eq!(cap.owner_pid, 1);
    assert_eq!(cap.expires_ms, 0);
}

#[test]
fn test_service_cap_with_expiry() {
    let cap = ServiceCap::with_expiry(CAP_NET, 2, 10000);
    assert_eq!(cap.bits, CAP_NET);
    assert_eq!(cap.owner_pid, 2);
    assert_eq!(cap.expires_ms, 10000);
}

#[test]
fn test_service_cap_has() {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    assert!(cap.has(CAP_VFS));
    assert!(cap.has(CAP_NET));
    assert!(!cap.has(CAP_DISPLAY));
}

#[test]
fn test_service_cap_has_all() {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET | CAP_DISPLAY, 1);
    assert!(cap.has(CAP_VFS | CAP_NET));
    assert!(cap.has(CAP_VFS | CAP_NET | CAP_DISPLAY));
}

#[test]
fn test_service_cap_has_partial() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    assert!(!cap.has(CAP_VFS | CAP_NET));
}

#[test]
fn test_service_cap_is_expired_zero() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    assert!(!cap.is_expired(10000));
}

#[test]
fn test_service_cap_is_expired_not_yet() {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 10000);
    assert!(!cap.is_expired(5000));
}

#[test]
fn test_service_cap_is_expired_past() {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 10000);
    assert!(cap.is_expired(15000));
}

#[test]
fn test_service_cap_is_expired_exact() {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 10000);
    assert!(!cap.is_expired(10000));
}

#[test]
fn test_service_cap_debug() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    let debug_str = alloc::format!("{:?}", cap);
    assert!(debug_str.contains("ServiceCap"));
}

#[test]
fn test_service_cap_clone() {
    let cap = ServiceCap::new(CAP_NET, 2);
    let cloned = cap.clone();
    assert_eq!(cap.bits, cloned.bits);
    assert_eq!(cap.owner_pid, cloned.owner_pid);
}

#[test]
fn test_service_cap_copy() {
    let cap = ServiceCap::new(CAP_DISPLAY, 3);
    let copied: ServiceCap = cap;
    assert_eq!(cap.bits, copied.bits);
}

#[test]
fn test_service_cap_partial_eq() {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_VFS, 1);
    assert_eq!(cap1, cap2);
}

#[test]
fn test_service_cap_not_equal_different_bits() {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_NET, 1);
    assert_ne!(cap1, cap2);
}

#[test]
fn test_service_cap_not_equal_different_owner() {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_VFS, 2);
    assert_ne!(cap1, cap2);
}

#[test]
fn test_vfs_service_gets_vfs_cap() {
    let caps = cap_for_service("vfs");
    assert_ne!(caps & CAP_VFS, 0);
}

#[test]
fn test_network_service_gets_net_cap() {
    let caps = cap_for_service("network");
    assert_ne!(caps & CAP_NET, 0);
}

#[test]
fn test_display_service_gets_display_cap() {
    let caps = cap_for_service("display");
    assert_ne!(caps & CAP_DISPLAY, 0);
}

#[test]
fn test_crypto_service_gets_crypto_cap() {
    let caps = cap_for_service("crypto");
    assert_ne!(caps & CAP_CRYPTO, 0);
}

#[test]
fn test_desktop_service_gets_both_caps() {
    let caps = cap_for_service("desktop");
    assert_ne!(caps & CAP_DISPLAY, 0);
    assert_ne!(caps & CAP_INPUT, 0);
}

#[test]
fn test_services_get_only_needed_caps() {
    let vfs_caps = cap_for_service("vfs");
    assert_eq!(vfs_caps & CAP_NET, 0);
    assert_eq!(vfs_caps & CAP_DISPLAY, 0);
    assert_eq!(vfs_caps & CAP_ADMIN, 0);
}

#[test]
fn test_unknown_service_gets_no_caps() {
    let caps = cap_for_service("unknown");
    assert_eq!(caps, 0);
}
