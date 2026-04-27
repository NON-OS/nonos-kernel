use crate::services::caps::{
    ServiceCap, CAP_ADMIN, CAP_AGENTS, CAP_APPS, CAP_AUDIO, CAP_CRYPTO, CAP_DISPLAY, CAP_DRIVER,
    CAP_GPU, CAP_INPUT, CAP_MEMORY, CAP_NET, CAP_PROCESS, CAP_SHELL, CAP_VFS, CAP_ZK,
};
use crate::test::framework::TestResult;
use crate::userspace::init::spawner::cap_for_service;

pub(crate) fn test_cap_vfs_is_bit_0() -> TestResult {
    if CAP_VFS != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_net_is_bit_1() -> TestResult {
    if CAP_NET != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_display_is_bit_2() -> TestResult {
    if CAP_DISPLAY != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_driver_is_bit_3() -> TestResult {
    if CAP_DRIVER != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_crypto_is_bit_4() -> TestResult {
    if CAP_CRYPTO != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_process_is_bit_5() -> TestResult {
    if CAP_PROCESS != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_memory_is_bit_6() -> TestResult {
    if CAP_MEMORY != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_input_is_bit_7() -> TestResult {
    if CAP_INPUT != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_audio_is_bit_8() -> TestResult {
    if CAP_AUDIO != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_zk_is_bit_9() -> TestResult {
    if CAP_ZK != 1 << 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_gpu_is_bit_10() -> TestResult {
    if CAP_GPU != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_apps_is_bit_11() -> TestResult {
    if CAP_APPS != 1 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_agents_is_bit_12() -> TestResult {
    if CAP_AGENTS != 1 << 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_shell_is_bit_13() -> TestResult {
    if CAP_SHELL != 1 << 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_admin_is_bit_63() -> TestResult {
    if CAP_ADMIN != 1 << 63 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_caps_unique() -> TestResult {
    let caps = [
        CAP_VFS,
        CAP_NET,
        CAP_DISPLAY,
        CAP_DRIVER,
        CAP_CRYPTO,
        CAP_PROCESS,
        CAP_MEMORY,
        CAP_INPUT,
        CAP_AUDIO,
        CAP_ZK,
        CAP_GPU,
        CAP_APPS,
        CAP_AGENTS,
        CAP_SHELL,
        CAP_ADMIN,
    ];
    for (i, &cap1) in caps.iter().enumerate() {
        for (j, &cap2) in caps.iter().enumerate() {
            if i != j {
                if cap1 == cap2 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_caps_are_powers_of_two() -> TestResult {
    let caps = [
        CAP_VFS,
        CAP_NET,
        CAP_DISPLAY,
        CAP_DRIVER,
        CAP_CRYPTO,
        CAP_PROCESS,
        CAP_MEMORY,
        CAP_INPUT,
        CAP_AUDIO,
        CAP_ZK,
        CAP_GPU,
        CAP_APPS,
        CAP_AGENTS,
        CAP_SHELL,
        CAP_ADMIN,
    ];
    for cap in caps {
        if !cap.is_power_of_two() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_caps_no_overlap() -> TestResult {
    let caps = [
        CAP_VFS,
        CAP_NET,
        CAP_DISPLAY,
        CAP_DRIVER,
        CAP_CRYPTO,
        CAP_PROCESS,
        CAP_MEMORY,
        CAP_INPUT,
        CAP_AUDIO,
        CAP_ZK,
        CAP_GPU,
        CAP_APPS,
        CAP_AGENTS,
        CAP_SHELL,
        CAP_ADMIN,
    ];
    for (i, &cap1) in caps.iter().enumerate() {
        for (j, &cap2) in caps.iter().enumerate() {
            if i != j {
                if cap1 & cap2 != 0 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_new() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    if cap.bits != CAP_VFS {
        return TestResult::Fail;
    }
    if cap.owner_pid != 1 {
        return TestResult::Fail;
    }
    if cap.expires_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_with_expiry() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_NET, 2, 10000);
    if cap.bits != CAP_NET {
        return TestResult::Fail;
    }
    if cap.owner_pid != 2 {
        return TestResult::Fail;
    }
    if cap.expires_ms != 10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    if !cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_NET) {
        return TestResult::Fail;
    }
    if cap.has(CAP_DISPLAY) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has_all() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET | CAP_DISPLAY, 1);
    if !cap.has(CAP_VFS | CAP_NET) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_VFS | CAP_NET | CAP_DISPLAY) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has_partial() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    if cap.has(CAP_VFS | CAP_NET) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_is_expired_zero() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    if cap.is_expired(10000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_is_expired_not_yet() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 10000);
    if cap.is_expired(5000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_is_expired_past() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 10000);
    if !cap.is_expired(15000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_is_expired_exact() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 10000);
    if cap.is_expired(10000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_debug() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    let debug_str = alloc::format!("{:?}", cap);
    if !debug_str.contains("ServiceCap") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_clone() -> TestResult {
    let cap = ServiceCap::new(CAP_NET, 2);
    let cloned = cap.clone();
    if cap.bits != cloned.bits {
        return TestResult::Fail;
    }
    if cap.owner_pid != cloned.owner_pid {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_copy() -> TestResult {
    let cap = ServiceCap::new(CAP_DISPLAY, 3);
    let copied: ServiceCap = cap;
    if cap.bits != copied.bits {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_partial_eq() -> TestResult {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_VFS, 1);
    if cap1 != cap2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_not_equal_different_bits() -> TestResult {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_NET, 1);
    if cap1 == cap2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_not_equal_different_owner() -> TestResult {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_VFS, 2);
    if cap1 == cap2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vfs_service_gets_vfs_cap() -> TestResult {
    let caps = cap_for_service("vfs");
    if caps & CAP_VFS == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_service_gets_net_cap() -> TestResult {
    let caps = cap_for_service("network");
    if caps & CAP_NET == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_service_gets_display_cap() -> TestResult {
    let caps = cap_for_service("display");
    if caps & CAP_DISPLAY == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_crypto_service_gets_crypto_cap() -> TestResult {
    let caps = cap_for_service("crypto");
    if caps & CAP_CRYPTO == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_desktop_service_gets_both_caps() -> TestResult {
    let caps = cap_for_service("desktop");
    if caps & CAP_DISPLAY == 0 {
        return TestResult::Fail;
    }
    if caps & CAP_INPUT == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_services_get_only_needed_caps() -> TestResult {
    let vfs_caps = cap_for_service("vfs");
    if vfs_caps & CAP_NET != 0 {
        return TestResult::Fail;
    }
    if vfs_caps & CAP_DISPLAY != 0 {
        return TestResult::Fail;
    }
    if vfs_caps & CAP_ADMIN != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unknown_service_gets_no_caps() -> TestResult {
    let caps = cap_for_service("unknown");
    if caps != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
