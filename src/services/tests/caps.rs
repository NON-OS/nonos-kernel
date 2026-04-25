use crate::services::caps::{CAP_MEMORY, CAP_PROCESS};
use crate::services::*;
use crate::test::framework::TestResult;

pub(crate) fn test_cap_vfs_bit_value() -> TestResult {
    if CAP_VFS != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_net_bit_value() -> TestResult {
    if CAP_NET != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_display_bit_value() -> TestResult {
    if CAP_DISPLAY != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_driver_bit_value() -> TestResult {
    if CAP_DRIVER != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_crypto_bit_value() -> TestResult {
    if CAP_CRYPTO != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_process_bit_value() -> TestResult {
    if CAP_PROCESS != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_memory_bit_value() -> TestResult {
    if CAP_MEMORY != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_input_bit_value() -> TestResult {
    if CAP_INPUT != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_audio_bit_value() -> TestResult {
    if CAP_AUDIO != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_zk_bit_value() -> TestResult {
    if CAP_ZK != 1 << 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_gpu_bit_value() -> TestResult {
    if CAP_GPU != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_apps_bit_value() -> TestResult {
    if CAP_APPS != 1 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_agents_bit_value() -> TestResult {
    if CAP_AGENTS != 1 << 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_shell_bit_value() -> TestResult {
    if CAP_SHELL != 1 << 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_admin_bit_value() -> TestResult {
    if CAP_ADMIN != 1 << 63 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_bits_are_powers_of_two() -> TestResult {
    if !CAP_VFS.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_NET.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_DISPLAY.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_DRIVER.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_CRYPTO.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_INPUT.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_AUDIO.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_ZK.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_GPU.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_APPS.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_AGENTS.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_SHELL.is_power_of_two() {
        return TestResult::Fail;
    }
    if !CAP_ADMIN.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_bits_are_unique() -> TestResult {
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
    for i in 0..caps.len() {
        for j in (i + 1)..caps.len() {
            if caps[i] == caps[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_new() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 42);
    if cap.bits != CAP_VFS | CAP_NET {
        return TestResult::Fail;
    }
    if cap.owner_pid != 42 {
        return TestResult::Fail;
    }
    if cap.expires_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_with_expiry() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_CRYPTO, 100, 5000);
    if cap.bits != CAP_CRYPTO {
        return TestResult::Fail;
    }
    if cap.owner_pid != 100 {
        return TestResult::Fail;
    }
    if cap.expires_ms != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has_single_cap() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    if !cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if cap.has(CAP_NET) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has_multiple_caps() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET | CAP_CRYPTO, 1);
    if !cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_NET) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_CRYPTO) {
        return TestResult::Fail;
    }
    if cap.has(CAP_INPUT) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has_combined_caps() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    if !cap.has(CAP_VFS | CAP_NET) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has_zero_cap_always_true() -> TestResult {
    let cap = ServiceCap::new(0, 1);
    if !cap.has(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_has_partial_caps_fails() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    if cap.has(CAP_VFS | CAP_NET) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_is_expired_zero_never_expires() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    if cap.is_expired(0) {
        return TestResult::Fail;
    }
    if cap.is_expired(u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_is_expired_before_expiry() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 1000);
    if cap.is_expired(500) {
        return TestResult::Fail;
    }
    if cap.is_expired(999) {
        return TestResult::Fail;
    }
    if cap.is_expired(1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_is_expired_after_expiry() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 1000);
    if !cap.is_expired(1001) {
        return TestResult::Fail;
    }
    if !cap.is_expired(2000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_clone() -> TestResult {
    let cap = ServiceCap::new(CAP_NET, 42);
    let cloned = cap.clone();
    if cap.bits != cloned.bits {
        return TestResult::Fail;
    }
    if cap.owner_pid != cloned.owner_pid {
        return TestResult::Fail;
    }
    if cap.expires_ms != cloned.expires_ms {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_copy() -> TestResult {
    let cap = ServiceCap::new(CAP_CRYPTO, 99);
    let copied: ServiceCap = cap;
    if cap.bits != copied.bits {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_equality() -> TestResult {
    let cap1 = ServiceCap::new(CAP_VFS, 1);
    let cap2 = ServiceCap::new(CAP_VFS, 1);
    let cap3 = ServiceCap::new(CAP_NET, 1);
    if cap1 != cap2 {
        return TestResult::Fail;
    }
    if cap1 == cap3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_debug_format() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 42);
    let debug_str = alloc::format!("{:?}", cap);
    if !debug_str.contains("ServiceCap") {
        return TestResult::Fail;
    }
    if !debug_str.contains("bits") {
        return TestResult::Fail;
    }
    if !debug_str.contains("owner_pid") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_error_variants_exist() -> TestResult {
    let _no_cap = CapError::NoCap;
    let _insufficient = CapError::InsufficientCaps;
    let _expired = CapError::Expired;
    let _not_found = CapError::ServiceNotFound;
    TestResult::Pass
}

pub(crate) fn test_cap_error_equality() -> TestResult {
    if CapError::NoCap != CapError::NoCap {
        return TestResult::Fail;
    }
    if CapError::InsufficientCaps != CapError::InsufficientCaps {
        return TestResult::Fail;
    }
    if CapError::Expired != CapError::Expired {
        return TestResult::Fail;
    }
    if CapError::ServiceNotFound != CapError::ServiceNotFound {
        return TestResult::Fail;
    }
    if CapError::NoCap == CapError::Expired {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_error_clone() -> TestResult {
    let err = CapError::InsufficientCaps;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_error_copy() -> TestResult {
    let err = CapError::Expired;
    let copied: CapError = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_error_debug_format() -> TestResult {
    let err = CapError::ServiceNotFound;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("ServiceNotFound") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_caps_can_be_combined_with_or() -> TestResult {
    let combined = CAP_VFS | CAP_NET | CAP_CRYPTO;
    if combined != (1 << 0) | (1 << 1) | (1 << 4) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_caps_can_be_checked_with_and() -> TestResult {
    let combined = CAP_VFS | CAP_NET;
    if combined & CAP_VFS != CAP_VFS {
        return TestResult::Fail;
    }
    if combined & CAP_CRYPTO != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_with_all_standard_caps() -> TestResult {
    let all = CAP_VFS
        | CAP_NET
        | CAP_DISPLAY
        | CAP_DRIVER
        | CAP_CRYPTO
        | CAP_INPUT
        | CAP_AUDIO
        | CAP_ZK
        | CAP_GPU
        | CAP_APPS
        | CAP_AGENTS
        | CAP_SHELL;
    let cap = ServiceCap::new(all, 1);
    if !cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_NET) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_DISPLAY) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_DRIVER) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_CRYPTO) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_INPUT) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_AUDIO) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_ZK) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_GPU) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_APPS) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_AGENTS) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_SHELL) {
        return TestResult::Fail;
    }
    if cap.has(CAP_ADMIN) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_admin_is_separate() -> TestResult {
    let cap = ServiceCap::new(CAP_ADMIN, 1);
    if !cap.has(CAP_ADMIN) {
        return TestResult::Fail;
    }
    if cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if cap.has(CAP_NET) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_zero_bits_has_nothing() -> TestResult {
    let cap = ServiceCap::new(0, 1);
    if cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if cap.has(CAP_NET) {
        return TestResult::Fail;
    }
    if cap.has(CAP_ADMIN) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_max_bits() -> TestResult {
    let cap = ServiceCap::new(u64::MAX, 1);
    if !cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_ADMIN) {
        return TestResult::Fail;
    }
    if !cap.has(u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
