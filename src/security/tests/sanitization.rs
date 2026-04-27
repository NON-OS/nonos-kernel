// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Memory sanitization and stack canary tests

extern crate alloc;

use crate::security::*;
use crate::test::framework::TestResult;
use alloc::format;

pub(crate) fn test_sanitization_level_none() -> TestResult {
    let level = SanitizationLevel::None;
    if level != SanitizationLevel::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_basic() -> TestResult {
    let level = SanitizationLevel::Basic;
    if level != SanitizationLevel::Basic {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_standard() -> TestResult {
    let level = SanitizationLevel::Standard;
    if level != SanitizationLevel::Standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_paranoid() -> TestResult {
    let level = SanitizationLevel::Paranoid;
    if level != SanitizationLevel::Paranoid {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_gutmann() -> TestResult {
    let level = SanitizationLevel::Gutmann;
    if level != SanitizationLevel::Gutmann {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_default() -> TestResult {
    let level = SanitizationLevel::default();
    if level != SanitizationLevel::Standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_from_u64_none() -> TestResult {
    let level = SanitizationLevel::from_u64(0);
    if level != SanitizationLevel::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_from_u64_basic() -> TestResult {
    let level = SanitizationLevel::from_u64(1);
    if level != SanitizationLevel::Basic {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_from_u64_standard() -> TestResult {
    let level = SanitizationLevel::from_u64(2);
    if level != SanitizationLevel::Standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_from_u64_paranoid() -> TestResult {
    let level = SanitizationLevel::from_u64(3);
    if level != SanitizationLevel::Paranoid {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_from_u64_gutmann() -> TestResult {
    let level = SanitizationLevel::from_u64(4);
    if level != SanitizationLevel::Gutmann {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_from_u64_invalid() -> TestResult {
    let level = SanitizationLevel::from_u64(100);
    if level != SanitizationLevel::Standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_equality() -> TestResult {
    if SanitizationLevel::None != SanitizationLevel::None {
        return TestResult::Fail;
    }
    if SanitizationLevel::None == SanitizationLevel::Basic {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_copy() -> TestResult {
    let level1 = SanitizationLevel::Paranoid;
    let level2 = level1;
    if level1 != level2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_default() -> TestResult {
    let config = StackCanaryConfig::default();
    if !config.enabled {
        return TestResult::Fail;
    }
    if config.canary_value != 0xDEAD_BEEF_CAFE_BABE {
        return TestResult::Fail;
    }
    if config.check_frequency != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_is_enabled() -> TestResult {
    let config = StackCanaryConfig::default();
    if !config.is_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_get_canary() -> TestResult {
    let config = StackCanaryConfig::default();
    if config.get_canary() != 0xDEAD_BEEF_CAFE_BABE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_get_frequency() -> TestResult {
    let config = StackCanaryConfig::default();
    if config.get_frequency() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_verify_correct() -> TestResult {
    let config = StackCanaryConfig::default();
    if !config.verify(0xDEAD_BEEF_CAFE_BABE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_verify_incorrect() -> TestResult {
    let config = StackCanaryConfig::default();
    if config.verify(0x1234567890ABCDEF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_verify_disabled() -> TestResult {
    let config = StackCanaryConfig {
        enabled: false,
        canary_value: 0xDEAD_BEEF_CAFE_BABE,
        check_frequency: 1,
    };
    if !config.verify(0x0000000000000000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_custom() -> TestResult {
    let config =
        StackCanaryConfig { enabled: true, canary_value: 0x1122334455667788, check_frequency: 10 };
    if !config.is_enabled() {
        return TestResult::Fail;
    }
    if config.get_canary() != 0x1122334455667788 {
        return TestResult::Fail;
    }
    if config.get_frequency() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_fields() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 1024,
        sanitization_calls: 10,
        level: SanitizationLevel::Standard,
        canary_enabled: true,
    };
    if stats.bytes_sanitized != 1024 {
        return TestResult::Fail;
    }
    if stats.sanitization_calls != 10 {
        return TestResult::Fail;
    }
    if stats.level != SanitizationLevel::Standard {
        return TestResult::Fail;
    }
    if !stats.canary_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_get_bytes_sanitized() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 4096,
        sanitization_calls: 1,
        level: SanitizationLevel::Basic,
        canary_enabled: true,
    };
    if stats.get_bytes_sanitized() != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_get_call_count() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 100,
        sanitization_calls: 50,
        level: SanitizationLevel::Paranoid,
        canary_enabled: true,
    };
    if stats.get_call_count() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_get_level() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 0,
        sanitization_calls: 0,
        level: SanitizationLevel::Gutmann,
        canary_enabled: false,
    };
    if stats.get_level() != SanitizationLevel::Gutmann {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_is_canary_enabled() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 0,
        sanitization_calls: 0,
        level: SanitizationLevel::None,
        canary_enabled: true,
    };
    if !stats.is_canary_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_avg_bytes_per_call() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 1000,
        sanitization_calls: 10,
        level: SanitizationLevel::Standard,
        canary_enabled: true,
    };
    if stats.avg_bytes_per_call() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_avg_bytes_per_call_zero_calls() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 1000,
        sanitization_calls: 0,
        level: SanitizationLevel::Standard,
        canary_enabled: true,
    };
    if stats.avg_bytes_per_call() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_zero_small_buffer() -> TestResult {
    let mut buf = [0xFFu8; 16];
    secure_zero(buf.as_mut_ptr(), buf.len());
    if !buf.iter().all(|&b| b == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_zero_large_buffer() -> TestResult {
    let mut buf = [0xABu8; 1024];
    secure_zero(buf.as_mut_ptr(), buf.len());
    if !buf.iter().all(|&b| b == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_zero_slice() -> TestResult {
    let mut buf = [0xCDu8; 64];
    secure_zero_slice(&mut buf);
    if !buf.iter().all(|&b| b == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_zero_empty() -> TestResult {
    let mut buf: [u8; 0] = [];
    secure_zero_slice(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_secure_zero_single_byte() -> TestResult {
    let mut buf = [0xFFu8; 1];
    secure_zero_slice(&mut buf);
    if buf[0] != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitize_slice() -> TestResult {
    let mut buf = [0x55u8; 32];
    sanitize_slice(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_init_stack_canary() -> TestResult {
    init_stack_canary();
    TestResult::Pass
}

pub(crate) fn test_get_stack_canary() -> TestResult {
    init_stack_canary();
    let canary = get_stack_canary();
    if canary == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_stack_canary_correct() -> TestResult {
    init_stack_canary();
    let canary = get_stack_canary();
    if !verify_stack_canary(canary) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_stack_canary_incorrect() -> TestResult {
    init_stack_canary();
    if verify_stack_canary(0x0000000000000000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_level_debug() -> TestResult {
    let level = SanitizationLevel::Paranoid;
    let debug_str = format!("{:?}", level);
    if !debug_str.contains("Paranoid") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_debug() -> TestResult {
    let config = StackCanaryConfig::default();
    let debug_str = format!("{:?}", config);
    if !debug_str.contains("enabled") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_debug() -> TestResult {
    let stats = SanitizationStats {
        bytes_sanitized: 100,
        sanitization_calls: 5,
        level: SanitizationLevel::Basic,
        canary_enabled: true,
    };
    let debug_str = format!("{:?}", stats);
    if !debug_str.contains("bytes_sanitized") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sanitization_stats_copy() -> TestResult {
    let stats1 = SanitizationStats {
        bytes_sanitized: 200,
        sanitization_calls: 2,
        level: SanitizationLevel::Standard,
        canary_enabled: false,
    };
    let stats2 = stats1;
    if stats1.bytes_sanitized != stats2.bytes_sanitized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stack_canary_config_copy() -> TestResult {
    let config1 = StackCanaryConfig::default();
    let config2 = config1;
    if config1.canary_value != config2.canary_value {
        return TestResult::Fail;
    }
    TestResult::Pass
}
