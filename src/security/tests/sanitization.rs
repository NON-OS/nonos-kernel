use crate::security::*;

#[test]
fn test_sanitization_level_none() {
    let level = SanitizationLevel::None;
    assert_eq!(level, SanitizationLevel::None);
}

#[test]
fn test_sanitization_level_basic() {
    let level = SanitizationLevel::Basic;
    assert_eq!(level, SanitizationLevel::Basic);
}

#[test]
fn test_sanitization_level_standard() {
    let level = SanitizationLevel::Standard;
    assert_eq!(level, SanitizationLevel::Standard);
}

#[test]
fn test_sanitization_level_paranoid() {
    let level = SanitizationLevel::Paranoid;
    assert_eq!(level, SanitizationLevel::Paranoid);
}

#[test]
fn test_sanitization_level_gutmann() {
    let level = SanitizationLevel::Gutmann;
    assert_eq!(level, SanitizationLevel::Gutmann);
}

#[test]
fn test_sanitization_level_default() {
    let level = SanitizationLevel::default();
    assert_eq!(level, SanitizationLevel::Standard);
}

#[test]
fn test_sanitization_level_from_u64_none() {
    let level = SanitizationLevel::from_u64(0);
    assert_eq!(level, SanitizationLevel::None);
}

#[test]
fn test_sanitization_level_from_u64_basic() {
    let level = SanitizationLevel::from_u64(1);
    assert_eq!(level, SanitizationLevel::Basic);
}

#[test]
fn test_sanitization_level_from_u64_standard() {
    let level = SanitizationLevel::from_u64(2);
    assert_eq!(level, SanitizationLevel::Standard);
}

#[test]
fn test_sanitization_level_from_u64_paranoid() {
    let level = SanitizationLevel::from_u64(3);
    assert_eq!(level, SanitizationLevel::Paranoid);
}

#[test]
fn test_sanitization_level_from_u64_gutmann() {
    let level = SanitizationLevel::from_u64(4);
    assert_eq!(level, SanitizationLevel::Gutmann);
}

#[test]
fn test_sanitization_level_from_u64_invalid() {
    let level = SanitizationLevel::from_u64(100);
    assert_eq!(level, SanitizationLevel::Standard);
}

#[test]
fn test_sanitization_level_equality() {
    assert_eq!(SanitizationLevel::None, SanitizationLevel::None);
    assert_ne!(SanitizationLevel::None, SanitizationLevel::Basic);
}

#[test]
fn test_sanitization_level_copy() {
    let level1 = SanitizationLevel::Paranoid;
    let level2 = level1;
    assert_eq!(level1, level2);
}

#[test]
fn test_stack_canary_config_default() {
    let config = StackCanaryConfig::default();
    assert!(config.enabled);
    assert_eq!(config.canary_value, 0xDEAD_BEEF_CAFE_BABE);
    assert_eq!(config.check_frequency, 1);
}

#[test]
fn test_stack_canary_config_is_enabled() {
    let config = StackCanaryConfig::default();
    assert!(config.is_enabled());
}

#[test]
fn test_stack_canary_config_get_canary() {
    let config = StackCanaryConfig::default();
    assert_eq!(config.get_canary(), 0xDEAD_BEEF_CAFE_BABE);
}

#[test]
fn test_stack_canary_config_get_frequency() {
    let config = StackCanaryConfig::default();
    assert_eq!(config.get_frequency(), 1);
}

#[test]
fn test_stack_canary_config_verify_correct() {
    let config = StackCanaryConfig::default();
    assert!(config.verify(0xDEAD_BEEF_CAFE_BABE));
}

#[test]
fn test_stack_canary_config_verify_incorrect() {
    let config = StackCanaryConfig::default();
    assert!(!config.verify(0x1234567890ABCDEF));
}

#[test]
fn test_stack_canary_config_verify_disabled() {
    let config = StackCanaryConfig {
        enabled: false,
        canary_value: 0xDEAD_BEEF_CAFE_BABE,
        check_frequency: 1,
    };
    assert!(config.verify(0x0000000000000000));
}

#[test]
fn test_stack_canary_config_custom() {
    let config = StackCanaryConfig {
        enabled: true,
        canary_value: 0x1122334455667788,
        check_frequency: 10,
    };
    assert!(config.is_enabled());
    assert_eq!(config.get_canary(), 0x1122334455667788);
    assert_eq!(config.get_frequency(), 10);
}

#[test]
fn test_sanitization_stats_fields() {
    let stats = SanitizationStats {
        bytes_sanitized: 1024,
        sanitization_calls: 10,
        level: SanitizationLevel::Standard,
        canary_enabled: true,
    };
    assert_eq!(stats.bytes_sanitized, 1024);
    assert_eq!(stats.sanitization_calls, 10);
    assert_eq!(stats.level, SanitizationLevel::Standard);
    assert!(stats.canary_enabled);
}

#[test]
fn test_sanitization_stats_get_bytes_sanitized() {
    let stats = SanitizationStats {
        bytes_sanitized: 4096,
        sanitization_calls: 1,
        level: SanitizationLevel::Basic,
        canary_enabled: true,
    };
    assert_eq!(stats.get_bytes_sanitized(), 4096);
}

#[test]
fn test_sanitization_stats_get_call_count() {
    let stats = SanitizationStats {
        bytes_sanitized: 100,
        sanitization_calls: 50,
        level: SanitizationLevel::Paranoid,
        canary_enabled: true,
    };
    assert_eq!(stats.get_call_count(), 50);
}

#[test]
fn test_sanitization_stats_get_level() {
    let stats = SanitizationStats {
        bytes_sanitized: 0,
        sanitization_calls: 0,
        level: SanitizationLevel::Gutmann,
        canary_enabled: false,
    };
    assert_eq!(stats.get_level(), SanitizationLevel::Gutmann);
}

#[test]
fn test_sanitization_stats_is_canary_enabled() {
    let stats = SanitizationStats {
        bytes_sanitized: 0,
        sanitization_calls: 0,
        level: SanitizationLevel::None,
        canary_enabled: true,
    };
    assert!(stats.is_canary_enabled());
}

#[test]
fn test_sanitization_stats_avg_bytes_per_call() {
    let stats = SanitizationStats {
        bytes_sanitized: 1000,
        sanitization_calls: 10,
        level: SanitizationLevel::Standard,
        canary_enabled: true,
    };
    assert_eq!(stats.avg_bytes_per_call(), 100);
}

#[test]
fn test_sanitization_stats_avg_bytes_per_call_zero_calls() {
    let stats = SanitizationStats {
        bytes_sanitized: 1000,
        sanitization_calls: 0,
        level: SanitizationLevel::Standard,
        canary_enabled: true,
    };
    assert_eq!(stats.avg_bytes_per_call(), 0);
}

#[test]
fn test_secure_zero_small_buffer() {
    let mut buf = [0xFFu8; 16];
    secure_zero(buf.as_mut_ptr(), buf.len());
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn test_secure_zero_large_buffer() {
    let mut buf = [0xABu8; 1024];
    secure_zero(buf.as_mut_ptr(), buf.len());
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn test_secure_zero_slice() {
    let mut buf = [0xCDu8; 64];
    secure_zero_slice(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn test_secure_zero_empty() {
    let mut buf: [u8; 0] = [];
    secure_zero_slice(&mut buf);
}

#[test]
fn test_secure_zero_single_byte() {
    let mut buf = [0xFFu8; 1];
    secure_zero_slice(&mut buf);
    assert_eq!(buf[0], 0);
}

#[test]
fn test_sanitize_slice() {
    let mut buf = [0x55u8; 32];
    sanitize_slice(&mut buf);
}

#[test]
fn test_init_stack_canary() {
    init_stack_canary();
}

#[test]
fn test_get_stack_canary() {
    init_stack_canary();
    let canary = get_stack_canary();
    assert_ne!(canary, 0);
}

#[test]
fn test_verify_stack_canary_correct() {
    init_stack_canary();
    let canary = get_stack_canary();
    assert!(verify_stack_canary(canary));
}

#[test]
fn test_verify_stack_canary_incorrect() {
    init_stack_canary();
    assert!(!verify_stack_canary(0x0000000000000000));
}

#[test]
fn test_sanitization_level_debug() {
    let level = SanitizationLevel::Paranoid;
    let debug_str = alloc::format!("{:?}", level);
    assert!(debug_str.contains("Paranoid"));
}

#[test]
fn test_stack_canary_config_debug() {
    let config = StackCanaryConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    assert!(debug_str.contains("enabled"));
}

#[test]
fn test_sanitization_stats_debug() {
    let stats = SanitizationStats {
        bytes_sanitized: 100,
        sanitization_calls: 5,
        level: SanitizationLevel::Basic,
        canary_enabled: true,
    };
    let debug_str = alloc::format!("{:?}", stats);
    assert!(debug_str.contains("bytes_sanitized"));
}

#[test]
fn test_sanitization_stats_copy() {
    let stats1 = SanitizationStats {
        bytes_sanitized: 200,
        sanitization_calls: 2,
        level: SanitizationLevel::Standard,
        canary_enabled: false,
    };
    let stats2 = stats1;
    assert_eq!(stats1.bytes_sanitized, stats2.bytes_sanitized);
}

#[test]
fn test_stack_canary_config_copy() {
    let config1 = StackCanaryConfig::default();
    let config2 = config1;
    assert_eq!(config1.canary_value, config2.canary_value);
}
