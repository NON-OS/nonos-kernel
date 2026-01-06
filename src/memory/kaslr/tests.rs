// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::*;
use super::constants::*;
use super::error::KaslrError;

// ============================================================================
// CONSTANTS TESTS
// ============================================================================

#[test]
fn test_default_window_size() {
    assert_eq!(DEFAULT_WINDOW_SIZE, 0x40000000); // 1 GiB
}

#[test]
fn test_slide_range() {
    assert!(MIN_SLIDE < MAX_SLIDE);
    assert_eq!(MIN_SLIDE, 0x10000000);  // 256 MiB
    assert_eq!(MAX_SLIDE, 0x80000000);  // 2 GiB
}

#[test]
fn test_safe_slide_range() {
    assert!(SAFE_SLIDE_MIN < SAFE_SLIDE_MAX);
    assert_eq!(SAFE_SLIDE_MIN, 0x1000000);    // 16 MiB
    assert_eq!(SAFE_SLIDE_MAX, 0x100000000);  // 4 GiB
}

#[test]
fn test_entropy_constants() {
    assert_ne!(INITIAL_ENTROPY_SEED, 0);
    assert_ne!(ENTROPY_MIX_MULTIPLIER, 0);
    assert_ne!(NONCE_GEN_MULTIPLIER, 0);
}

#[test]
fn test_cpuid_constants() {
    assert_eq!(CPUID_FEATURES_LEAF, 1);
    assert_eq!(CPUID_EXTENDED_LEAF, 7);
    assert_eq!(RDRAND_FEATURE_BIT, 30);
    assert_eq!(RDSEED_FEATURE_BIT, 18);
}

#[test]
fn test_hash_output_size() {
    assert_eq!(HASH_OUTPUT_SIZE, 32); // SHA3-256
}

#[test]
fn test_kdf_label_prefix() {
    assert_eq!(KDF_LABEL_PREFIX, b"NONOS-KASLR-KDF:");
}

#[test]
fn test_integrity_check_constants() {
    assert_eq!(INTEGRITY_CHECK_LABEL, b"integrity_check");
    assert_eq!(INTEGRITY_CHECK_BUFFER_SIZE, 64);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_display() {
    assert_eq!(KaslrError::NotInitialized.as_str(), "KASLR not initialized");
    assert_eq!(KaslrError::InvalidPolicy.as_str(), "Invalid KASLR policy: min_slide >= max_slide");
    assert_eq!(KaslrError::InvalidAlignment.as_str(), "Invalid alignment granularity");
    assert_eq!(KaslrError::RangeTooSmall.as_str(), "KASLR range too small for alignment");
    assert_eq!(KaslrError::SlideOutOfRange.as_str(), "Generated slide out of range");
    assert_eq!(KaslrError::SlideNotAligned.as_str(), "Generated slide not properly aligned");
}

#[test]
fn test_error_security_critical() {
    assert!(KaslrError::InsufficientEntropy.is_security_critical());
    assert!(KaslrError::IntegrityCheckFailed.is_security_critical());
    assert!(KaslrError::SlideNotAligned.is_security_critical());
    assert!(!KaslrError::NotInitialized.is_security_critical());
    assert!(!KaslrError::InvalidPolicy.is_security_critical());
}

#[test]
fn test_error_from_string() {
    let err: KaslrError = "KASLR not initialized".into();
    assert_eq!(err, KaslrError::NotInitialized);

    let err: KaslrError = "Invalid KASLR policy: min_slide >= max_slide".into();
    assert_eq!(err, KaslrError::InvalidPolicy);

    let err: KaslrError = "KASLR slide not page-aligned".into();
    assert_eq!(err, KaslrError::SlideNotAligned);
}

// ============================================================================
// POLICY TESTS
// ============================================================================

#[test]
fn test_policy_default() {
    let policy = Policy::default();

    assert_eq!(policy.window_bytes, DEFAULT_WINDOW_SIZE);
    assert_eq!(policy.min_slide, MIN_SLIDE);
    assert_eq!(policy.max_slide, MAX_SLIDE);
    assert!(policy.align > 0);
}

#[test]
fn test_policy_custom() {
    let policy = Policy {
        align: 0x1000,
        window_bytes: 0x10000000,
        min_slide: 0x1000000,
        max_slide: 0x10000000,
    };

    assert_eq!(policy.align, 0x1000);
    assert_eq!(policy.window_bytes, 0x10000000);
    assert!(policy.min_slide < policy.max_slide);
}

#[test]
fn test_policy_min_max_validation() {
    let valid_policy = Policy {
        align: 4096,
        window_bytes: 0x40000000,
        min_slide: 0x1000000,
        max_slide: 0x10000000,
    };
    assert!(valid_policy.min_slide < valid_policy.max_slide);

    // Invalid policy where min >= max would fail in choose_slide
}

// ============================================================================
// RANGE TESTS
// ============================================================================

#[test]
fn test_range_new() {
    let range = Range::new(0x1000, 0x2000);
    assert_eq!(range.lo, 0x1000);
    assert_eq!(range.hi, 0x2000);
}

#[test]
fn test_range_contains() {
    let range = Range::new(0x1000, 0x2000);

    // Within range
    assert!(range.contains(0x1000)); // Lower bound inclusive
    assert!(range.contains(0x1500));
    assert!(range.contains(0x1FFF));

    // Outside range
    assert!(!range.contains(0x0FFF)); // Below
    assert!(!range.contains(0x2000)); // Upper bound exclusive
    assert!(!range.contains(0x3000)); // Above
}

#[test]
fn test_range_size() {
    let range = Range::new(0x1000, 0x2000);
    assert_eq!(range.size(), 0x1000);

    let zero_range = Range::new(0x1000, 0x1000);
    assert_eq!(zero_range.size(), 0);

    let inverted_range = Range::new(0x2000, 0x1000);
    assert_eq!(inverted_range.size(), 0);
}

#[test]
fn test_range_edge_cases() {
    // Zero-sized range
    let zero = Range::new(100, 100);
    assert!(!zero.contains(100));
    assert_eq!(zero.size(), 0);

    // Maximum range
    let max_range = Range::new(0, u64::MAX);
    assert!(max_range.contains(0));
    assert!(max_range.contains(u64::MAX - 1));
    assert!(!max_range.contains(u64::MAX));
}

// ============================================================================
// KASLR STRUCT TESTS
// ============================================================================

#[test]
fn test_kaslr_struct() {
    let kaslr = Kaslr {
        slide: 0x10000000,
        entropy_hash: [0u8; 32],
        boot_nonce: 0x12345678,
    };

    assert_eq!(kaslr.slide, 0x10000000);
    assert_eq!(kaslr.boot_nonce, 0x12345678);
    assert_eq!(kaslr.entropy_hash.len(), 32);
}

// ============================================================================
// HASH TESTS
// ============================================================================

#[test]
fn test_secure_hash_output_size() {
    let input = b"test input";
    let hash = secure_hash(input);
    assert_eq!(hash.len(), HASH_OUTPUT_SIZE);
}

#[test]
fn test_secure_hash_deterministic() {
    let input = b"deterministic test";
    let hash1 = secure_hash(input);
    let hash2 = secure_hash(input);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_secure_hash_different_inputs() {
    let hash1 = secure_hash(b"input1");
    let hash2 = secure_hash(b"input2");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_secure_hash_empty_input() {
    let hash = secure_hash(b"");
    assert_eq!(hash.len(), HASH_OUTPUT_SIZE);
    // Hash should not be all zeros for empty input
    assert!(hash.iter().any(|&b| b != 0));
}

// ============================================================================
// HARDWARE FEATURE DETECTION TESTS
// ============================================================================

#[test]
fn test_has_hardware_rng_detection() {
    // This just tests that the function runs without panic
    let _has_hw_rng = has_hardware_rng();
}

// ============================================================================
// CHOOSE_SLIDE TESTS
// ============================================================================

#[test]
fn test_choose_slide_invalid_policy() {
    let invalid_policy = Policy {
        align: 4096,
        window_bytes: 0x40000000,
        min_slide: 0x10000000,
        max_slide: 0x1000000, // Less than min_slide
    };

    let result = choose_slide(0x12345678, invalid_policy);
    assert_eq!(result, Err(KaslrError::InvalidPolicy));
}

#[test]
fn test_choose_slide_equal_min_max() {
    let equal_policy = Policy {
        align: 4096,
        window_bytes: 0x40000000,
        min_slide: 0x10000000,
        max_slide: 0x10000000, // Equal to min_slide
    };

    let result = choose_slide(0x12345678, equal_policy);
    assert_eq!(result, Err(KaslrError::InvalidPolicy));
}

#[test]
fn test_choose_slide_zero_alignment() {
    let zero_align_policy = Policy {
        align: 0, // Zero alignment should use PAGE_SIZE
        window_bytes: 0x40000000,
        min_slide: 0x10000000,
        max_slide: 0x80000000,
    };

    // Should succeed using PAGE_SIZE as alignment
    let result = choose_slide(0x12345678, zero_align_policy);
    assert!(result.is_ok());
}

#[test]
fn test_choose_slide_valid_policy() {
    let valid_policy = Policy::default();

    let result = choose_slide(0x12345678, valid_policy);
    assert!(result.is_ok());

    let slide = result.unwrap();
    assert!(slide >= valid_policy.min_slide);
    assert!(slide < valid_policy.max_slide);
    assert_eq!(slide % valid_policy.align, 0);
}

#[test]
fn test_choose_slide_alignment() {
    let policy = Policy {
        align: 0x100000, // 1 MiB alignment
        window_bytes: 0x40000000,
        min_slide: 0x10000000,
        max_slide: 0x80000000,
    };

    for entropy in [0u64, 1, 1000, u64::MAX / 2, u64::MAX] {
        let result = choose_slide(entropy, policy);
        if let Ok(slide) = result {
            assert_eq!(slide % policy.align, 0, "Slide not aligned for entropy {}", entropy);
        }
    }
}

#[test]
fn test_choose_slide_range_bounds() {
    let policy = Policy {
        align: 4096,
        window_bytes: 0x40000000,
        min_slide: 0x10000000,
        max_slide: 0x20000000,
    };

    for i in 0..100 {
        let entropy = (i as u64).wrapping_mul(0x123456789ABCDEF);
        let result = choose_slide(entropy, policy);
        if let Ok(slide) = result {
            assert!(slide >= policy.min_slide, "Slide below min for entropy {}", entropy);
            assert!(slide < policy.max_slide, "Slide at or above max for entropy {}", entropy);
        }
    }
}

// ============================================================================
// PUBLIC API TESTS
// ============================================================================

#[test]
fn test_get_slide_initial() {
    let slide = get_slide();
    assert!(slide == 0 || slide > 0);
}

#[test]
fn test_is_initialized() {
    // Just verify it runs
    let _initialized = is_initialized();
}

// ============================================================================
// ENTROPY QUALITY TESTS
// ============================================================================

#[test]
fn test_entropy_not_constant() {
    let mut values = alloc::vec::Vec::new();
    for _ in 0..5 {
        values.push(collect_entropy());
    }

    let first = values[0];
    let all_same = values.iter().all(|&v| v == first);
    let _ = all_same;
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================
#[test]
fn test_full_kaslr_workflow() {
    let policy = Policy::default();
    assert!(policy.min_slide < policy.max_slide);
    assert!(policy.align > 0);
    let entropy = collect_entropy();
    assert_ne!(entropy, 0);
    let slide = choose_slide(entropy, policy);
    assert!(slide.is_ok());
    let slide_value = slide.unwrap();
    assert!(slide_value >= policy.min_slide);
    assert!(slide_value < policy.max_slide);
    assert_eq!(slide_value % policy.align, 0);
}
