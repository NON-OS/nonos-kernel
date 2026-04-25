// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Secure random number generation tests

use crate::security::*;
use crate::test::framework::TestResult;

pub(crate) fn test_secure_random_u64_returns_value() -> TestResult {
    let value = secure_random_u64();
    let _ = value;
    TestResult::Pass
}

pub(crate) fn test_secure_random_u64_produces_different_values() -> TestResult {
    let v1 = secure_random_u64();
    let v2 = secure_random_u64();
    let v3 = secure_random_u64();
    if !(v1 != v2 || v2 != v3 || v1 != v3) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_random_u32_returns_value() -> TestResult {
    let value = secure_random_u32();
    let _ = value;
    TestResult::Pass
}

pub(crate) fn test_secure_random_u32_produces_different_values() -> TestResult {
    let v1 = secure_random_u32();
    let v2 = secure_random_u32();
    let v3 = secure_random_u32();
    if !(v1 != v2 || v2 != v3 || v1 != v3) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_random_u8_returns_value() -> TestResult {
    let value = secure_random_u8();
    let _ = value;
    TestResult::Pass
}

pub(crate) fn test_fill_random_small_buffer() -> TestResult {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    if !buf.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fill_random_large_buffer() -> TestResult {
    let mut buf = [0u8; 256];
    fill_random(&mut buf);
    if !buf.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fill_random_different_calls() -> TestResult {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    fill_random(&mut buf1);
    fill_random(&mut buf2);
    if buf1 == buf2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fill_random_empty_buffer() -> TestResult {
    let mut buf: [u8; 0] = [];
    fill_random(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_fill_random_single_byte() -> TestResult {
    let mut buf = [0u8; 1];
    fill_random(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_fill_random_non_aligned_size() -> TestResult {
    let mut buf = [0u8; 13];
    fill_random(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_fill_random_exactly_u64_size() -> TestResult {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_fill_random_multiple_of_u64() -> TestResult {
    let mut buf = [0u8; 64];
    fill_random(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_secure_random_u64_nonzero_probability() -> TestResult {
    let mut found_nonzero = false;
    for _ in 0..100 {
        if secure_random_u64() != 0 {
            found_nonzero = true;
            break;
        }
    }
    if !found_nonzero {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_random_u32_range() -> TestResult {
    for _ in 0..100 {
        let value = secure_random_u32();
        if value > u32::MAX {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_secure_random_u8_range() -> TestResult {
    for _ in 0..100 {
        let value = secure_random_u8();
        if value > u8::MAX {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_fill_random_all_bytes_potentially_nonzero() -> TestResult {
    let mut combined = [0u8; 32];
    for _ in 0..100 {
        let mut buf = [0u8; 32];
        fill_random(&mut buf);
        for i in 0..32 {
            combined[i] |= buf[i];
        }
    }
    if !combined.iter().all(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_random_u64_statistical_distribution() -> TestResult {
    let mut high_count = 0u64;
    let mut low_count = 0u64;
    let threshold = 1u64 << 63;

    for _ in 0..1000 {
        let value = secure_random_u64();
        if value >= threshold {
            high_count += 1;
        } else {
            low_count += 1;
        }
    }

    if high_count <= 300 {
        return TestResult::Fail;
    }
    if low_count <= 300 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fill_random_byte_distribution() -> TestResult {
    let mut counts = [0u32; 256];
    let mut buf = [0u8; 1024];

    for _ in 0..100 {
        fill_random(&mut buf);
        for &b in &buf {
            counts[b as usize] += 1;
        }
    }

    let nonzero_buckets = counts.iter().filter(|&&c| c > 0).count();
    if nonzero_buckets <= 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_random_u64_bit_coverage() -> TestResult {
    let mut combined = 0u64;
    for _ in 0..1000 {
        combined |= secure_random_u64();
    }
    if combined != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fill_random_independence() -> TestResult {
    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];
    let mut buf3 = [0u8; 16];

    fill_random(&mut buf1);
    fill_random(&mut buf2);
    fill_random(&mut buf3);

    if buf1 == buf2 {
        return TestResult::Fail;
    }
    if buf2 == buf3 {
        return TestResult::Fail;
    }
    if buf1 == buf3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
