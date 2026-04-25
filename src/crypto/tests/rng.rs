// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// ChaCha-based CSPRNG tests

use crate::crypto::util::rng::csprng::{ChaChaRng, RESEED_INTERVAL};
use crate::test::framework::TestResult;

pub(crate) fn test_chacha_rng_new() -> TestResult {
    let seed = [0x42u8; 32];
    let rng = ChaChaRng::new(seed);
    if rng.blocks_generated() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_fill_bytes() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 64];
    rng.fill_bytes(&mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_deterministic() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    rng1.fill_bytes(&mut out1);
    rng2.fill_bytes(&mut out2);
    if out1 != out2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_different_seeds() -> TestResult {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng1 = ChaChaRng::new(seed1);
    let mut rng2 = ChaChaRng::new(seed2);
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    rng1.fill_bytes(&mut out1);
    rng2.fill_bytes(&mut out2);
    if out1 == out2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_next_u64() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u64();
    if val == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_next_u64_deterministic() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);
    if rng1.next_u64() != rng2.next_u64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_next_u32() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u32();
    if val == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_next_u32_deterministic() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);
    if rng1.next_u32() != rng2.next_u32() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_multiple_calls() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val1 = rng.next_u64();
    let val2 = rng.next_u64();
    if val1 == val2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_blocks_generated() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    if rng.blocks_generated() != 0 {
        return TestResult::Fail;
    }
    let mut output = [0u8; 64];
    rng.fill_bytes(&mut output);
    if rng.blocks_generated() < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_needs_reseed_initial() -> TestResult {
    let seed = [0x42u8; 32];
    let rng = ChaChaRng::new(seed);
    if rng.needs_reseed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_reseed() -> TestResult {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng = ChaChaRng::new(seed1);
    let mut out1 = [0u8; 64];
    rng.fill_bytes(&mut out1);
    rng.reseed(seed2);
    if rng.blocks_generated() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_reseed_changes_output() -> TestResult {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng = ChaChaRng::new(seed1);
    let val1 = rng.next_u64();
    rng.reseed(seed2);
    let val2 = rng.next_u64();
    if val1 == val2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_reseed_deterministic() -> TestResult {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng1 = ChaChaRng::new(seed1);
    let mut rng2 = ChaChaRng::new(seed1);
    rng1.reseed(seed2);
    rng2.reseed(seed2);
    if rng1.next_u64() != rng2.next_u64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_fill_small() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 1];
    rng.fill_bytes(&mut output);
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_fill_large() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 1024];
    rng.fill_bytes(&mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_fill_exact_block() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 64];
    rng.fill_bytes(&mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_fill_two_blocks() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 128];
    rng.fill_bytes(&mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_fill_partial_block() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 63];
    rng.fill_bytes(&mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_fill_empty() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 0];
    rng.fill_bytes(&mut output);
    TestResult::Pass
}

pub(crate) fn test_reseed_interval_constant() -> TestResult {
    if RESEED_INTERVAL == 0 {
        return TestResult::Fail;
    }
    if RESEED_INTERVAL != 1 << 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_zero_seed() -> TestResult {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u64();
    if val == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_all_ones_seed() -> TestResult {
    let seed = [0xffu8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u64();
    if val == u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_sequential_consistent() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);

    let mut buf1 = [0u8; 100];
    let mut buf2 = [0u8; 100];

    for i in 0..10 {
        rng1.fill_bytes(&mut buf1[i * 10..(i + 1) * 10]);
    }

    rng2.fill_bytes(&mut buf2);

    if buf1 != buf2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_different_sizes_match() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);

    let mut buf1_16 = [0u8; 16];
    let mut buf1_32 = [0u8; 32];
    rng1.fill_bytes(&mut buf1_16);
    rng1.fill_bytes(&mut buf1_32);

    let mut buf2 = [0u8; 48];
    rng2.fill_bytes(&mut buf2);

    if &buf1_16[..] != &buf2[..16] {
        return TestResult::Fail;
    }
    if &buf1_32[..] != &buf2[16..48] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha_rng_u32_u64_consistency() -> TestResult {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);

    let mut buf = [0u8; 4];
    rng1.fill_bytes(&mut buf);
    let expected = u32::from_le_bytes(buf);

    if rng2.next_u32() != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}
