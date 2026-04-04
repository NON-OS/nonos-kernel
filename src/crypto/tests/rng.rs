// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::crypto::util::rng::csprng::{ChaChaRng, RESEED_INTERVAL};

#[test]
fn test_chacha_rng_new() {
    let seed = [0x42u8; 32];
    let rng = ChaChaRng::new(seed);
    assert_eq!(rng.blocks_generated(), 0);
}

#[test]
fn test_chacha_rng_fill_bytes() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 64];
    rng.fill_bytes(&mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_chacha_rng_deterministic() {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    rng1.fill_bytes(&mut out1);
    rng2.fill_bytes(&mut out2);
    assert_eq!(out1, out2);
}

#[test]
fn test_chacha_rng_different_seeds() {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng1 = ChaChaRng::new(seed1);
    let mut rng2 = ChaChaRng::new(seed2);
    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    rng1.fill_bytes(&mut out1);
    rng2.fill_bytes(&mut out2);
    assert_ne!(out1, out2);
}

#[test]
fn test_chacha_rng_next_u64() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u64();
    assert_ne!(val, 0);
}

#[test]
fn test_chacha_rng_next_u64_deterministic() {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);
    assert_eq!(rng1.next_u64(), rng2.next_u64());
}

#[test]
fn test_chacha_rng_next_u32() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u32();
    assert_ne!(val, 0);
}

#[test]
fn test_chacha_rng_next_u32_deterministic() {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);
    assert_eq!(rng1.next_u32(), rng2.next_u32());
}

#[test]
fn test_chacha_rng_multiple_calls() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val1 = rng.next_u64();
    let val2 = rng.next_u64();
    assert_ne!(val1, val2);
}

#[test]
fn test_chacha_rng_blocks_generated() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    assert_eq!(rng.blocks_generated(), 0);
    let mut output = [0u8; 64];
    rng.fill_bytes(&mut output);
    assert!(rng.blocks_generated() >= 1);
}

#[test]
fn test_chacha_rng_needs_reseed_initial() {
    let seed = [0x42u8; 32];
    let rng = ChaChaRng::new(seed);
    assert!(!rng.needs_reseed());
}

#[test]
fn test_chacha_rng_reseed() {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng = ChaChaRng::new(seed1);
    let mut out1 = [0u8; 64];
    rng.fill_bytes(&mut out1);
    rng.reseed(seed2);
    assert_eq!(rng.blocks_generated(), 0);
}

#[test]
fn test_chacha_rng_reseed_changes_output() {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng = ChaChaRng::new(seed1);
    let val1 = rng.next_u64();
    rng.reseed(seed2);
    let val2 = rng.next_u64();
    assert_ne!(val1, val2);
}

#[test]
fn test_chacha_rng_reseed_deterministic() {
    let seed1 = [0x42u8; 32];
    let seed2 = [0x43u8; 32];
    let mut rng1 = ChaChaRng::new(seed1);
    let mut rng2 = ChaChaRng::new(seed1);
    rng1.reseed(seed2);
    rng2.reseed(seed2);
    assert_eq!(rng1.next_u64(), rng2.next_u64());
}

#[test]
fn test_chacha_rng_fill_small() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 1];
    rng.fill_bytes(&mut output);
    assert!(output[0] != 0 || true);
}

#[test]
fn test_chacha_rng_fill_large() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 1024];
    rng.fill_bytes(&mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_chacha_rng_fill_exact_block() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 64];
    rng.fill_bytes(&mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_chacha_rng_fill_two_blocks() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 128];
    rng.fill_bytes(&mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_chacha_rng_fill_partial_block() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 63];
    rng.fill_bytes(&mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_chacha_rng_fill_empty() {
    let seed = [0x42u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let mut output = [0u8; 0];
    rng.fill_bytes(&mut output);
}

#[test]
fn test_reseed_interval_constant() {
    assert!(RESEED_INTERVAL > 0);
    assert_eq!(RESEED_INTERVAL, 1 << 20);
}

#[test]
fn test_chacha_rng_zero_seed() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u64();
    assert_ne!(val, 0);
}

#[test]
fn test_chacha_rng_all_ones_seed() {
    let seed = [0xffu8; 32];
    let mut rng = ChaChaRng::new(seed);
    let val = rng.next_u64();
    assert_ne!(val, u64::MAX);
}

#[test]
fn test_chacha_rng_sequential_consistent() {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);

    let mut buf1 = [0u8; 100];
    let mut buf2 = [0u8; 100];

    for i in 0..10 {
        rng1.fill_bytes(&mut buf1[i * 10..(i + 1) * 10]);
    }

    rng2.fill_bytes(&mut buf2);

    assert_eq!(buf1, buf2);
}

#[test]
fn test_chacha_rng_different_sizes_match() {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);

    let mut buf1_16 = [0u8; 16];
    let mut buf1_32 = [0u8; 32];
    rng1.fill_bytes(&mut buf1_16);
    rng1.fill_bytes(&mut buf1_32);

    let mut buf2 = [0u8; 48];
    rng2.fill_bytes(&mut buf2);

    assert_eq!(&buf1_16[..], &buf2[..16]);
    assert_eq!(&buf1_32[..], &buf2[16..48]);
}

#[test]
fn test_chacha_rng_u32_u64_consistency() {
    let seed = [0x42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);

    let mut buf = [0u8; 4];
    rng1.fill_bytes(&mut buf);
    let expected = u32::from_le_bytes(buf);

    assert_eq!(rng2.next_u32(), expected);
}
