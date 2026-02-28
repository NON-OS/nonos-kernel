// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

//! Unit tests for RNG module.

use super::*;

#[test]
fn test_chacha_rng_creation() {
    let seed = [0u8; 32];
    let rng = ChaChaRng::new(seed);
    assert_eq!(rng.blocks_generated(), 0);
}

#[test]
fn test_chacha_rng_deterministic() {
    let seed = [42u8; 32];
    let mut rng1 = ChaChaRng::new(seed);
    let mut rng2 = ChaChaRng::new(seed);

    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];

    rng1.fill_bytes(&mut buf1);
    rng2.fill_bytes(&mut buf2);

    assert_eq!(buf1, buf2);
}

#[test]
fn test_chacha_rng_different_seeds_different_output() {
    let mut rng1 = ChaChaRng::new([1u8; 32]);
    let mut rng2 = ChaChaRng::new([2u8; 32]);

    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    rng1.fill_bytes(&mut buf1);
    rng2.fill_bytes(&mut buf2);

    assert_ne!(buf1, buf2);
}

#[test]
fn test_chacha_rng_reseed() {
    let mut rng = ChaChaRng::new([0u8; 32]);

    let mut buf1 = [0u8; 32];
    rng.fill_bytes(&mut buf1);

    rng.reseed([1u8; 32]);

    let mut buf2 = [0u8; 32];
    rng.fill_bytes(&mut buf2);

    // After reseed, output should be different
    assert_ne!(buf1, buf2);

    // Blocks generated should reset
    assert_eq!(rng.blocks_generated(), 1);
}

#[test]
fn test_chacha_rng_next_u64() {
    let mut rng = ChaChaRng::new([42u8; 32]);

    let v1 = rng.next_u64();
    let v2 = rng.next_u64();

    // Consecutive values should be different
    assert_ne!(v1, v2);
}

#[test]
fn test_chacha_rng_next_u32() {
    let mut rng = ChaChaRng::new([42u8; 32]);

    let v1 = rng.next_u32();
    let v2 = rng.next_u32();

    assert_ne!(v1, v2);
}

#[test]
fn test_chacha_rng_needs_reseed() {
    let mut rng = ChaChaRng::new([0u8; 32]);
    assert!(!rng.needs_reseed());

    // Generate a lot of data to trigger reseed recommendation
    let mut buf = [0u8; 64];
    for _ in 0..RESEED_INTERVAL {
        rng.fill_bytes(&mut buf);
    }

    assert!(rng.needs_reseed());
}

#[test]
fn test_collect_seed_entropy_fills_buffer() {
    let seed = collect_seed_entropy();
    // Should not be all zeros (extremely unlikely with any entropy source)
    assert_ne!(seed, [0u8; 32]);
}

#[test]
fn test_get_entropy64_varies() {
    let v1 = get_entropy64();
    let v2 = get_entropy64();
    // Two consecutive calls should produce different values
    assert_ne!(v1, v2);
}

#[test]
fn test_random_range_bounds() {
    // Test that random_range stays within bounds
    for _ in 0..1000 {
        let r = random_range(10);
        assert!(r < 10);
    }
}

#[test]
fn test_random_range_zero() {
    assert_eq!(random_range(0), 0);
}

#[test]
fn test_random_range_one() {
    assert_eq!(random_range(1), 0);
}

#[test]
fn test_random_range_power_of_two() {
    for _ in 0..1000 {
        let r = random_range(16);
        assert!(r < 16);
    }
}

#[test]
fn test_fill_random_bytes() {
    let mut buf = [0u8; 64];
    fill_random_bytes(&mut buf);
    // Should not be all zeros
    assert_ne!(buf, [0u8; 64]);
}

#[test]
fn test_get_random_bytes() {
    let bytes = get_random_bytes();
    assert_ne!(bytes, [0u8; 32]);
}

#[test]
fn test_error_messages() {
    assert_eq!(RngError::NotInitialized.as_str(), "RNG has not been initialized");
    assert_eq!(RngError::HardwareEntropyFailed.as_str(), "Hardware entropy source failed after retries");
    assert_eq!(RngError::EntropyUnavailable.as_str(), "No adequate entropy source available");
}

#[test]
fn test_entropy_error_messages() {
    use super::entropy::EntropyError;
    assert_eq!(EntropyError::NoHardwareSource.as_str(), "No hardware entropy source available");
    assert_eq!(EntropyError::HardwareFailure.as_str(), "Hardware entropy source failed after retries");
    assert_eq!(EntropyError::InsufficientEntropy.as_str(), "Insufficient entropy collected");
    assert_eq!(EntropyError::NotInitialized.as_str(), "Entropy system not initialized");
}

#[test]
fn test_secure_variants_succeed_after_init() {
    // Ensure RNG is initialized
    let _ = init_rng();

    // All secure variants should succeed after initialization
    let result = get_random_bytes_secure();
    assert!(result.is_ok());
    assert_ne!(result.unwrap(), [0u8; 32]);

    let mut buf = [0u8; 32];
    let result = fill_random_bytes_secure(&mut buf);
    assert!(result.is_ok());
    assert_ne!(buf, [0u8; 32]);

    let result = random_u64_secure();
    assert!(result.is_ok());

    let result = random_u32_secure();
    assert!(result.is_ok());

    let result = random_range_secure(100);
    assert!(result.is_ok());
    assert!(result.unwrap() < 100);
}

#[test]
fn test_has_adequate_entropy() {
    // Should have adequate entropy after init
    let _ = init_rng();
    assert!(has_adequate_entropy());
}

#[test]
fn test_collect_seed_entropy_secure() {
    use super::entropy::collect_seed_entropy_secure;
    // This will fail if no hardware entropy, which is acceptable
    if let Ok(seed) = collect_seed_entropy_secure() {
        assert_ne!(seed, [0u8; 32]);
    }
}

#[test]
fn test_get_entropy64_secure() {
    use super::entropy::get_entropy64_secure;
    // This will fail if no hardware entropy, which is acceptable
    if let Ok(v1) = get_entropy64_secure() {
        if let Ok(v2) = get_entropy64_secure() {
            // Two consecutive calls should produce different values
            assert_ne!(v1, v2);
        }
    }
}
