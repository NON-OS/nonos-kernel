use crate::security::*;

#[test]
fn test_secure_random_u64_returns_value() {
    let value = secure_random_u64();
    let _ = value;
}

#[test]
fn test_secure_random_u64_produces_different_values() {
    let v1 = secure_random_u64();
    let v2 = secure_random_u64();
    let v3 = secure_random_u64();
    assert!(v1 != v2 || v2 != v3 || v1 != v3);
}

#[test]
fn test_secure_random_u32_returns_value() {
    let value = secure_random_u32();
    let _ = value;
}

#[test]
fn test_secure_random_u32_produces_different_values() {
    let v1 = secure_random_u32();
    let v2 = secure_random_u32();
    let v3 = secure_random_u32();
    assert!(v1 != v2 || v2 != v3 || v1 != v3);
}

#[test]
fn test_secure_random_u8_returns_value() {
    let value = secure_random_u8();
    let _ = value;
}

#[test]
fn test_fill_random_small_buffer() {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn test_fill_random_large_buffer() {
    let mut buf = [0u8; 256];
    fill_random(&mut buf);
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn test_fill_random_different_calls() {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    fill_random(&mut buf1);
    fill_random(&mut buf2);
    assert_ne!(buf1, buf2);
}

#[test]
fn test_fill_random_empty_buffer() {
    let mut buf: [u8; 0] = [];
    fill_random(&mut buf);
}

#[test]
fn test_fill_random_single_byte() {
    let mut buf = [0u8; 1];
    fill_random(&mut buf);
}

#[test]
fn test_fill_random_non_aligned_size() {
    let mut buf = [0u8; 13];
    fill_random(&mut buf);
}

#[test]
fn test_fill_random_exactly_u64_size() {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
}

#[test]
fn test_fill_random_multiple_of_u64() {
    let mut buf = [0u8; 64];
    fill_random(&mut buf);
}

#[test]
fn test_secure_random_u64_nonzero_probability() {
    let mut found_nonzero = false;
    for _ in 0..100 {
        if secure_random_u64() != 0 {
            found_nonzero = true;
            break;
        }
    }
    assert!(found_nonzero);
}

#[test]
fn test_secure_random_u32_range() {
    for _ in 0..100 {
        let value = secure_random_u32();
        assert!(value <= u32::MAX);
    }
}

#[test]
fn test_secure_random_u8_range() {
    for _ in 0..100 {
        let value = secure_random_u8();
        assert!(value <= u8::MAX);
    }
}

#[test]
fn test_fill_random_all_bytes_potentially_nonzero() {
    let mut combined = [0u8; 32];
    for _ in 0..100 {
        let mut buf = [0u8; 32];
        fill_random(&mut buf);
        for i in 0..32 {
            combined[i] |= buf[i];
        }
    }
    assert!(combined.iter().all(|&b| b != 0));
}

#[test]
fn test_secure_random_u64_statistical_distribution() {
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

    assert!(high_count > 300);
    assert!(low_count > 300);
}

#[test]
fn test_fill_random_byte_distribution() {
    let mut counts = [0u32; 256];
    let mut buf = [0u8; 1024];

    for _ in 0..100 {
        fill_random(&mut buf);
        for &b in &buf {
            counts[b as usize] += 1;
        }
    }

    let nonzero_buckets = counts.iter().filter(|&&c| c > 0).count();
    assert!(nonzero_buckets > 200);
}

#[test]
fn test_secure_random_u64_bit_coverage() {
    let mut combined = 0u64;
    for _ in 0..1000 {
        combined |= secure_random_u64();
    }
    assert_eq!(combined, u64::MAX);
}

#[test]
fn test_fill_random_independence() {
    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];
    let mut buf3 = [0u8; 16];

    fill_random(&mut buf1);
    fill_random(&mut buf2);
    fill_random(&mut buf3);

    assert_ne!(buf1, buf2);
    assert_ne!(buf2, buf3);
    assert_ne!(buf1, buf3);
}
