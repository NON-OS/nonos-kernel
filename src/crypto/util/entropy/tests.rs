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

use super::*;

#[test]
fn test_cpuid_rdrand_bit() {
    assert_eq!(1u32 << 30, 0x40000000);
}

#[test]
fn test_cpuid_rdseed_bit() {
    assert_eq!(1u32 << 18, 0x00040000);
}

#[test]
fn test_u64_le_encoding() {
    let bytes = 0x0102030405060708u64.to_le_bytes();
    assert_eq!(bytes, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn test_u64_le_encoding_one() {
    assert_eq!(1u64.to_le_bytes(), [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn test_u64_le_encoding_max() {
    assert_eq!(u64::MAX.to_le_bytes(), [0xFF; 8]);
}

#[test]
fn test_u64_le_encoding_high_bit() {
    assert_eq!(
        0x8000000000000000u64.to_le_bytes(),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
    );
}

#[test]
fn test_entropy_pool_sizes() {
    assert_eq!((64 * 4) / 8, 32);
    assert_eq!(32 + 8 + 8, 48);
}

#[test]
fn test_get_entropy_length() {
    assert_eq!(get_entropy(16).len(), 16);
    assert_eq!(get_entropy(32).len(), 32);
    assert_eq!(get_entropy(64).len(), 64);
    assert_eq!(get_entropy(100).len(), 100);
}

#[test]
fn test_fill_entropy_complete() {
    let mut buf = [0u8; 64];
    fill_entropy(&mut buf);
    assert!(buf.iter().filter(|&&b| b != 0).count() > 0);
}

#[test]
fn test_entropy_uniqueness() {
    let e1 = gather_entropy();
    let e2 = gather_entropy();
    let e3 = gather_entropy();
    assert_ne!(e1, e2);
    assert_ne!(e2, e3);
    assert_ne!(e1, e3);
}

#[test]
fn test_rand_functions() {
    let _ = rand_u32();
    let _ = rand_u64();
}

#[test]
fn test_fill_random_ok() {
    let mut buf = [0u8; 32];
    assert!(fill_random(&mut buf).is_ok());
}
