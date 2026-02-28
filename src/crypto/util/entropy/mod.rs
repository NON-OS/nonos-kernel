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

mod state;
mod hardware;
mod collect;

pub use hardware::{init, has_hardware_rng};
pub use collect::{
    gather_entropy, get_entropy, fill_entropy, get_random_u64,
    fill_random, rand_u32, rand_u64
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpuid_rdrand_bit() {
        let rdrand_mask: u32 = 1 << 30;
        assert_eq!(rdrand_mask, 0x40000000);
    }

    #[test]
    fn test_cpuid_rdseed_bit() {
        let rdseed_mask: u32 = 1 << 18;
        assert_eq!(rdseed_mask, 0x00040000);
    }

    #[test]
    fn test_u64_le_encoding() {
        let val: u64 = 0x0102030405060708;
        let bytes = val.to_le_bytes();
        assert_eq!(bytes, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_u64_le_encoding_one() {
        let val: u64 = 1;
        let bytes = val.to_le_bytes();
        assert_eq!(bytes, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_u64_le_encoding_max() {
        let val: u64 = u64::MAX;
        let bytes = val.to_le_bytes();
        assert_eq!(bytes, [0xFF; 8]);
    }

    #[test]
    fn test_u64_le_encoding_high_bit() {
        let val: u64 = 0x8000000000000000;
        let bytes = val.to_le_bytes();
        assert_eq!(bytes, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
    }

    #[test]
    fn test_entropy_pool_sizes() {
        let rdseed_bits_per_call = 64;
        let rdseed_max_calls = 4;
        let rdseed_total_bytes = (rdseed_bits_per_call * rdseed_max_calls) / 8;
        assert_eq!(rdseed_total_bytes, 32);

        let mixer_input_size = 32 + 8 + 8;
        assert_eq!(mixer_input_size, 48);

        let sha256_output_size = 32;
        assert_eq!(sha256_output_size, 32);
    }

    #[test]
    fn test_get_entropy_length() {
        let e16 = get_entropy(16);
        assert_eq!(e16.len(), 16);

        let e32 = get_entropy(32);
        assert_eq!(e32.len(), 32);

        let e64 = get_entropy(64);
        assert_eq!(e64.len(), 64);

        let e100 = get_entropy(100);
        assert_eq!(e100.len(), 100);
    }

    #[test]
    fn test_fill_entropy_complete() {
        let mut buf = [0u8; 64];
        fill_entropy(&mut buf);
        let non_zero_count = buf.iter().filter(|&&b| b != 0).count();
        assert!(non_zero_count > 0, "entropy should contain non-zero bytes");
    }

    #[test]
    fn test_entropy_uniqueness() {
        let e1 = gather_entropy();
        let e2 = gather_entropy();
        let e3 = gather_entropy();

        assert_ne!(e1, e2, "consecutive entropy calls should differ");
        assert_ne!(e2, e3, "consecutive entropy calls should differ");
        assert_ne!(e1, e3, "consecutive entropy calls should differ");
    }

    #[test]
    fn test_rand_functions() {
        let r1 = rand_u32();
        let r2 = rand_u32();
        let _ = r1;
        let _ = r2;

        let r3 = rand_u64();
        let r4 = rand_u64();
        let _ = r3;
        let _ = r4;
    }

    #[test]
    fn test_fill_random_ok() {
        let mut buf = [0u8; 32];
        let result = fill_random(&mut buf);
        assert!(result.is_ok());
    }
}
