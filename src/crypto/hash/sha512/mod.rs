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

mod constants;
mod hasher;

pub use hasher::Sha512;

pub type Hash512 = [u8; 64];

pub fn sha512(data: &[u8]) -> Hash512 {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

#[inline]
pub fn sha512_hash(data: &[u8]) -> Hash512 {
    sha512(data)
}

#[cfg(test)]
mod tests {
    use super::{sha512, Hash512, Sha512};
    use alloc::vec::Vec;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s = s.replace(|c: char| c.is_whitespace(), "");
        let mut result = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i+2], 16).expect("valid hex");
            result.push(byte);
        }
        result
    }

    fn assert_eq_hex(actual: &Hash512, expected_hex: &str) {
        let expected_bytes = hex_to_bytes(expected_hex);
        assert_eq!(&expected_bytes[..], &actual[..]);
    }

    #[test]
    fn test_empty() {
        let digest = sha512(b"");
        assert_eq_hex(
            &digest,
            "cf83e1357eefb8bd
             f1542850d66d8007
             d620e4050b5715dc
             83f4a921d36ce9ce
             47d0d13c5d85f2b0
             ff8318d2877eec2f
             63b931bd47417a81
             a538327af927da3e",
        );
    }

    #[test]
    fn test_abc() {
        let digest = sha512(b"abc");
        assert_eq_hex(
            &digest,
            "ddaf35a193617aba
             cc417349ae204131
             12e6fa4e89a97ea2
             0a9eeee64b55d39a
             2192992a274fc1a8
             36ba3c23a3feebbd
             454d4423643ce80e
             2a9ac94fa54ca49f",
        );
    }

    #[test]
    fn test_quick_brown_fox() {
        let digest = sha512(b"The quick brown fox jumps over the lazy dog");
        assert_eq_hex(
            &digest,
            "07e547d9586f6a73
             f73fbac0435ed769
             51218fb7d0c8d788
             a309d785436bbb64
             2e93a252a954f239
             12547d1e8a3b5ed6
             e1bfd7097821233f
             a0538f3db854fee6",
        );
    }

    #[test]
    fn test_streaming_matches_oneshot() {
        let data = b"abcdefgh0123456789".repeat(100);
        let mut s = Sha512::new();
        for chunk in data.chunks(50) {
            s.update(chunk);
        }
        let out1 = s.finalize();
        let out2 = sha512(&data);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_partial_buffers_and_boundaries() {
        for len in 0..128 {
            let data = vec![0x5Au8; len];
            let out1 = sha512(&data);
            let mut s = Sha512::new();
            s.update(&data);
            let out2 = s.finalize();
            assert_eq!(out1, out2, "mismatch for len {}", len);
        }
    }
}
