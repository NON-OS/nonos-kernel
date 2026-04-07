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

use super::{sha512, Hash512, Sha512};
use alloc::vec::Vec;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.replace(|c: char| c.is_whitespace(), "");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}

fn assert_eq_hex(actual: &Hash512, expected_hex: &str) {
    assert_eq!(&hex_to_bytes(expected_hex)[..], &actual[..]);
}

#[test]
fn test_empty() {
    assert_eq_hex(&sha512(b""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

#[test]
fn test_abc() {
    assert_eq_hex(&sha512(b"abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

#[test]
fn test_quick_brown_fox() {
    assert_eq_hex(&sha512(b"The quick brown fox jumps over the lazy dog"), "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
}

#[test]
fn test_streaming_matches_oneshot() {
    let data = b"abcdefgh0123456789".repeat(100);
    let mut s = Sha512::new();
    for chunk in data.chunks(50) { s.update(chunk); }
    assert_eq!(s.finalize(), sha512(&data));
}

#[test]
fn test_partial_buffers_and_boundaries() {
    for len in 0..128 {
        let data = alloc::vec![0x5Au8; len];
        let out1 = sha512(&data);
        let mut s = Sha512::new();
        s.update(&data);
        assert_eq!(out1, s.finalize());
    }
}
