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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumType { Crc32, Sha256, Sha512, Md5 }

pub fn calculate_crc32(data: &[u8]) -> u32 {
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();
    let mut crc = 0xFFFFFFFF;
    for &byte in data { crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize]; }
    !crc
}

pub fn calculate_sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for chunk in data.chunks(64) {
        let mut w = [0u32; 64];
        for (i, byte_chunk) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([byte_chunk.get(0).copied().unwrap_or(0), byte_chunk.get(1).copied().unwrap_or(0), byte_chunk.get(2).copied().unwrap_or(0), byte_chunk.get(3).copied().unwrap_or(0)]);
        }
        for i in 16..64 { w[i] = w[i-16].wrapping_add(w[i-7]).wrapping_add(sigma1(w[i-2])).wrapping_add(sigma0(w[i-15])); }
        let mut working_vars = state;
        for i in 0..64 { let temp1 = working_vars[7].wrapping_add(big_sigma1(working_vars[4])).wrapping_add(ch(working_vars[4], working_vars[5], working_vars[6])).wrapping_add(K[i]).wrapping_add(w[i]); let temp2 = big_sigma0(working_vars[0]).wrapping_add(maj(working_vars[0], working_vars[1], working_vars[2])); working_vars = [temp1.wrapping_add(temp2), working_vars[0], working_vars[1], working_vars[2], working_vars[3].wrapping_add(temp1), working_vars[4], working_vars[5], working_vars[6]]; }
        for (i, &val) in working_vars.iter().enumerate() { state[i] = state[i].wrapping_add(val); }
    }
    for (chunk, &val) in hash.chunks_mut(4).zip(&state) { chunk.copy_from_slice(&val.to_be_bytes()); }
    hash
}

pub fn verify_checksum(data: &[u8], expected: &[u8], checksum_type: ChecksumType) -> bool {
    match checksum_type {
        ChecksumType::Crc32 => { if expected.len() != 4 { return false; } calculate_crc32(data).to_le_bytes() == expected },
        ChecksumType::Sha256 => { if expected.len() != 32 { return false; } calculate_sha256(data).as_slice() == expected },
        _ => false,
    }
}

const fn generate_crc32_table() -> [u32; 256] { let mut table = [0; 256]; let mut i = 0; while i < 256 { let mut crc = i; let mut j = 0; while j < 8 { crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB88320 } else { crc >> 1 }; j += 1; } table[i as usize] = crc; i += 1; } table }
fn sigma0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }
fn sigma1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }
fn big_sigma0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }
fn big_sigma1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }
fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
const K: [u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];