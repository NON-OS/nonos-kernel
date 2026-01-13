// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::crypto::zk::halo2::FR_MODULUS_BYTES;

pub const P: [u8; 32] = [
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c,
    0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

pub const R: [u8; 32] = FR_MODULUS_BYTES;

pub const SECURITY_BITS: u32 = 100;

pub const MIN_K: u32 = super::MIN_K;

pub const MAX_K: u32 = super::MAX_K;

pub const G1_SIZE: usize = 64;

pub const G2_SIZE: usize = 128;

pub const FR_SIZE: usize = 32;

pub const BLAKE2B_DIGEST_SIZE: usize = 64;

pub const TYPICAL_PROOF_SIZE: usize = 1024;

pub const TWO_ADICITY: u32 = 28;
