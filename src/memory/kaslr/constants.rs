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

pub const DEFAULT_WINDOW_SIZE: u64 = 0x40000000;
pub const MIN_SLIDE: u64 = 0x10000000;
pub const MAX_SLIDE: u64 = 0x80000000;
pub const SAFE_SLIDE_MIN: u64 = 0x1000000;
pub const SAFE_SLIDE_MAX: u64 = 0x100000000;
pub const INITIAL_ENTROPY_SEED: u64 = 0x1337DEADBEEF4242;
pub const ENTROPY_MIX_MULTIPLIER: u64 = 0x2545f4914f6cdd1d;
pub const NONCE_GEN_MULTIPLIER: u64 = 0x9e3779b97f4a7c15;
pub const NONCE_ROTATE_BITS: u32 = 23;
pub const ENTROPY_SPIN_ITERATIONS: usize = 1000;
pub const CPUID_FEATURES_LEAF: u32 = 1;
pub const CPUID_EXTENDED_LEAF: u32 = 7;
pub const RDRAND_FEATURE_BIT: u32 = 30; // in CPUID.01H:ECX
pub const RDSEED_FEATURE_BIT: u32 = 18; // in CPUID.07H:EBX
pub const KDF_LABEL_PREFIX: &[u8] = b"NONOS-KASLR-KDF:";
pub const HASH_OUTPUT_SIZE: usize = 32; // (SHA3-256)
pub const INTEGRITY_CHECK_LABEL: &[u8] = b"integrity_check";
pub const INTEGRITY_CHECK_BUFFER_SIZE: usize = 64;
