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

//! Syscall parameter structures.

/// System call numbers for ZK operations
pub const SYS_ZK_PROVE: usize = 400;
pub const SYS_ZK_VERIFY: usize = 401;
pub const SYS_ZK_COMPILE_CIRCUIT: usize = 402;
pub const SYS_ZK_GET_STATS: usize = 403;

/// Maximum sizes for syscall parameters (security limits)
pub const MAX_WITNESS_SIZE: usize = 1_000_000;  // 1MB
pub const MAX_PROOF_SIZE: usize = 10_000;       // 10KB
pub const MAX_PUBLIC_INPUTS: usize = 1000;       // 1000 inputs
pub const MAX_CONSTRAINTS: usize = 100_000;      // 100K constraints

/// ZK Prove syscall parameters
#[repr(C)]
pub struct ZKProveParams {
    pub circuit_id: u32,
    pub witness_ptr: *const u8,
    pub witness_len: usize,
    pub public_inputs_ptr: *const u8,
    pub public_inputs_len: usize,
    pub proof_output_ptr: *mut u8,
    pub proof_output_len: *mut usize,
}

/// ZK Verify syscall parameters
#[repr(C)]
pub struct ZKVerifyParams {
    pub proof_ptr: *const u8,
    pub proof_len: usize,
    pub result_ptr: *mut bool,
}

/// Circuit compilation parameters
#[repr(C)]
pub struct ZKCompileParams {
    pub constraints_ptr: *const u8,
    pub constraints_len: usize,
    pub num_witnesses: usize,
    pub circuit_id_ptr: *mut u32,
}

/// ZK Statistics structure for userspace
#[repr(C)]
pub struct ZKStatsUserspace {
    pub proofs_generated: u64,
    pub proofs_verified: u64,
    pub verification_failures: u64,
    pub circuits_compiled: u32,
    pub avg_proving_time_ms: u64,
    pub avg_verification_time_ms: u64,
}
