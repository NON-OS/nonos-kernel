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

/// Boot-time measurements for kernel security verification.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Measurements {
    pub kernel_blake3: [u8; 32],
    pub kernel_sig_ok: u8,
    pub secure_boot: u8,
    pub zk_attestation_ok: u8,
    pub reserved: [u8; 5],
}

/// Zero-knowledge attestation proof verification result.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ZkAttestation {
    pub verified: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
    pub program_hash: [u8; 32],
    pub capsule_commitment: [u8; 32],
}

/// 256-bit entropy seed for kernel CSPRNG initialization.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RngSeed {
    pub seed32: [u8; 32],
}
