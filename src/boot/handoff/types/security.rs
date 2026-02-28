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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Measurements {
    pub kernel_sha256: [u8; 32],
    pub kernel_sig_ok: u8,
    pub secure_boot: u8,
    pub zk_attestation_ok: u8,
    pub reserved: [u8; 5],
}

impl Default for Measurements {
    fn default() -> Self {
        Self {
            kernel_sha256: [0; 32],
            kernel_sig_ok: 0,
            secure_boot: 0,
            zk_attestation_ok: 0,
            reserved: [0; 5],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZkAttestation {
    pub verified: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
    pub program_hash: [u8; 32],
    pub capsule_commitment: [u8; 32],
}

impl Default for ZkAttestation {
    fn default() -> Self {
        Self {
            verified: 0,
            flags: 0,
            reserved: [0; 6],
            program_hash: [0; 32],
            capsule_commitment: [0; 32],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RngSeed {
    pub seed32: [u8; 32],
}

impl Default for RngSeed {
    fn default() -> Self {
        Self { seed32: [0; 32] }
    }
}
