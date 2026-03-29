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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StageState {
    Pending,
    Running,
    Success,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VerifyState {
    Pending,
    Verifying,
    Valid,
    Invalid,
    NotPresent,
}

#[derive(Clone, Copy)]
pub struct CryptoScreenState {
    pub blake3_hash: [u8; 32],
    pub blake3_revealed: u8,
    pub blake3_state: VerifyState,
    pub ed25519_sig_r: [u8; 32],
    pub ed25519_sig_s: [u8; 32],
    pub ed25519_state: VerifyState,
    pub zk_program_hash: [u8; 32],
    pub zk_capsule: [u8; 32],
    pub zk_state: VerifyState,
    pub stage_uefi: StageState,
    pub stage_security: StageState,
    pub stage_hardware: StageState,
    pub stage_kernel: StageState,
    pub stage_crypto: StageState,
    pub stage_handoff: StageState,
    pub progress: u32,
    pub total_stages: u32,
}

impl Default for CryptoScreenState {
    fn default() -> Self {
        Self {
            blake3_hash: [0u8; 32],
            blake3_revealed: 0,
            blake3_state: VerifyState::Pending,
            ed25519_sig_r: [0u8; 32],
            ed25519_sig_s: [0u8; 32],
            ed25519_state: VerifyState::Pending,
            zk_program_hash: [0u8; 32],
            zk_capsule: [0u8; 32],
            zk_state: VerifyState::Pending,
            stage_uefi: StageState::Pending,
            stage_security: StageState::Pending,
            stage_hardware: StageState::Pending,
            stage_kernel: StageState::Pending,
            stage_crypto: StageState::Pending,
            stage_handoff: StageState::Pending,
            progress: 0,
            total_stages: 6,
        }
    }
}
