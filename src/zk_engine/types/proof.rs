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

use crate::zk_engine::groth16::Proof;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct ZKProof {
    pub circuit_id: u32,
    pub proof_data: Proof,
    pub public_inputs: Vec<Vec<u8>>,
    pub proof_hash: [u8; 32],
    pub created_at: u64,
}
