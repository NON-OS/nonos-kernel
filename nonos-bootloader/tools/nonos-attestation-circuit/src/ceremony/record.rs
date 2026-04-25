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

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct DestructionAttestation {
    pub method: String,
    pub witness_count: usize,
    pub attestation_hash: [u8; 32],
    pub video_hash: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ContributionRecord {
    pub round: u32,
    pub contributor_id: String,
    pub contributor_contact: String,
    pub location: String,
    pub randomness_source: String,
    pub previous_params_hash: [u8; 32],
    pub new_params_hash: [u8; 32],
    pub randomness_commitment: [u8; 32],
    pub contribution_timestamp: u64,
    pub destruction_attestation: Option<DestructionAttestation>,
}
