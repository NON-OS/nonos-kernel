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

use super::measurement::KernelMeasurement;
use crate::crypto::ed25519::Signature as Ed25519Signature;
use crate::zk_engine::groth16::Proof;

#[derive(Debug, Clone)]
pub struct KernelAttestation {
    pub measurement: KernelMeasurement,
    pub signature: Ed25519Signature,
    pub zk_proof: Option<Proof>,
    pub public_key: [u8; 32],
    pub timestamp: u64,
}
