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

use super::attestation::KernelAttestation;
use alloc::vec::Vec;

impl KernelAttestation {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.measurement.to_bytes());
        data.extend_from_slice(&self.signature.to_bytes());
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.timestamp.to_le_bytes());

        if let Some(ref proof) = self.zk_proof {
            data.push(1);
            data.extend_from_slice(&proof.serialize());
        } else {
            data.push(0);
        }

        data
    }
}
