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

#[cfg(test)]
mod tests {
    use super::super::types::{ZKConfig, ZKProof};
    use super::super::engine::ZKEngine;

    #[test]
    fn test_zk_engine_initialization() {
        let config = ZKConfig::default();
        let engine = ZKEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_proof_serialization() {
        let proof = ZKProof {
            circuit_id: 123,
            proof_data: vec![1, 2, 3, 4],
            public_inputs: vec![vec![5, 6], vec![7, 8, 9]],
            proof_hash: [0xAB; 32],
            created_at: 1234567890,
        };

        let config = ZKConfig::default();
        let engine = ZKEngine::new(config).unwrap();

        let serialized = engine.serialize_proof(&proof);
        let deserialized = engine.deserialize_proof(&serialized).unwrap();

        assert_eq!(proof.circuit_id, deserialized.circuit_id);
        assert_eq!(proof.proof_data, deserialized.proof_data);
        assert_eq!(proof.public_inputs, deserialized.public_inputs);
        assert_eq!(proof.proof_hash, deserialized.proof_hash);
        assert_eq!(proof.created_at, deserialized.created_at);
    }
}
