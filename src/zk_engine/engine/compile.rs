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

use super::super::circuit::{CircuitBuilder, Constraint};
use super::super::groth16::Groth16Prover;
use super::super::types::ZKError;
use super::core::ZKEngine;
use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::Ordering;

impl ZKEngine {
    pub fn compile_circuit(
        &self,
        constraints: Vec<Constraint>,
        num_witnesses: usize,
    ) -> Result<u32, ZKError> {
        if constraints.len() > self.config.max_constraints {
            return Err(ZKError::InvalidCircuit);
        }
        if num_witnesses > self.config.max_witnesses {
            return Err(ZKError::InvalidWitness);
        }
        let circuit_id = self.next_circuit_id.fetch_add(1, Ordering::SeqCst);
        let num_constraints = constraints.len();
        let mut builder = CircuitBuilder::new();
        for constraint in constraints {
            builder.add_constraint(constraint)?;
        }
        let circuit = builder.build(num_witnesses)?;
        let start_time = crate::time::timestamp_millis();
        let (proving_key, verifying_key) = Groth16Prover::generate_keys(&circuit)?;
        let key_gen_time = crate::time::timestamp_millis() - start_time;
        {
            let mut circuits = self.circuits.write();
            let mut proving_keys = self.proving_keys.write();
            let mut verifying_keys = self.verifying_keys.write();
            circuits.insert(circuit_id, Box::new(circuit));
            proving_keys.insert(circuit_id, proving_key);
            verifying_keys.insert(circuit_id, verifying_key);
        }
        self.stats.circuits_compiled.fetch_add(1, Ordering::SeqCst);
        crate::log::info!(
            "Compiled circuit {} with {} constraints, key generation took {}ms",
            circuit_id,
            num_constraints,
            key_gen_time
        );
        Ok(circuit_id)
    }
}
