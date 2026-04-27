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

use crate::zk_engine::circuit::Circuit;
use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::keys::{ProvingKey, VerifyingKey};
use crate::zk_engine::groth16::proof::Proof;
use crate::zk_engine::ZKError;

pub struct Groth16Prover;

impl Groth16Prover {
    pub fn new(_setup: &crate::zk_engine::setup::SetupParameters) -> Result<Self, ZKError> {
        Ok(Groth16Prover)
    }

    pub fn generate_keys(circuit: &Circuit) -> Result<(ProvingKey, VerifyingKey), ZKError> {
        let setup = crate::zk_engine::setup::TrustedSetup::setup(circuit)?;
        Ok((setup.proving_key, setup.verifying_key))
    }

    pub fn prove(
        proving_key: &ProvingKey,
        circuit: &Circuit,
        witness: &[FieldElement],
        public_inputs: &[FieldElement],
        circuit_id: u32,
    ) -> Result<Proof, ZKError> {
        super::prove_impl::create_proof(proving_key, circuit, witness, public_inputs, circuit_id)
    }
}
