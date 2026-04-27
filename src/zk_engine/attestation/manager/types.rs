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

use super::super::types::KernelMeasurement;
use crate::crypto::ed25519::KeyPair;
use crate::zk_engine::circuit::Circuit;
use crate::zk_engine::{ZKEngine, ZKError};
use alloc::vec::Vec;

pub struct AttestationManager {
    pub(super) signing_keypair: KeyPair,
    pub(super) measurement_history: Vec<KernelMeasurement>,
    pub(super) attestation_circuit: Option<Circuit>,
    pub(super) zk_engine: Option<&'static ZKEngine>,
}

impl AttestationManager {
    pub fn new() -> Result<Self, ZKError> {
        Ok(Self {
            signing_keypair: KeyPair::generate(),
            measurement_history: Vec::new(),
            attestation_circuit: None,
            zk_engine: None,
        })
    }

    pub fn initialize_with_engine(&mut self, engine: &'static ZKEngine) -> Result<(), ZKError> {
        self.zk_engine = Some(engine);
        self.attestation_circuit = Some(super::proof::build_attestation_circuit()?);
        Ok(())
    }

    pub fn get_measurement_history(&self) -> &[KernelMeasurement] {
        &self.measurement_history
    }

    pub fn clear_history(&mut self) {
        self.measurement_history.clear();
    }

    pub fn rotate_key(&mut self) -> Result<(), ZKError> {
        self.signing_keypair = KeyPair::generate();
        Ok(())
    }
}
