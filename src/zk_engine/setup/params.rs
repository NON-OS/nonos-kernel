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

//! Setup parameters and key structures.

use crate::zk_engine::groth16::{FieldElement, ProvingKey, VerifyingKey};

/// Complete setup output
#[derive(Debug, Clone)]
pub struct SetupParameters {
    pub proving_key: ProvingKey,
    pub verifying_key: VerifyingKey,
    pub toxic_waste: Option<ToxicWaste>,
}

/// Toxic waste that must be destroyed after setup
#[derive(Debug, Clone)]
pub struct ToxicWaste {
    pub tau: FieldElement,
    pub alpha: FieldElement,
    pub beta: FieldElement,
    pub gamma: FieldElement,
    pub delta: FieldElement,
}

impl ToxicWaste {
    pub fn destroy(&mut self) {
        // Securely zero out the toxic waste
        self.tau = FieldElement::zero();
        self.alpha = FieldElement::zero();
        self.beta = FieldElement::zero();
        self.gamma = FieldElement::zero();
        self.delta = FieldElement::zero();
    }
}
