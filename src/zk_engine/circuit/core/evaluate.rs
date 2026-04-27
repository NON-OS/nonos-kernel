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

use super::linear_combination::LinearCombination;
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;

impl LinearCombination {
    pub fn evaluate(&self, assignment: &[FieldElement]) -> Result<FieldElement, ZKError> {
        let mut result = FieldElement::zero();

        for (var, coeff) in &self.terms {
            let value = if var.index() == 0 {
                FieldElement::one()
            } else if var.index() - 1 < assignment.len() {
                assignment[var.index() - 1]
            } else {
                return Err(ZKError::InvalidWitness);
            };

            let term = coeff.mul(&value);
            result = result.add(&term);
        }

        Ok(result)
    }
}
