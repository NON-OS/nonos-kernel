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

use super::circuit::Circuit;
use super::constraint::Constraint;
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;
use alloc::vec;
use alloc::vec::Vec;

impl Circuit {
    pub fn compute_witness_map(
        &self,
        inputs: &[FieldElement],
    ) -> Result<Vec<FieldElement>, ZKError> {
        if inputs.len() != self.num_inputs {
            return Err(ZKError::InvalidWitness);
        }

        let mut assignment = vec![FieldElement::zero(); self.num_variables];

        for (i, &input) in inputs.iter().enumerate() {
            if i < assignment.len() {
                assignment[i] = input;
            }
        }

        for _ in 0..10 {
            let mut changed = false;

            for constraint in &self.constraints {
                if let Ok(should_be_zero) = self.try_solve_constraint(constraint, &mut assignment) {
                    if !should_be_zero.is_zero() {
                        changed = true;
                    }
                }
            }

            if !changed {
                break;
            }
        }

        if !self.verify_assignment(&assignment)? {
            return Err(ZKError::InvalidWitness);
        }

        Ok(assignment)
    }

    fn try_solve_constraint(
        &self,
        constraint: &Constraint,
        assignment: &mut [FieldElement],
    ) -> Result<FieldElement, ZKError> {
        let a_val = constraint.a.evaluate(assignment)?;
        let b_val = constraint.b.evaluate(assignment)?;
        let c_val = constraint.c.evaluate(assignment)?;

        let left = a_val.mul(&b_val);
        let diff = left.sub(&c_val);

        Ok(diff)
    }
}
