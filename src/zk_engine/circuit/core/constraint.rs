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
use super::variable::Variable;
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;

#[derive(Debug, Clone)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

impl Constraint {
    pub fn new(a: LinearCombination, b: LinearCombination, c: LinearCombination) -> Self {
        Self { a, b, c }
    }

    pub fn enforce_equal(left: LinearCombination, right: LinearCombination) -> Self {
        let mut c = left.clone();
        let mut neg_right = right.clone();
        neg_right.scale(&FieldElement::zero().sub(&FieldElement::one()));
        c.add(&neg_right);

        Self::new(
            LinearCombination::from_constant(FieldElement::one()),
            c,
            LinearCombination::new(),
        )
    }

    pub fn enforce_multiplication(a_var: Variable, b_var: Variable, c_var: Variable) -> Self {
        Self::new(
            LinearCombination::from_variable(a_var),
            LinearCombination::from_variable(b_var),
            LinearCombination::from_variable(c_var),
        )
    }

    pub fn verify(&self, assignment: &[FieldElement]) -> Result<bool, ZKError> {
        let a_val = self.a.evaluate(assignment)?;
        let b_val = self.b.evaluate(assignment)?;
        let c_val = self.c.evaluate(assignment)?;

        let left = a_val.mul(&b_val);
        Ok(left.equals(&c_val))
    }

    pub fn default_multiplication(index: usize) -> Self {
        let var_a = Variable::new(index * 3);
        let var_b = Variable::new(index * 3 + 1);
        let var_c = Variable::new(index * 3 + 2);

        Self::enforce_multiplication(var_a, var_b, var_c)
    }
}
