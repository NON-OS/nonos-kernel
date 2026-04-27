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

use super::state::CircuitBuilder;
use crate::zk_engine::circuit::core::{Constraint, LinearCombination, Variable};
use crate::zk_engine::groth16::FieldElement;

impl CircuitBuilder {
    pub fn add_boolean_constraint(&mut self, var: Variable) {
        let var_lc = LinearCombination::from_variable(var);

        let mut var_minus_one = var_lc.clone();
        var_minus_one.add_term(Variable::ONE, FieldElement::zero().sub(&FieldElement::one()));

        self.enforce_constraint(Constraint::new(var_lc, var_minus_one, LinearCombination::new()));
    }

    pub fn add_range_constraint(&mut self, var: Variable, bits: usize) {
        let mut current = LinearCombination::from_variable(var);
        let mut power_of_two = FieldElement::one();

        for i in 0..bits {
            let bit_var = self.alloc_variable(Some(&alloc::format!("bit_{}", i)));
            self.add_boolean_constraint(bit_var);

            let mut bit_contribution = LinearCombination::from_variable(bit_var);
            bit_contribution.scale(&power_of_two);

            current.add_term(bit_var, FieldElement::zero().sub(&power_of_two));
            power_of_two = power_of_two.add(&power_of_two);
        }

        self.enforce_equal(current, LinearCombination::new());
    }
}
