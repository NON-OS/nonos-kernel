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

//! Circuit builder for constructing R1CS constraints.

use alloc::{vec::Vec, collections::BTreeMap};
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;

use super::core::{Variable, LinearCombination, Constraint, Circuit};

/// Circuit builder for constructing R1CS constraints
pub struct CircuitBuilder {
    pub constraints: Vec<Constraint>,
    pub num_variables: usize,
    pub num_inputs: usize,
    pub variable_names: BTreeMap<Variable, alloc::string::String>,
}

impl CircuitBuilder {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            num_variables: 0,
            num_inputs: 0,
            variable_names: BTreeMap::new(),
        }
    }

    pub fn alloc_variable(&mut self, name: Option<&str>) -> Variable {
        let var = Variable::new(self.num_variables);
        self.num_variables += 1;

        if let Some(name) = name {
            self.variable_names.insert(var, alloc::string::String::from(name));
        }

        var
    }

    pub fn alloc_input(&mut self, name: Option<&str>) -> Variable {
        let var = self.alloc_variable(name);
        self.num_inputs += 1;
        var
    }

    pub fn enforce_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    pub fn enforce_equal(&mut self, left: LinearCombination, right: LinearCombination) {
        self.enforce_constraint(Constraint::enforce_equal(left, right));
    }

    pub fn enforce_multiplication(&mut self, a: Variable, b: Variable, c: Variable) {
        self.enforce_constraint(Constraint::enforce_multiplication(a, b, c));
    }

    pub fn build(mut self, num_witnesses: usize) -> Result<Circuit, ZKError> {
        // Set the number of variables to include witnesses
        self.num_variables = self.num_inputs + num_witnesses;

        Ok(Circuit {
            constraints: self.constraints,
            num_variables: self.num_variables,
            num_inputs: self.num_inputs,
            variable_names: self.variable_names,
        })
    }

    pub fn add_boolean_constraint(&mut self, var: Variable) {
        // Enforce var * (var - 1) = 0, ensuring var is 0 or 1
        let var_lc = LinearCombination::from_variable(var);

        let mut var_minus_one = var_lc.clone();
        var_minus_one.add_term(Variable::ONE, FieldElement::zero().sub(&FieldElement::one()));

        self.enforce_constraint(Constraint::new(
            var_lc,
            var_minus_one,
            LinearCombination::new(),
        ));
    }

    pub fn add_range_constraint(&mut self, var: Variable, bits: usize) {
        // Decompose variable into bits and enforce each bit is boolean
        let mut current = LinearCombination::from_variable(var);
        let mut power_of_two = FieldElement::one();

        for i in 0..bits {
            let bit_var = self.alloc_variable(Some(&alloc::format!("bit_{}", i)));
            self.add_boolean_constraint(bit_var);

            let mut bit_contribution = LinearCombination::from_variable(bit_var);
            bit_contribution.scale(&power_of_two);

            current.add_term(bit_var, FieldElement::zero().sub(&power_of_two));

            power_of_two = power_of_two.add(&power_of_two); // Double
        }

        self.enforce_equal(current, LinearCombination::new());
    }

    /// Add a constraint to the circuit
    pub fn add_constraint(&mut self, constraint: Constraint) -> Result<(), ZKError> {
        self.constraints.push(constraint);
        Ok(())
    }
}
