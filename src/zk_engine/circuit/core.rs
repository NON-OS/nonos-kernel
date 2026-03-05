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

//! Core circuit types and structures.

use alloc::{vec, vec::Vec, collections::BTreeMap};
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;

/// Variable in a constraint system
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Variable(pub usize);

impl Variable {
    pub const ONE: Variable = Variable(0);

    pub fn new(index: usize) -> Self {
        Variable(index + 1) // Reserve 0 for constant ONE
    }

    pub fn index(&self) -> usize {
        self.0
    }
}

/// Linear combination of variables with coefficients
#[derive(Debug, Clone)]
pub struct LinearCombination {
    pub terms: BTreeMap<Variable, FieldElement>,
}

impl LinearCombination {
    pub fn new() -> Self {
        Self {
            terms: BTreeMap::new(),
        }
    }

    pub fn from_variable(var: Variable) -> Self {
        let mut lc = Self::new();
        lc.terms.insert(var, FieldElement::one());
        lc
    }

    pub fn from_constant(value: FieldElement) -> Self {
        let mut lc = Self::new();
        if !value.is_zero() {
            lc.terms.insert(Variable::ONE, value);
        }
        lc
    }

    pub fn add_term(&mut self, var: Variable, coeff: FieldElement) {
        if coeff.is_zero() {
            return;
        }

        if let Some(existing) = self.terms.get(&var) {
            let new_coeff = existing.add(&coeff);
            if new_coeff.is_zero() {
                self.terms.remove(&var);
            } else {
                self.terms.insert(var, new_coeff);
            }
        } else {
            self.terms.insert(var, coeff);
        }
    }

    pub fn scale(&mut self, factor: &FieldElement) {
        if factor.is_zero() {
            self.terms.clear();
            return;
        }

        for coeff in self.terms.values_mut() {
            *coeff = coeff.mul(factor);
        }
    }

    pub fn add(&mut self, other: &LinearCombination) {
        for (var, coeff) in &other.terms {
            self.add_term(*var, *coeff);
        }
    }

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

/// R1CS constraint: (A . z) * (B . z) = (C . z)
/// where z is the assignment vector [1, x1, x2, ..., xn]
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
        neg_right.scale(&FieldElement::zero().sub(&FieldElement::one())); // Negate
        c.add(&neg_right);

        Self::new(
            LinearCombination::from_constant(FieldElement::one()),
            c,
            LinearCombination::new(), // Zero
        )
    }

    pub fn enforce_multiplication(
        a_var: Variable,
        b_var: Variable,
        c_var: Variable
    ) -> Self {
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

    /// Create a default multiplication constraint for parsing.
    pub fn default_multiplication(index: usize) -> Self {
        let var_a = Variable::new(index * 3);
        let var_b = Variable::new(index * 3 + 1);
        let var_c = Variable::new(index * 3 + 2);

        Self::enforce_multiplication(var_a, var_b, var_c)
    }
}

/// Compiled circuit ready for proof generation
#[derive(Clone)]
pub struct Circuit {
    pub constraints: Vec<Constraint>,
    pub num_variables: usize,
    pub num_inputs: usize,
    pub variable_names: BTreeMap<Variable, alloc::string::String>,
}

impl Circuit {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            num_variables: 0,
            num_inputs: 0,
            variable_names: BTreeMap::new(),
        }
    }

    pub fn with_params(constraints: Vec<Constraint>, num_variables: usize, num_inputs: usize) -> Self {
        Self {
            constraints,
            num_variables,
            num_inputs,
            variable_names: BTreeMap::new(),
        }
    }

    pub fn verify_assignment(&self, assignment: &[FieldElement]) -> Result<bool, ZKError> {
        if assignment.len() != self.num_variables {
            return Err(ZKError::InvalidWitness);
        }

        for constraint in &self.constraints {
            if !constraint.verify(assignment)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn compute_witness_map(&self, inputs: &[FieldElement]) -> Result<Vec<FieldElement>, ZKError> {
        if inputs.len() != self.num_inputs {
            return Err(ZKError::InvalidWitness);
        }

        let mut assignment = vec![FieldElement::zero(); self.num_variables];

        // Set input values
        for (i, &input) in inputs.iter().enumerate() {
            if i < assignment.len() {
                assignment[i] = input;
            }
        }

        // Try to satisfy constraints (simplified approach)
        for _ in 0..10 { // Max iterations to avoid infinite loops
            let mut changed = false;

            for constraint in &self.constraints {
                // Try to deduce unknown variables
                if let Ok(should_be_zero) = self.try_solve_constraint(constraint, &mut assignment) {
                    if !should_be_zero.is_zero() {
                        // Constraint not satisfied, try to fix it
                        changed = true;
                    }
                }
            }

            if !changed {
                break;
            }
        }

        // Verify final assignment
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

    pub fn get_matrices(&self) -> (Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>) {
        let m = self.constraints.len();
        let n = self.num_variables + 1; // +1 for constant term

        let mut a_matrix = vec![vec![FieldElement::zero(); n]; m];
        let mut b_matrix = vec![vec![FieldElement::zero(); n]; m];
        let mut c_matrix = vec![vec![FieldElement::zero(); n]; m];

        for (i, constraint) in self.constraints.iter().enumerate() {
            // Fill A matrix
            for (var, coeff) in &constraint.a.terms {
                a_matrix[i][var.index()] = *coeff;
            }

            // Fill B matrix
            for (var, coeff) in &constraint.b.terms {
                b_matrix[i][var.index()] = *coeff;
            }

            // Fill C matrix
            for (var, coeff) in &constraint.c.terms {
                c_matrix[i][var.index()] = *coeff;
            }
        }

        (a_matrix, b_matrix, c_matrix)
    }
}
