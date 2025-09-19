//! Circuit representation and compilation for Groth16
//!
//! This module handles R1CS (Rank-1 Constraint System) circuits used in Groth16 proofs.
//! It provides constraint representation, variable management, and circuit compilation.

use alloc::{vec, vec::Vec, collections::BTreeMap};
use super::groth16::{FieldElement, G1Point, G2Point};
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
    
    pub fn dummy_constraint(index: usize) -> Self {
        let var_a = Variable::new(index * 3);
        let var_b = Variable::new(index * 3 + 1);
        let var_c = Variable::new(index * 3 + 2);
        
        Self::enforce_multiplication(var_a, var_b, var_c)
    }
}

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
        let one_lc = LinearCombination::from_constant(FieldElement::one());
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

/// Circuit optimizer for reducing constraint count
pub struct CircuitOptimizer;

impl CircuitOptimizer {
    pub fn optimize(circuit: Circuit) -> Circuit {
        // Simple optimization: remove redundant constraints
        let mut optimized_constraints = Vec::new();
        
        for constraint in circuit.constraints {
            if !Self::is_trivial(&constraint) {
                optimized_constraints.push(constraint);
            }
        }
        
        Circuit {
            constraints: optimized_constraints,
            num_variables: circuit.num_variables,
            num_inputs: circuit.num_inputs,
            variable_names: circuit.variable_names,
        }
    }
    
    fn is_trivial(constraint: &Constraint) -> bool {
        // Check if constraint is 0 * 0 = 0
        constraint.a.terms.is_empty() && 
        constraint.b.terms.is_empty() && 
        constraint.c.terms.is_empty()
    }
}

/// Example circuits for testing
pub mod examples {
    use super::*;
    
    /// Create a simple multiplication circuit: x * y = z
    pub fn multiplication_circuit() -> Circuit {
        let mut builder = CircuitBuilder::new();
        
        let x = builder.alloc_input(Some("x"));
        let y = builder.alloc_input(Some("y")); 
        let z = builder.alloc_variable(Some("z"));
        
        builder.enforce_multiplication(x, y, z);
        
        builder.build(1).unwrap() // 1 witness for the result
    }
    
    /// Create a hash preimage circuit
    pub fn hash_preimage_circuit() -> Circuit {
        let mut builder = CircuitBuilder::new();
        
        // Simplified hash circuit (would be much more complex in practice)
        let preimage = builder.alloc_input(Some("preimage"));
        let hash = builder.alloc_input(Some("hash"));
        let temp = builder.alloc_variable(Some("temp"));
        
        // preimage^2 = temp (simplified)
        builder.enforce_multiplication(preimage, preimage, temp);
        
        // temp = hash (simplified equality check)
        builder.enforce_equal(
            LinearCombination::from_variable(temp),
            LinearCombination::from_variable(hash)
        );
        
        builder.build(1).unwrap() // 1 witness for the result
    }
    
    /// Create a range proof circuit (prove x is in [0, 2^bits))
    pub fn range_proof_circuit(bits: usize) -> Circuit {
        let mut builder = CircuitBuilder::new();
        
        let x = builder.alloc_input(Some("x"));
        builder.add_range_constraint(x, bits);
        
        builder.build(1).unwrap() // 1 witness for the result
    }
}