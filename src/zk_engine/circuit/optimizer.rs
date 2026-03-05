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

//! Circuit optimizer for reducing constraint count.

use alloc::vec::Vec;

use super::core::{Circuit, Constraint};

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
