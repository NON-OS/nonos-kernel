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
use crate::zk_engine::ZKError;

impl CircuitBuilder {
    pub fn enforce_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    pub fn enforce_equal(&mut self, left: LinearCombination, right: LinearCombination) {
        self.enforce_constraint(Constraint::enforce_equal(left, right));
    }

    pub fn enforce_multiplication(&mut self, a: Variable, b: Variable, c: Variable) {
        self.enforce_constraint(Constraint::enforce_multiplication(a, b, c));
    }

    pub fn add_constraint(&mut self, constraint: Constraint) -> Result<(), ZKError> {
        self.constraints.push(constraint);
        Ok(())
    }
}
