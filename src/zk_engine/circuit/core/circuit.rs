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

use super::constraint::Constraint;
use super::variable::Variable;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

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

    pub fn with_params(
        constraints: Vec<Constraint>,
        num_variables: usize,
        num_inputs: usize,
    ) -> Self {
        Self { constraints, num_variables, num_inputs, variable_names: BTreeMap::new() }
    }
}
