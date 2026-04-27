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
use crate::zk_engine::circuit::core::Circuit;
use crate::zk_engine::ZKError;

impl CircuitBuilder {
    pub fn build(mut self, num_witnesses: usize) -> Result<Circuit, ZKError> {
        self.num_variables = self.num_inputs + num_witnesses;

        Ok(Circuit {
            constraints: self.constraints,
            num_variables: self.num_variables,
            num_inputs: self.num_inputs,
            variable_names: self.variable_names,
        })
    }
}
