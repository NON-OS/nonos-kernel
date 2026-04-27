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
use crate::zk_engine::circuit::core::Variable;

impl CircuitBuilder {
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
}
