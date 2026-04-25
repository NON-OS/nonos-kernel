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

use super::Variable;
use crate::zk_engine::groth16::FieldElement;
use alloc::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct LinearCombination {
    pub terms: BTreeMap<Variable, FieldElement>,
}

impl LinearCombination {
    pub fn new() -> Self {
        Self { terms: BTreeMap::new() }
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
}
