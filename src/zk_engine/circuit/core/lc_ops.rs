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

use super::linear_combination::LinearCombination;
use super::Variable;
use crate::zk_engine::groth16::FieldElement;

impl LinearCombination {
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
}
