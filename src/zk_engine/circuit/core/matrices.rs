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

use super::circuit::Circuit;
use crate::zk_engine::groth16::FieldElement;
use alloc::vec;
use alloc::vec::Vec;

impl Circuit {
    pub fn get_matrices(
        &self,
    ) -> (Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>) {
        let m = self.constraints.len();
        let n = self.num_variables + 1;

        let mut a_matrix = vec![vec![FieldElement::zero(); n]; m];
        let mut b_matrix = vec![vec![FieldElement::zero(); n]; m];
        let mut c_matrix = vec![vec![FieldElement::zero(); n]; m];

        for (i, constraint) in self.constraints.iter().enumerate() {
            for (var, coeff) in &constraint.a.terms {
                a_matrix[i][var.index()] = *coeff;
            }

            for (var, coeff) in &constraint.b.terms {
                b_matrix[i][var.index()] = *coeff;
            }

            for (var, coeff) in &constraint.c.terms {
                c_matrix[i][var.index()] = *coeff;
            }
        }

        (a_matrix, b_matrix, c_matrix)
    }
}
