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

use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn compute_qap_polynomials(
    a_matrix: &[Vec<FieldElement>],
    b_matrix: &[Vec<FieldElement>],
    c_matrix: &[Vec<FieldElement>],
) -> Result<(Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>), ZKError> {
    let m = a_matrix.len();
    let n = a_matrix[0].len();

    let mut a_poly = vec![vec![FieldElement::zero(); m]; n];
    let mut b_poly = vec![vec![FieldElement::zero(); m]; n];
    let mut c_poly = vec![vec![FieldElement::zero(); m]; n];

    for i in 0..n {
        for j in 0..m {
            a_poly[i][j] = a_matrix[j][i];
            b_poly[i][j] = b_matrix[j][i];
            c_poly[i][j] = c_matrix[j][i];
        }
    }

    Ok((a_poly, b_poly, c_poly))
}
