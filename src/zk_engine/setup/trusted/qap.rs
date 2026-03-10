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

use alloc::vec;
use alloc::vec::Vec;
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;

pub(super) fn compute_qap_polynomials(
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

pub(super) fn evaluate_polynomials_at_tau(
    polynomials: &[Vec<FieldElement>],
    tau: &FieldElement,
) -> Result<Vec<FieldElement>, ZKError> {
    let mut evaluations = Vec::with_capacity(polynomials.len());

    for poly in polynomials {
        let mut eval = FieldElement::zero();
        let mut tau_power = FieldElement::one();

        for coeff in poly {
            let term = coeff.mul(&tau_power);
            eval = eval.add(&term);
            tau_power = tau_power.mul(tau);
        }

        evaluations.push(eval);
    }

    Ok(evaluations)
}

pub(super) fn compute_target_polynomial_at_tau(
    num_constraints: usize,
    tau: &FieldElement,
) -> Result<FieldElement, ZKError> {
    let mut result = FieldElement::one();
    for _ in 0..num_constraints {
        result = result.mul(tau);
    }
    result = result.sub(&FieldElement::one());
    Ok(result)
}
