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

use crate::zk_engine::circuit::Circuit;
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::setup::params::{SetupParameters, ToxicWaste};
use crate::zk_engine::setup::powers::Powers;
use crate::zk_engine::setup::trusted::keys::{build_proving_key, build_verifying_key};
use crate::zk_engine::setup::trusted::qap::{
    compute_qap_polynomials, compute_target_polynomial_at_tau, evaluate_polynomials_at_tau,
};
use crate::zk_engine::ZKError;

pub struct TrustedSetup;

impl TrustedSetup {
    pub fn setup(circuit: &Circuit) -> Result<SetupParameters, ZKError> {
        let tau = FieldElement::random();
        let alpha = FieldElement::random();
        let beta = FieldElement::random();
        let gamma = FieldElement::random();
        let delta = FieldElement::random();

        let (a_matrix, b_matrix, c_matrix) = circuit.get_matrices();
        let m = a_matrix.len();
        if m == 0 {
            return Err(ZKError::InvalidCircuit);
        }
        let n = a_matrix[0].len();

        let max_degree = m.max(n);
        let powers = Powers::new(max_degree)?;

        let (a_poly, b_poly, c_poly) = compute_qap_polynomials(&a_matrix, &b_matrix, &c_matrix)?;

        let a_tau = evaluate_polynomials_at_tau(&a_poly, &tau)?;
        let b_tau = evaluate_polynomials_at_tau(&b_poly, &tau)?;
        let c_tau = evaluate_polynomials_at_tau(&c_poly, &tau)?;

        let t_tau = compute_target_polynomial_at_tau(m, &tau)?;
        if t_tau.is_zero() {
            return Err(ZKError::InvalidCircuit);
        }

        let proving_key = build_proving_key(
            &powers,
            &a_tau,
            &b_tau,
            &c_tau,
            &alpha,
            &beta,
            &gamma,
            &delta,
            circuit.num_variables,
            circuit.num_inputs,
        )?;

        let verifying_key =
            build_verifying_key(&a_tau, &alpha, &beta, &gamma, &delta, circuit.num_inputs)?;

        let toxic_waste = ToxicWaste { tau, alpha, beta, gamma, delta };

        Ok(SetupParameters { proving_key, verifying_key, toxic_waste: Some(toxic_waste) })
    }
}
