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
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::circuit::Circuit;
use crate::zk_engine::ZKError;
use crate::zk_engine::setup::powers::Powers;
use crate::zk_engine::setup::params::{SetupParameters, ToxicWaste};
use super::keys::{build_proving_key, build_verifying_key};
use super::qap::{compute_qap_polynomials, evaluate_polynomials_at_tau, compute_target_polynomial_at_tau};
use super::serialize::{load_from_storage, save_to_storage};

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
            &powers, &a_tau, &b_tau, &c_tau,
            &alpha, &beta, &gamma, &delta,
            circuit.num_variables, circuit.num_inputs
        )?;

        let verifying_key = build_verifying_key(
            &a_tau, &alpha, &beta, &gamma, &delta,
            circuit.num_inputs
        )?;

        let toxic_waste = ToxicWaste { tau, alpha, beta, gamma, delta };

        Ok(SetupParameters {
            proving_key,
            verifying_key,
            toxic_waste: Some(toxic_waste),
        })
    }

    pub fn load_or_generate(config: &crate::zk_engine::ZKConfig) -> Result<SetupParameters, ZKError> {
        if let Some(ref path) = config.trusted_setup_path {
            if let Ok(params) = load_from_storage(path) {
                return Ok(params);
            }
        }

        let default_paths = [
            "/nonos/zk/trusted_setup.bin",
            "/etc/nonos/zk_setup.bin",
            "/boot/zk_params.bin",
        ];

        for path in &default_paths {
            if let Ok(params) = load_from_storage(path) {
                return Ok(params);
            }
        }

        use crate::zk_engine::circuit::{LinearCombination, Constraint};
        let one = LinearCombination::from_constant(FieldElement::one());
        let identity_constraint = Constraint::new(one.clone(), one.clone(), one);
        let dummy_circuit = Circuit::with_params(vec![identity_constraint], 1, 0);
        let params = TrustedSetup::setup(&dummy_circuit)?;

        if let Some(ref path) = config.trusted_setup_path {
            let _ = save_to_storage(path, &params);
        }

        Ok(params)
    }
}

pub struct UniversalSetup;

impl UniversalSetup {
    pub fn phase1_setup(max_constraints: usize) -> Result<Powers, ZKError> {
        Powers::new(max_constraints)
    }

    pub fn phase2_setup(circuit: &Circuit, _powers: &Powers) -> Result<SetupParameters, ZKError> {
        TrustedSetup::setup(circuit)
    }
}
