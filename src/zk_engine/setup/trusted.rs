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

//! Trusted setup implementation.

use alloc::{vec, vec::Vec};
use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point, ProvingKey, VerifyingKey};
use crate::zk_engine::circuit::Circuit;
use crate::zk_engine::ZKError;
use super::powers::Powers;
use super::params::{SetupParameters, ToxicWaste};

/// Trusted setup implementation
pub struct TrustedSetup;

impl TrustedSetup {
    /// Perform trusted setup for a circuit
    pub fn setup(circuit: &Circuit) -> Result<SetupParameters, ZKError> {
        // Generate toxic waste
        let tau = FieldElement::random();
        let alpha = FieldElement::random();
        let beta = FieldElement::random();
        let gamma = FieldElement::random();
        let delta = FieldElement::random();

        // Get circuit matrices
        let (a_matrix, b_matrix, c_matrix) = circuit.get_matrices();
        let m = a_matrix.len(); // number of constraints
        let n = a_matrix[0].len(); // number of variables + 1

        // Generate powers of tau
        let max_degree = m.max(n);
        let powers = Powers::new(max_degree)?;

        // Compute QAP polynomials (simplified)
        let (a_poly, b_poly, c_poly) = Self::compute_qap_polynomials(&a_matrix, &b_matrix, &c_matrix)?;

        // Evaluate polynomials at tau
        let a_tau = Self::evaluate_polynomials_at_tau(&a_poly, &tau)?;
        let b_tau = Self::evaluate_polynomials_at_tau(&b_poly, &tau)?;
        let c_tau = Self::evaluate_polynomials_at_tau(&c_poly, &tau)?;

        // Compute target polynomial t(tau)
        let t_tau = Self::compute_target_polynomial_at_tau(m, &tau)?;
        if t_tau.is_zero() {
            return Err(ZKError::InvalidCircuit);
        }

        // Build proving key
        let proving_key = Self::build_proving_key(
            &powers, &a_tau, &b_tau, &c_tau,
            &alpha, &beta, &gamma, &delta,
            circuit.num_variables, circuit.num_inputs
        )?;

        // Build verifying key
        let verifying_key = Self::build_verifying_key(
            &a_tau, &alpha, &beta, &gamma, &delta,
            circuit.num_inputs
        )?;

        let toxic_waste = ToxicWaste {
            tau, alpha, beta, gamma, delta
        };

        let setup_params = SetupParameters {
            proving_key,
            verifying_key,
            toxic_waste: Some(toxic_waste),
        };

        Ok(setup_params)
    }

    fn compute_qap_polynomials(
        a_matrix: &[Vec<FieldElement>],
        b_matrix: &[Vec<FieldElement>],
        c_matrix: &[Vec<FieldElement>],
    ) -> Result<(Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>), ZKError> {
        let m = a_matrix.len();
        let n = a_matrix[0].len();

        // For simplicity, we'll use the matrices directly as polynomials
        // Real QAP would involve polynomial interpolation
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

    fn evaluate_polynomials_at_tau(
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

    fn compute_target_polynomial_at_tau(
        num_constraints: usize,
        tau: &FieldElement,
    ) -> Result<FieldElement, ZKError> {
        // Target polynomial t(x) = (x - omega^0)(x - omega^1)...(x - omega^(m-1))
        // For simplicity, we'll use t(x) = x^m - 1
        let mut result = FieldElement::one();
        for _ in 0..num_constraints {
            result = result.mul(tau);
        }
        result = result.sub(&FieldElement::one());

        Ok(result)
    }

    fn build_proving_key(
        powers: &Powers,
        a_tau: &[FieldElement],
        b_tau: &[FieldElement],
        c_tau: &[FieldElement],
        alpha: &FieldElement,
        beta: &FieldElement,
        _gamma: &FieldElement,
        delta: &FieldElement,
        num_variables: usize,
        num_inputs: usize,
    ) -> Result<ProvingKey, ZKError> {
        let g1_gen = G1Point::generator();
        let g2_gen = G2Point::generator();

        // Generate key elements
        let alpha_g1 = g1_gen.scalar_mul(&alpha.limbs);
        let beta_g1 = g1_gen.scalar_mul(&beta.limbs);
        let beta_g2 = g2_gen.scalar_mul(&beta.limbs);
        let delta_g1 = g1_gen.scalar_mul(&delta.limbs);
        let delta_g2 = g2_gen.scalar_mul(&delta.limbs);

        // A query: [A_i(tau)]_1
        let mut a_query = Vec::with_capacity(num_variables + 1);
        for i in 0..=num_variables {
            if i < a_tau.len() {
                a_query.push(g1_gen.scalar_mul(&a_tau[i].limbs));
            } else {
                a_query.push(G1Point::identity());
            }
        }

        // B query in G1: [B_i(tau)]_1
        let mut b_g1_query = Vec::with_capacity(num_variables + 1);
        for i in 0..=num_variables {
            if i < b_tau.len() {
                b_g1_query.push(g1_gen.scalar_mul(&b_tau[i].limbs));
            } else {
                b_g1_query.push(G1Point::identity());
            }
        }

        // B query in G2: [B_i(tau)]_2
        let mut b_g2_query = Vec::with_capacity(num_variables + 1);
        for i in 0..=num_variables {
            if i < b_tau.len() {
                b_g2_query.push(g2_gen.scalar_mul(&b_tau[i].limbs));
            } else {
                b_g2_query.push(G2Point::identity());
            }
        }

        // H query: powers of tau for polynomial division
        let h_query = powers.tau_g1[..powers.tau_g1.len().saturating_sub(1)].to_vec();

        // L query: [(beta*A_i(tau) + alpha*B_i(tau) + C_i(tau))/delta]_1 for auxiliary inputs
        let mut l_query = Vec::new();
        let delta_inv = delta.invert().ok_or(ZKError::InvalidProof)?;

        for i in num_inputs + 1..=num_variables {
            if i < a_tau.len() && i < b_tau.len() && i < c_tau.len() {
                let beta_a = beta.mul(&a_tau[i]);
                let alpha_b = alpha.mul(&b_tau[i]);
                let numerator = beta_a.add(&alpha_b).add(&c_tau[i]);
                let l_i = numerator.mul(&delta_inv);
                l_query.push(g1_gen.scalar_mul(&l_i.limbs));
            }
        }

        Ok(ProvingKey {
            alpha_g1,
            beta_g1,
            beta_g2,
            delta_g1,
            delta_g2,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
            num_variables,
            num_inputs,
        })
    }

    fn build_verifying_key(
        a_tau: &[FieldElement],
        alpha: &FieldElement,
        beta: &FieldElement,
        gamma: &FieldElement,
        delta: &FieldElement,
        num_inputs: usize,
    ) -> Result<VerifyingKey, ZKError> {
        let g1_gen = G1Point::generator();
        let g2_gen = G2Point::generator();

        let alpha_g1 = g1_gen.scalar_mul(&alpha.limbs);
        let beta_g2 = g2_gen.scalar_mul(&beta.limbs);
        let gamma_g2 = g2_gen.scalar_mul(&gamma.limbs);
        let delta_g2 = g2_gen.scalar_mul(&delta.limbs);

        // IC query for public inputs
        let mut ic = Vec::with_capacity(num_inputs + 1);
        let gamma_inv = gamma.invert().ok_or(ZKError::InvalidProof)?;

        for i in 0..=num_inputs {
            if i < a_tau.len() {
                let ic_i = a_tau[i].mul(&gamma_inv);
                ic.push(g1_gen.scalar_mul(&ic_i.limbs));
            } else {
                ic.push(G1Point::identity());
            }
        }

        Ok(VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }

    /// Load existing trusted setup from persistent storage or generate new one
    pub fn load_or_generate(config: &crate::zk_engine::ZKConfig) -> Result<SetupParameters, ZKError> {
        // Try to load from configured path first
        if let Some(ref path) = config.trusted_setup_path {
            if let Ok(params) = Self::load_from_storage(path) {
                crate::log::info!("Loaded trusted setup from {}", path);
                return Ok(params);
            }
        }

        // Try default system paths
        let default_paths = [
            "/nonos/zk/trusted_setup.bin",
            "/etc/nonos/zk_setup.bin",
            "/boot/zk_params.bin",
        ];

        for path in &default_paths {
            if let Ok(params) = Self::load_from_storage(path) {
                crate::log::info!("Loaded trusted setup from {}", path);
                return Ok(params);
            }
        }

        // Fallback: generate new setup with default circuit
        crate::log::warn!("No stored trusted setup found, generating new (this may take time)");
        let dummy_circuit = crate::zk_engine::circuit::Circuit::new();
        let params = TrustedSetup::setup(&dummy_circuit)?;

        // Try to persist the generated setup
        if let Some(ref path) = config.trusted_setup_path {
            if Self::save_to_storage(path, &params).is_ok() {
                crate::log::info!("Saved trusted setup to {}", path);
            }
        }

        Ok(params)
    }

    /// Load setup parameters from storage
    fn load_from_storage(path: &str) -> Result<SetupParameters, ZKError> {
        use crate::fs::nonos_filesystem::NonosFilesystem;

        let fs = NonosFilesystem::new();
        let data = fs.read_file(path).map_err(|_| ZKError::TrustedSetupNotFound)?;

        // Validate minimum size (magic + version + key sizes)
        if data.len() < 16 {
            return Err(ZKError::InvalidFormat);
        }

        // Check magic number "NZKS" (NONOS ZK Setup)
        if &data[0..4] != b"NZKS" {
            return Err(ZKError::InvalidFormat);
        }

        // Check version
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != 1 {
            return Err(ZKError::InvalidFormat);
        }

        // Deserialize the keys
        Self::deserialize_params(&data[8..])
    }

    /// Save setup parameters to storage
    fn save_to_storage(path: &str, params: &SetupParameters) -> Result<(), ZKError> {
        use crate::fs::nonos_filesystem::NonosFilesystem;

        let mut data = Vec::new();

        // Magic number
        data.extend_from_slice(b"NZKS");

        // Version
        data.extend_from_slice(&1u32.to_le_bytes());

        // Serialize the keys
        Self::serialize_params(params, &mut data);

        let fs = NonosFilesystem::new();
        fs.create_file(path, &data).map_err(|_| ZKError::SetupError)?;

        Ok(())
    }

    /// Serialize setup parameters to bytes
    fn serialize_params(params: &SetupParameters, out: &mut Vec<u8>) {
        // Serialize proving key
        let pk = &params.proving_key;
        out.extend_from_slice(&(pk.num_variables as u32).to_le_bytes());
        out.extend_from_slice(&(pk.num_inputs as u32).to_le_bytes());

        // Serialize G1 points
        Self::serialize_g1(&pk.alpha_g1, out);
        Self::serialize_g1(&pk.beta_g1, out);
        Self::serialize_g1(&pk.delta_g1, out);

        // Serialize G2 points
        Self::serialize_g2(&pk.beta_g2, out);
        Self::serialize_g2(&pk.delta_g2, out);

        // Serialize queries
        out.extend_from_slice(&(pk.a_query.len() as u32).to_le_bytes());
        for pt in &pk.a_query {
            Self::serialize_g1(pt, out);
        }

        out.extend_from_slice(&(pk.b_g1_query.len() as u32).to_le_bytes());
        for pt in &pk.b_g1_query {
            Self::serialize_g1(pt, out);
        }

        out.extend_from_slice(&(pk.b_g2_query.len() as u32).to_le_bytes());
        for pt in &pk.b_g2_query {
            Self::serialize_g2(pt, out);
        }

        out.extend_from_slice(&(pk.h_query.len() as u32).to_le_bytes());
        for pt in &pk.h_query {
            Self::serialize_g1(pt, out);
        }

        out.extend_from_slice(&(pk.l_query.len() as u32).to_le_bytes());
        for pt in &pk.l_query {
            Self::serialize_g1(pt, out);
        }

        // Serialize verifying key
        let vk = &params.verifying_key;
        Self::serialize_g1(&vk.alpha_g1, out);
        Self::serialize_g2(&vk.beta_g2, out);
        Self::serialize_g2(&vk.gamma_g2, out);
        Self::serialize_g2(&vk.delta_g2, out);

        out.extend_from_slice(&(vk.ic.len() as u32).to_le_bytes());
        for pt in &vk.ic {
            Self::serialize_g1(pt, out);
        }
    }

    fn u64_limbs_to_bytes(limbs: &[u64; 4]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, &limb) in limbs.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    fn serialize_g1(pt: &G1Point, out: &mut Vec<u8>) {
        out.extend_from_slice(&Self::u64_limbs_to_bytes(&pt.x.limbs));
        out.extend_from_slice(&Self::u64_limbs_to_bytes(&pt.y.limbs));
    }

    fn serialize_g2(pt: &G2Point, out: &mut Vec<u8>) {
        out.extend_from_slice(&Self::u64_limbs_to_bytes(&pt.x.c0.limbs));
        out.extend_from_slice(&Self::u64_limbs_to_bytes(&pt.x.c1.limbs));
        out.extend_from_slice(&Self::u64_limbs_to_bytes(&pt.y.c0.limbs));
        out.extend_from_slice(&Self::u64_limbs_to_bytes(&pt.y.c1.limbs));
    }

    fn deserialize_params(data: &[u8]) -> Result<SetupParameters, ZKError> {
        if data.len() < 8 {
            return Err(ZKError::InvalidFormat);
        }

        let mut offset = 0;

        let num_variables = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        let num_inputs = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        // Deserialize G1 points
        let (alpha_g1, new_offset) = Self::deserialize_g1(data, offset)?;
        offset = new_offset;
        let (beta_g1, new_offset) = Self::deserialize_g1(data, offset)?;
        offset = new_offset;
        let (delta_g1, new_offset) = Self::deserialize_g1(data, offset)?;
        offset = new_offset;

        // Deserialize G2 points
        let (beta_g2, new_offset) = Self::deserialize_g2(data, offset)?;
        offset = new_offset;
        let (delta_g2, new_offset) = Self::deserialize_g2(data, offset)?;
        offset = new_offset;

        // Deserialize queries
        let (a_query, new_offset) = Self::deserialize_g1_vec(data, offset)?;
        offset = new_offset;
        let (b_g1_query, new_offset) = Self::deserialize_g1_vec(data, offset)?;
        offset = new_offset;
        let (b_g2_query, new_offset) = Self::deserialize_g2_vec(data, offset)?;
        offset = new_offset;
        let (h_query, new_offset) = Self::deserialize_g1_vec(data, offset)?;
        offset = new_offset;
        let (l_query, new_offset) = Self::deserialize_g1_vec(data, offset)?;
        offset = new_offset;

        let proving_key = ProvingKey {
            alpha_g1,
            beta_g1,
            beta_g2,
            delta_g1,
            delta_g2,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
            num_variables,
            num_inputs,
        };

        // Deserialize verifying key
        let (vk_alpha_g1, new_offset) = Self::deserialize_g1(data, offset)?;
        offset = new_offset;
        let (vk_beta_g2, new_offset) = Self::deserialize_g2(data, offset)?;
        offset = new_offset;
        let (vk_gamma_g2, new_offset) = Self::deserialize_g2(data, offset)?;
        offset = new_offset;
        let (vk_delta_g2, new_offset) = Self::deserialize_g2(data, offset)?;
        offset = new_offset;
        let (ic, _) = Self::deserialize_g1_vec(data, offset)?;

        let verifying_key = VerifyingKey {
            alpha_g1: vk_alpha_g1,
            beta_g2: vk_beta_g2,
            gamma_g2: vk_gamma_g2,
            delta_g2: vk_delta_g2,
            ic,
        };

        Ok(SetupParameters {
            proving_key,
            verifying_key,
            toxic_waste: None, // Not persisted for security
        })
    }

    fn bytes_to_u64_limbs(bytes: &[u8; 32]) -> [u64; 4] {
        [
            u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]),
            u64::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]),
            u64::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]]),
            u64::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31]]),
        ]
    }

    fn deserialize_g1(data: &[u8], offset: usize) -> Result<(G1Point, usize), ZKError> {
        if offset + 64 > data.len() {
            return Err(ZKError::InvalidFormat);
        }

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&data[offset..offset + 32]);
        y_bytes.copy_from_slice(&data[offset + 32..offset + 64]);

        Ok((G1Point {
            x: FieldElement { limbs: Self::bytes_to_u64_limbs(&x_bytes) },
            y: FieldElement { limbs: Self::bytes_to_u64_limbs(&y_bytes) },
            z: FieldElement::one(),
        }, offset + 64))
    }

    fn deserialize_g2(data: &[u8], offset: usize) -> Result<(G2Point, usize), ZKError> {
        use crate::zk_engine::groth16::G2FieldElement;

        if offset + 128 > data.len() {
            return Err(ZKError::InvalidFormat);
        }

        let mut c0_x = [0u8; 32];
        let mut c1_x = [0u8; 32];
        let mut c0_y = [0u8; 32];
        let mut c1_y = [0u8; 32];

        c0_x.copy_from_slice(&data[offset..offset + 32]);
        c1_x.copy_from_slice(&data[offset + 32..offset + 64]);
        c0_y.copy_from_slice(&data[offset + 64..offset + 96]);
        c1_y.copy_from_slice(&data[offset + 96..offset + 128]);

        Ok((G2Point {
            x: G2FieldElement {
                c0: FieldElement { limbs: Self::bytes_to_u64_limbs(&c0_x) },
                c1: FieldElement { limbs: Self::bytes_to_u64_limbs(&c1_x) },
            },
            y: G2FieldElement {
                c0: FieldElement { limbs: Self::bytes_to_u64_limbs(&c0_y) },
                c1: FieldElement { limbs: Self::bytes_to_u64_limbs(&c1_y) },
            },
            z: G2FieldElement::one(),
        }, offset + 128))
    }

    fn deserialize_g1_vec(data: &[u8], offset: usize) -> Result<(Vec<G1Point>, usize), ZKError> {
        if offset + 4 > data.len() {
            return Err(ZKError::InvalidFormat);
        }

        let count = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        let mut current = offset + 4;

        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            let (pt, new_offset) = Self::deserialize_g1(data, current)?;
            points.push(pt);
            current = new_offset;
        }

        Ok((points, current))
    }

    fn deserialize_g2_vec(data: &[u8], offset: usize) -> Result<(Vec<G2Point>, usize), ZKError> {
        if offset + 4 > data.len() {
            return Err(ZKError::InvalidFormat);
        }

        let count = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        let mut current = offset + 4;

        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            let (pt, new_offset) = Self::deserialize_g2(data, current)?;
            points.push(pt);
            current = new_offset;
        }

        Ok((points, current))
    }
}

/// Universal setup for multiple circuits (Phase 1 of ceremony)
pub struct UniversalSetup;

impl UniversalSetup {
    pub fn phase1_setup(max_constraints: usize) -> Result<Powers, ZKError> {
        Powers::new(max_constraints)
    }

    pub fn phase2_setup(circuit: &Circuit, _powers: &Powers) -> Result<SetupParameters, ZKError> {
        // Use pre-computed powers for circuit-specific setup
        TrustedSetup::setup(circuit)
    }
}
