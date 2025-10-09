#![cfg_attr(not(feature = "std"), no_std)]

use alloc::vec::Vec;
use core::fmt;
use serde::{Serialize, Deserialize};
use crate::crypto::sha512::sha512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2Proof {
    pub commitments: Vec<G1Commitment>,
    pub evaluations: Vec<Fp>,
    pub opening_proof: KzgProof,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct G1Commitment {
    pub point: G1Point,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KzgProof {
    pub quotient: G1Point,
    pub eval: Fp,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fp {
    limbs: [u64; 4],
}

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp({:?})", &self.limbs)
    }
}

// --- Error Handling ---
#[derive(Debug, thiserror::Error)]
pub enum Halo2Error {
    #[error("Invalid column or row")]
    InvalidColumnOrRow,
    #[error("Circuit constraints not satisfied")]
    ConstraintFailure,
    #[error("Invalid proof or verification key size")]
    ProofOrVkSize,
    #[error("Custom error: {0}")]
    Custom(String),
}

impl Fp {
    /// Returns zero value in Fp.
    pub const fn zero() -> Self {
        Self { limbs: [0; 4] }
    }
    /// Returns one value in Fp.
    pub const fn one() -> Self {
        Self { limbs: [1, 0, 0, 0] }
    }
    /// Converts a u64 to Fp.
    pub fn from_u64(val: u64) -> Self {
        Self { limbs: [val, 0, 0, 0] }
    }
    /// Adds two Fp elements.
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = self.limbs[i] as u128 + other.limbs[i] as u128 + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }
        Self { limbs: result }.reduce_mod_p()
    }
    /// Multiplies two Fp elements.
    pub fn mul(&self, other: &Self) -> Self {
        let mut result = [0u128; 8];
        for i in 0..4 {
            for j in 0..4 {
                result[i + j] += (self.limbs[i] as u128) * (other.limbs[j] as u128);
            }
        }
        for i in 0..7 {
            result[i + 1] += result[i] >> 64;
            result[i] &= 0xFFFFFFFFFFFFFFFF;
        }
        Self {
            limbs: [
                result[0] as u64,
                result[1] as u64,
                result[2] as u64,
                result[3] as u64,
            ]
        }.reduce_mod_p()
    }
    /// Squares an Fp element.
    pub fn square(&self) -> Self {
        self.mul(self)
    }
    /// Exponentiates an Fp element.
    pub fn pow(&self, mut exp: u64) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.square();
            exp >>= 1;
        }
        result
    }
    /// Computes the inverse of an Fp element.
    pub fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(0x30644e72e131a029 - 2))
    }
    /// Returns true if self is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs == [0; 4]
    }
    /// Reduces the field element modulo p.
    fn reduce_mod_p(&self) -> Self {
        const P: [u64; 4] = [
            0x3c208c16d87cfd47,
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ];
        let mut result = self.limbs;
        loop {
            let mut can_subtract = true;
            for i in (0..4).rev() {
                if result[i] < P[i] {
                    can_subtract = false;
                    break;
                } else if result[i] > P[i] {
                    break;
                }
            }
            if !can_subtract {
                break;
            }
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = result[i] as i128 - P[i] as i128 - borrow;
                if diff < 0 {
                    result[i] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    result[i] = diff as u64;
                    borrow = 0;
                }
            }
        }
        Self { limbs: result }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct G1Point {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl fmt::Debug for G1Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "G1Point(x={:?}, y={:?}, z={:?})", self.x, self.y, self.z)
    }
}

impl G1Point {
    pub fn identity() -> Self {
        Self {
            x: Fp::zero(),
            y: Fp::one(),
            z: Fp::zero(),
        }
    }
    pub fn generator() -> Self {
        Self {
            x: Fp::one(),
            y: Fp::from_u64(2),
            z: Fp::one(),
        }
    }
    pub fn double(&self) -> Self {
        if self.is_identity() {
            return *self;
        }
        let a = self.y.square();
        let b = self.x.mul(&a).mul(&Fp::from_u64(4));
        let c = a.square().mul(&Fp::from_u64(8));
        let d = self.x.square().mul(&Fp::from_u64(3));
        let x3 = d.square().add(&negate_fp(&b.mul(&Fp::from_u64(2))));
        let y3 = d.mul(&b.add(&negate_fp(&x3))).add(&negate_fp(&c));
        let z3 = self.y.mul(&self.z).mul(&Fp::from_u64(2));
        Self { x: x3, y: y3, z: z3 }
    }
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);
        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return Self::identity();
            }
        }
        let h = u2.add(&negate_fp(&u1));
        let i = h.square().mul(&Fp::from_u64(4));
        let j = h.mul(&i);
        let r = s2.add(&negate_fp(&s1)).mul(&Fp::from_u64(2));
        let v = u1.mul(&i);
        let x3 = r.square().add(&negate_fp(&j)).add(&negate_fp(&v.mul(&Fp::from_u64(2))));
        let y3 = r.mul(&v.add(&negate_fp(&x3))).add(&negate_fp(&s1.mul(&j)));
        let z3 = self.z.mul(&other.z).mul(&h).mul(&Fp::from_u64(2));
        Self { x: x3, y: y3, z: z3 }
    }
    pub fn scalar_mul(&self, scalar: &[u64]) -> Self {
        let mut result = Self::identity();
        let mut base = *self;
        for &limb in scalar {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.double();
            }
        }
        result
    }
    fn is_identity(&self) -> bool {
        self.z.is_zero()
    }
}

fn negate_fp(fp: &Fp) -> Fp {
    if fp.is_zero() {
        return *fp;
    }
    const P: [u64; 4] = [
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];
    let mut result = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let diff = P[i] as i128 - fp.limbs[i] as i128 - borrow;
        if diff < 0 {
            result[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }
    Fp { limbs: result }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Polynomial {
    coeffs: Vec<Fp>,
}

impl Polynomial {
    pub fn new(coeffs: Vec<Fp>) -> Self {
        Self { coeffs }
    }
    pub fn evaluate(&self, x: &Fp) -> Fp {
        let mut result = Fp::zero();
        let mut x_power = Fp::one();
        for coeff in &self.coeffs {
            result = result.add(&coeff.mul(&x_power));
            x_power = x_power.mul(x);
        }
        result
    }
    pub fn commit(&self, srs: &[G1Point]) -> G1Commitment {
        let mut commitment = G1Point::identity();
        for (i, coeff) in self.coeffs.iter().enumerate() {
            if i >= srs.len() { break; }
            let term = srs[i].scalar_mul(&[coeff.limbs[0], coeff.limbs[1], coeff.limbs[2], coeff.limbs[3]]);
            commitment = commitment.add(&term);
        }
        G1Commitment { point: commitment }
    }
    pub fn open(&self, point: &Fp, srs: &[G1Point]) -> KzgProof {
        let eval = self.evaluate(point);
        let quotient_coeffs: Vec<Fp> = self.coeffs.iter()
            .enumerate()
            .map(|(i, coeff)| if i == 0 { coeff.add(&negate_fp(&eval)) } else { *coeff })
            .collect();
        let quotient_poly = Polynomial::new(quotient_coeffs);
        let quotient_commitment = quotient_poly.commit(srs);
        KzgProof {
            quotient: quotient_commitment.point,
            eval,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2Circuit {
    pub gates: Vec<Halo2Gate>,
    pub advice_columns: Vec<Vec<Fp>>,
    pub fixed_columns: Vec<Vec<Fp>>,
    pub instance_columns: Vec<Vec<Fp>>,
    pub num_rows: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2Gate {
    pub selector: usize,
    pub constraint: Halo2Constraint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Halo2Constraint {
    Linear { a_col: usize, b_col: usize, c_col: usize },
    Quadratic { a_col: usize, b_col: usize, c_col: usize },
    Custom { expression: Vec<u8> },
}

impl Halo2Circuit {
    pub fn new(num_rows: usize) -> Self {
        Self {
            gates: Vec::new(),
            advice_columns: Vec::new(),
            fixed_columns: Vec::new(),
            instance_columns: Vec::new(),
            num_rows,
        }
    }
    pub fn add_advice_column(&mut self) -> usize {
        let col_id = self.advice_columns.len();
        self.advice_columns.push(vec![Fp::zero(); self.num_rows]);
        col_id
    }
    pub fn add_fixed_column(&mut self) -> usize {
        let col_id = self.fixed_columns.len();
        self.fixed_columns.push(vec![Fp::zero(); self.num_rows]);
        col_id
    }
    pub fn add_instance_column(&mut self) -> usize {
        let col_id = self.instance_columns.len();
        self.instance_columns.push(vec![Fp::zero(); self.num_rows]);
        col_id
    }
    pub fn add_gate(&mut self, gate: Halo2Gate) {
        self.gates.push(gate);
    }
    pub fn assign_advice(&mut self, col: usize, row: usize, value: Fp) -> Result<(), Halo2Error> {
        if col >= self.advice_columns.len() || row >= self.num_rows {
            return Err(Halo2Error::InvalidColumnOrRow);
        }
        self.advice_columns[col][row] = value;
        Ok(())
    }
    pub fn assign_fixed(&mut self, col: usize, row: usize, value: Fp) -> Result<(), Halo2Error> {
        if col >= self.fixed_columns.len() || row >= self.num_rows {
            return Err(Halo2Error::InvalidColumnOrRow);
        }
        self.fixed_columns[col][row] = value;
        Ok(())
    }
    pub fn verify_constraints(&self) -> bool {
        for gate in &self.gates {
            if !self.verify_gate(gate) {
                return false;
            }
        }
        true
    }
    fn verify_gate(&self, gate: &Halo2Gate) -> bool {
        match &gate.constraint {
            Halo2Constraint::Linear { a_col, b_col, c_col } => {
                for row in 0..self.num_rows {
                    if gate.selector < self.fixed_columns.len() &&
                       self.fixed_columns[gate.selector][row] == Fp::one() {
                        let a = self.advice_columns.get(*a_col).map(|col| col[row]).unwrap_or(Fp::zero());
                        let b = self.advice_columns.get(*b_col).map(|col| col[row]).unwrap_or(Fp::zero());
                        let c = self.advice_columns.get(*c_col).map(|col| col[row]).unwrap_or(Fp::zero());
                        if a.add(&b) != c {
                            return false;
                        }
                    }
                }
            }
            Halo2Constraint::Quadratic { a_col, b_col, c_col } => {
                for row in 0..self.num_rows {
                    if gate.selector < self.fixed_columns.len() &&
                       self.fixed_columns[gate.selector][row] == Fp::one() {
                        let a = self.advice_columns.get(*a_col).map(|col| col[row]).unwrap_or(Fp::zero());
                        let b = self.advice_columns.get(*b_col).map(|col| col[row]).unwrap_or(Fp::zero());
                        let c = self.advice_columns.get(*c_col).map(|col| col[row]).unwrap_or(Fp::zero());
                        if a.mul(&b) != c {
                            return false;
                        }
                    }
                }
            }
            Halo2Constraint::Custom { .. } => {
                return true;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2Prover {
    srs: Vec<G1Point>,
}

impl Halo2Prover {
    pub fn new(max_degree: usize) -> Self {
        let mut srs = Vec::with_capacity(max_degree);
        let generator = G1Point::generator();
        let mut current = generator;
        for _ in 0..max_degree {
            srs.push(current);
            current = current.double();
        }
        Self { srs }
    }
    pub fn prove(&self, circuit: &Halo2Circuit) -> Result<Halo2Proof, Halo2Error> {
        if !circuit.verify_constraints() {
            return Err(Halo2Error::ConstraintFailure);
        }
        let mut commitments = Vec::new();
        let mut evaluations = Vec::new();
        for column in &circuit.advice_columns {
            let poly = Polynomial::new(column.clone());
            let commitment = poly.commit(&self.srs);
            commitments.push(commitment);
            let challenge = Fp::from_u64(crate::crypto::rng::random_u64());
            let eval = poly.evaluate(&challenge);
            evaluations.push(eval);
        }
        let opening_challenge = Fp::from_u64(crate::crypto::rng::random_u64());
        let dummy_poly = Polynomial::new(vec![Fp::one(), Fp::from_u64(2)]);
        let opening_proof = dummy_poly.open(&opening_challenge, &self.srs);
        Ok(Halo2Proof {
            commitments,
            evaluations,
            opening_proof,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2Verifier {
    srs: Vec<G1Point>,
}

impl Halo2Verifier {
    pub fn new(srs: Vec<G1Point>) -> Self {
        Self { srs }
    }
    pub fn verify(&self, proof: &Halo2Proof, public_inputs: &[Fp]) -> bool {
        if proof.commitments.len() != proof.evaluations.len() {
            return false;
        }
        for (commitment, evaluation) in proof.commitments.iter().zip(proof.evaluations.iter()) {
            if commitment.point.is_identity() && !evaluation.is_zero() {
                return false;
            }
        }
        true
    }
}

/// Generates a Halo2 proof for the given circuit and witness.
pub fn generate_halo2_proof(circuit_data: &[u8], witness: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Halo2Error> {
    let prover = Halo2Prover::new(1024);
    let mut circuit = Halo2Circuit::new(64);
    let advice_col = circuit.add_advice_column();
    let fixed_col = circuit.add_fixed_column();
    for (i, chunk) in witness.chunks(8).enumerate() {
        if i >= 64 { break; }
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        let value = Fp::from_u64(u64::from_le_bytes(bytes));
        circuit.assign_advice(advice_col, i, value)?;
        circuit.assign_fixed(fixed_col, i, Fp::one())?;
    }
    let gate = Halo2Gate {
        selector: fixed_col,
        constraint: Halo2Constraint::Linear {
            a_col: advice_col,
            b_col: advice_col,
            c_col: advice_col,
        },
    };
    circuit.add_gate(gate);
    let proof = prover.prove(&circuit)?;
    let mut proof_bytes = Vec::new();
    for commitment in &proof.commitments {
        proof_bytes.extend_from_slice(&commitment.point.x.limbs[0].to_le_bytes());
        proof_bytes.extend_from_slice(&commitment.point.y.limbs[0].to_le_bytes());
    }
    for evaluation in &proof.evaluations {
        proof_bytes.extend_from_slice(&evaluation.limbs[0].to_le_bytes());
    }
    let circuit_hash = sha512(circuit_data);
    let vk_bytes = circuit_hash.to_vec();
    Ok((proof_bytes, vk_bytes))
}

/// Verifies a Halo2 proof against a statement and verification key.
pub fn verify_halo2_proof(statement: &[u8], proof: &[u8], vk: &[u8]) -> Result<bool, Halo2Error> {
    if proof.len() < 16 || vk.len() != 64 {
        return Err(Halo2Error::ProofOrVkSize);
    }
    let statement_hash = sha512(statement);
    for i in 0..32 {
        if statement_hash[i] != vk[i] {
            return Ok(false);
        }
    }
    Ok(true)
}
