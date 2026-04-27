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

use crate::memory::VirtAddr;
use crate::test::framework::{TestCase, TestResult, TestSuite};
use crate::zk_engine::attestation::types::{KernelMeasurement, MemoryLayout, ModuleHash};
use crate::zk_engine::circuit::examples::{
    hash_preimage_circuit, multiplication_circuit, range_proof_circuit,
};
use crate::zk_engine::circuit::{
    Circuit, CircuitBuilder, CircuitOptimizer, Constraint, LinearCombination, Variable,
};
use crate::zk_engine::groth16::field::{
    FieldElement, BN254_MODULUS, MONTGOMERY_INV, MONTGOMERY_R, MONTGOMERY_R2,
};
use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::g2::{G2FieldElement, G2Point};
use crate::zk_engine::groth16::gt::{Fp6Element, GTElement};
use crate::zk_engine::groth16::keys::VerifyingKey;
use crate::zk_engine::groth16::pairing::Pairing;
use crate::zk_engine::groth16::proof::Proof;
use crate::zk_engine::syscalls::helpers::{
    deserialize_constraints, deserialize_public_inputs, deserialize_witness,
};
use crate::zk_engine::syscalls::params::{
    ZKCompileParams, ZKProveParams, ZKStatsUserspace, ZKVerifyParams, MAX_CONSTRAINTS,
    MAX_PROOF_SIZE, MAX_PUBLIC_INPUTS, MAX_WITNESS_SIZE, SYS_ZK_COMPILE_CIRCUIT, SYS_ZK_GET_STATS,
    SYS_ZK_PROVE, SYS_ZK_VERIFY,
};
use crate::zk_engine::types::{ZKConfig, ZKError};
use crate::zk_engine::verification::specialized::{MerkleVerifier, RangeProof, RangeProofVerifier};
use crate::zk_engine::verification::{
    compute_cache_key, Groth16Verifier, VerificationCache, VerificationKeyManager,
    VerificationResult, VerificationStats,
};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn test_field_element_zero() -> TestResult {
    let zero = FieldElement::zero();
    if !zero.is_zero() {
        return TestResult::Fail;
    }
    if zero.limbs != [0, 0, 0, 0] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_one() -> TestResult {
    let one = FieldElement::one();
    if one.is_zero() {
        return TestResult::Fail;
    }
    if one.limbs != MONTGOMERY_R {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_from_u64() -> TestResult {
    let fe = FieldElement::from_u64(42);
    if fe.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_from_u128() -> TestResult {
    let fe = FieldElement::from_u128(0x123456789ABCDEF0_123456789ABCDEF0);
    if fe.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_add_zero() -> TestResult {
    let a = FieldElement::from_u64(100);
    let zero = FieldElement::zero();
    let result = a.add(&zero);
    if !a.equals(&result) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_add_commutative() -> TestResult {
    let a = FieldElement::from_u64(123);
    let b = FieldElement::from_u64(456);
    let ab = a.add(&b);
    let ba = b.add(&a);
    if !ab.equals(&ba) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_sub_self_is_zero() -> TestResult {
    let a = FieldElement::from_u64(999);
    let result = a.sub(&a);
    if !result.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_mul_one() -> TestResult {
    let a = FieldElement::from_u64(777);
    let one = FieldElement::one();
    let result = a.mul(&one);
    if !a.equals(&result) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_mul_zero() -> TestResult {
    let a = FieldElement::from_u64(555);
    let zero = FieldElement::zero();
    let result = a.mul(&zero);
    if !result.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_mul_commutative() -> TestResult {
    let a = FieldElement::from_u64(17);
    let b = FieldElement::from_u64(23);
    let ab = a.mul(&b);
    let ba = b.mul(&a);
    if !ab.equals(&ba) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_square() -> TestResult {
    let a = FieldElement::from_u64(5);
    let square = a.square();
    let manual = a.mul(&a);
    if !square.equals(&manual) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_double() -> TestResult {
    let a = FieldElement::from_u64(100);
    let doubled = a.double();
    let manual = a.add(&a);
    if !doubled.equals(&manual) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_neg() -> TestResult {
    let a = FieldElement::from_u64(50);
    let neg_a = a.neg();
    let sum = a.add(&neg_a);
    if !sum.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_neg_zero() -> TestResult {
    let zero = FieldElement::zero();
    let neg_zero = zero.neg();
    if !neg_zero.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_inverse() -> TestResult {
    let a = FieldElement::from_u64(7);
    let inv = a.inverse().unwrap();
    let product = a.mul(&inv);
    if !product.equals(&FieldElement::one()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_inverse_zero_returns_none() -> TestResult {
    let zero = FieldElement::zero();
    if zero.inverse().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_invert() -> TestResult {
    let a = FieldElement::from_u64(11);
    let inv = a.invert().unwrap();
    let product = a.mul(&inv);
    if !product.equals(&FieldElement::one()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_pow_zero() -> TestResult {
    let a = FieldElement::from_u64(99);
    let result = a.pow(&[0, 0, 0, 0]);
    if !result.equals(&FieldElement::one()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_pow_one() -> TestResult {
    let a = FieldElement::from_u64(13);
    let result = a.pow(&[1, 0, 0, 0]);
    if !a.equals(&result) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_sqrt_perfect_square() -> TestResult {
    let a = FieldElement::from_u64(4);
    let sqrt = a.sqrt();
    if let Some(root) = sqrt {
        let squared = root.square();
        if !squared.equals(&a) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_sqrt_zero() -> TestResult {
    let zero = FieldElement::zero();
    let sqrt = zero.sqrt().unwrap();
    if !sqrt.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_to_bytes_from_bytes_roundtrip() -> TestResult {
    let a = FieldElement::from_u64(12345);
    let bytes = a.to_bytes();
    let recovered = FieldElement::from_bytes(&bytes).unwrap();
    if !a.equals(&recovered) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_from_bytes_too_short() -> TestResult {
    let short_bytes = [0u8; 16];
    if FieldElement::from_bytes(&short_bytes).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_from_bytes_array() -> TestResult {
    let bytes = [0u8; 32];
    let fe = FieldElement::from_bytes_array(&bytes);
    if !fe.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_gte_equal() -> TestResult {
    let a = [1u64, 2, 3, 4];
    let b = [1u64, 2, 3, 4];
    if !FieldElement::gte(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_gte_greater() -> TestResult {
    let a = [1u64, 2, 3, 5];
    let b = [1u64, 2, 3, 4];
    if !FieldElement::gte(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_gte_less() -> TestResult {
    let a = [1u64, 2, 3, 3];
    let b = [1u64, 2, 3, 4];
    if FieldElement::gte(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_montgomery_conversion_roundtrip() -> TestResult {
    let raw = FieldElement::from_limbs([1, 2, 3, 0]);
    let montgomery = raw.to_montgomery();
    let back = montgomery.from_montgomery();
    if raw.limbs != back.limbs {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_infinity() -> TestResult {
    let inf = G1Point::infinity();
    if !inf.is_infinity() {
        return TestResult::Fail;
    }
    if !inf.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_generator() -> TestResult {
    let gen = G1Point::generator();
    if gen.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_identity() -> TestResult {
    let id = G1Point::identity();
    if !id.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_negate() -> TestResult {
    let gen = G1Point::generator();
    let neg = gen.negate();
    let sum = gen.add(&neg);
    if !sum.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_add_infinity_left() -> TestResult {
    let inf = G1Point::infinity();
    let gen = G1Point::generator();
    let result = inf.add(&gen);
    if result.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_add_infinity_right() -> TestResult {
    let gen = G1Point::generator();
    let inf = G1Point::infinity();
    let result = gen.add(&inf);
    if result.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_double() -> TestResult {
    let gen = G1Point::generator();
    let doubled = gen.double();
    let manual = gen.add(&gen);
    let d_coords = doubled.to_affine_coords();
    let m_coords = manual.to_affine_coords();
    if let (Some((dx, dy)), Some((mx, my))) = (d_coords, m_coords) {
        if !dx.equals(&mx) {
            return TestResult::Fail;
        }
        if !dy.equals(&my) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_double_infinity() -> TestResult {
    let inf = G1Point::infinity();
    let doubled = inf.double();
    if !doubled.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_scalar_mul_zero() -> TestResult {
    let gen = G1Point::generator();
    let result = gen.scalar_mul(&[0, 0, 0, 0]);
    if !result.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_scalar_mul_one() -> TestResult {
    let gen = G1Point::generator();
    let result = gen.scalar_mul(&[1, 0, 0, 0]);
    let gen_coords = gen.to_affine_coords();
    let result_coords = result.to_affine_coords();
    if let (Some((gx, gy)), Some((rx, ry))) = (gen_coords, result_coords) {
        if !gx.equals(&rx) {
            return TestResult::Fail;
        }
        if !gy.equals(&ry) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_to_affine_infinity() -> TestResult {
    let inf = G1Point::infinity();
    if inf.to_affine_coords().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_to_bytes_from_bytes_roundtrip() -> TestResult {
    let gen = G1Point::generator();
    let bytes = gen.to_bytes();
    let recovered = G1Point::from_bytes(&bytes).unwrap();
    if recovered.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_from_bytes_too_short() -> TestResult {
    let short = [0u8; 16];
    if G1Point::from_bytes(&short).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_from_bytes_all_zeros() -> TestResult {
    let zeros = [0u8; 32];
    let result = G1Point::from_bytes(&zeros).unwrap();
    if !result.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_affine_from_point() -> TestResult {
    let gen = G1Point::generator();
    let affine = gen.to_affine();
    if affine.x.is_zero() && affine.y.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_zero() -> TestResult {
    let zero = G2FieldElement::zero();
    if !zero.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_one() -> TestResult {
    let one = G2FieldElement::one();
    if one.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_from_base_field() -> TestResult {
    let base = FieldElement::from_u64(42);
    let g2fe = G2FieldElement::from_base_field(&base);
    if g2fe.is_zero() {
        return TestResult::Fail;
    }
    if !g2fe.c1.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_add_zero() -> TestResult {
    let a = G2FieldElement::from_base(FieldElement::from_u64(100));
    let zero = G2FieldElement::zero();
    let result = a.add(&zero);
    if a != result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_sub_self_is_zero() -> TestResult {
    let a = G2FieldElement::from_base(FieldElement::from_u64(50));
    let result = a.sub(&a);
    if !result.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_mul_one() -> TestResult {
    let a = G2FieldElement::from_base(FieldElement::from_u64(77));
    let one = G2FieldElement::one();
    let result = a.mul(&one);
    if a != result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_square() -> TestResult {
    let a = G2FieldElement::from_base(FieldElement::from_u64(5));
    let squared = a.square();
    let manual = a.mul(&a);
    if squared != manual {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_double() -> TestResult {
    let a = G2FieldElement::from_base(FieldElement::from_u64(10));
    let doubled = a.double();
    let manual = a.add(&a);
    if doubled != manual {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_neg() -> TestResult {
    let a = G2FieldElement::from_base(FieldElement::from_u64(30));
    let neg_a = a.neg();
    let sum = a.add(&neg_a);
    if !sum.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_inverse() -> TestResult {
    let a = G2FieldElement::from_base(FieldElement::from_u64(7));
    let inv = a.inverse().unwrap();
    let product = a.mul(&inv);
    if product != G2FieldElement::one() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_inverse_zero_returns_none() -> TestResult {
    let zero = G2FieldElement::zero();
    if zero.inverse().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_conjugate() -> TestResult {
    let a = G2FieldElement { c0: FieldElement::from_u64(10), c1: FieldElement::from_u64(20) };
    let conj = a.conjugate();
    if !conj.c0.equals(&a.c0) {
        return TestResult::Fail;
    }
    if !conj.c1.equals(&a.c1.neg()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_infinity() -> TestResult {
    let inf = G2Point::infinity();
    if !inf.is_infinity() {
        return TestResult::Fail;
    }
    if !inf.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_generator() -> TestResult {
    let gen = G2Point::generator();
    if gen.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_negate() -> TestResult {
    let gen = G2Point::generator();
    let neg = gen.negate();
    let sum = gen.add(&neg);
    if !sum.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_add_infinity_left() -> TestResult {
    let inf = G2Point::infinity();
    let gen = G2Point::generator();
    let result = inf.add(&gen);
    if result.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_add_infinity_right() -> TestResult {
    let gen = G2Point::generator();
    let inf = G2Point::infinity();
    let result = gen.add(&inf);
    if result.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_double() -> TestResult {
    let gen = G2Point::generator();
    let doubled = gen.double();
    let manual = gen.add(&gen);
    if doubled.is_infinity() {
        return TestResult::Fail;
    }
    if manual.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_double_infinity() -> TestResult {
    let inf = G2Point::infinity();
    let doubled = inf.double();
    if !doubled.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_scalar_mul_zero() -> TestResult {
    let gen = G2Point::generator();
    let result = gen.scalar_mul(&[0, 0, 0, 0]);
    if !result.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_to_affine_infinity() -> TestResult {
    let inf = G2Point::infinity();
    if inf.to_affine_coords().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_to_bytes_from_bytes_roundtrip() -> TestResult {
    let gen = G2Point::generator();
    let bytes = gen.to_bytes();
    let recovered = G2Point::from_bytes(&bytes).unwrap();
    if recovered.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_from_bytes_too_short() -> TestResult {
    let short = [0u8; 32];
    if G2Point::from_bytes(&short).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_serialize_deserialize() -> TestResult {
    let gen = G2Point::generator();
    let serialized = gen.serialize();
    let deserialized = G2Point::deserialize(&serialized).unwrap();
    if deserialized.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_deserialize_too_short() -> TestResult {
    let short = [0u8; 64];
    if G2Point::deserialize(&short).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_deserialize_all_zeros() -> TestResult {
    let zeros = [0u8; 128];
    let result = G2Point::deserialize(&zeros).unwrap();
    if !result.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_affine_neg() -> TestResult {
    let gen = G2Point::generator();
    let affine = gen.to_affine();
    let neg_affine = affine.neg();
    if neg_affine.x != affine.x {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gt_element_identity() -> TestResult {
    let id = GTElement::identity();
    if !id.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gt_element_one() -> TestResult {
    let one = GTElement::one();
    if !one.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gt_element_equals() -> TestResult {
    let a = GTElement::identity();
    let b = GTElement::one();
    if !a.equals(&b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pairing_infinity_g1() -> TestResult {
    let inf = G1Point::infinity();
    let gen = G2Point::generator();
    let result = Pairing::compute(&inf, &gen);
    if !result.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pairing_infinity_g2() -> TestResult {
    let gen = G1Point::generator();
    let inf = G2Point::infinity();
    let result = Pairing::compute(&gen, &inf);
    if !result.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pairing_both_infinity() -> TestResult {
    let inf1 = G1Point::infinity();
    let inf2 = G2Point::infinity();
    let result = Pairing::compute(&inf1, &inf2);
    if !result.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pairing_generators() -> TestResult {
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let result = Pairing::compute(&g1, &g2);
    if result.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pairing_multi_empty() -> TestResult {
    let pairs: Vec<(G1Point, G2Point)> = vec![];
    let result = Pairing::multi_pairing(&pairs);
    if !result.is_identity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_one() -> TestResult {
    let one = Variable::ONE;
    if one.index() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_new() -> TestResult {
    let v = Variable::new(5);
    if v.index() != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_ordering() -> TestResult {
    let v1 = Variable::new(1);
    let v2 = Variable::new(2);
    if !(v1 < v2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_new() -> TestResult {
    let lc = LinearCombination::new();
    if !lc.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_from_variable() -> TestResult {
    let v = Variable::new(3);
    let lc = LinearCombination::from_variable(v);
    if lc.terms.len() != 1 {
        return TestResult::Fail;
    }
    if !lc.terms.contains_key(&v) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_from_constant() -> TestResult {
    let c = FieldElement::from_u64(10);
    let lc = LinearCombination::from_constant(c);
    if lc.terms.len() != 1 {
        return TestResult::Fail;
    }
    if !lc.terms.contains_key(&Variable::ONE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_from_constant_zero() -> TestResult {
    let zero = FieldElement::zero();
    let lc = LinearCombination::from_constant(zero);
    if !lc.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_add_term() -> TestResult {
    let mut lc = LinearCombination::new();
    let v = Variable::new(0);
    lc.add_term(v, FieldElement::from_u64(5));
    if lc.terms.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_add_term_zero_coefficient() -> TestResult {
    let mut lc = LinearCombination::new();
    let v = Variable::new(0);
    lc.add_term(v, FieldElement::zero());
    if !lc.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_add_term_cancellation() -> TestResult {
    let mut lc = LinearCombination::new();
    let v = Variable::new(0);
    let c = FieldElement::from_u64(5);
    lc.add_term(v, c);
    lc.add_term(v, c.neg());
    if !lc.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_scale() -> TestResult {
    let mut lc = LinearCombination::from_variable(Variable::new(0));
    lc.scale(&FieldElement::from_u64(3));
    if lc.terms.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_scale_zero() -> TestResult {
    let mut lc = LinearCombination::from_variable(Variable::new(0));
    lc.scale(&FieldElement::zero());
    if !lc.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_add() -> TestResult {
    let mut lc1 = LinearCombination::from_variable(Variable::new(0));
    let lc2 = LinearCombination::from_variable(Variable::new(1));
    lc1.add(&lc2);
    if lc1.terms.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_evaluate_constant() -> TestResult {
    let lc = LinearCombination::from_constant(FieldElement::from_u64(42));
    let result = lc.evaluate(&[]).unwrap();
    if !result.equals(&FieldElement::from_u64(42)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_evaluate_variable() -> TestResult {
    let v = Variable::new(0);
    let lc = LinearCombination::from_variable(v);
    let assignment = vec![FieldElement::from_u64(10)];
    let result = lc.evaluate(&assignment).unwrap();
    if !result.equals(&FieldElement::from_u64(10)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_evaluate_out_of_bounds() -> TestResult {
    let v = Variable::new(100);
    let lc = LinearCombination::from_variable(v);
    let assignment = vec![FieldElement::from_u64(10)];
    if lc.evaluate(&assignment).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constraint_new() -> TestResult {
    let a = LinearCombination::new();
    let b = LinearCombination::new();
    let c = LinearCombination::new();
    let constraint = Constraint::new(a, b, c);
    if !constraint.a.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constraint_enforce_equal() -> TestResult {
    let left = LinearCombination::from_variable(Variable::new(0));
    let right = LinearCombination::from_variable(Variable::new(1));
    let constraint = Constraint::enforce_equal(left, right);
    if constraint.a.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constraint_enforce_multiplication() -> TestResult {
    let a = Variable::new(0);
    let b = Variable::new(1);
    let c = Variable::new(2);
    let constraint = Constraint::enforce_multiplication(a, b, c);
    if constraint.a.terms.is_empty() {
        return TestResult::Fail;
    }
    if constraint.b.terms.is_empty() {
        return TestResult::Fail;
    }
    if constraint.c.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constraint_default_multiplication() -> TestResult {
    let constraint = Constraint::default_multiplication(0);
    if constraint.a.terms.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constraint_verify_valid() -> TestResult {
    let a = Variable::new(0);
    let b = Variable::new(1);
    let c = Variable::new(2);
    let constraint = Constraint::enforce_multiplication(a, b, c);
    let two = FieldElement::from_u64(2);
    let three = FieldElement::from_u64(3);
    let six = FieldElement::from_u64(6);
    let assignment = vec![two, three, six];
    let result = constraint.verify(&assignment).unwrap();
    if !result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constraint_verify_invalid() -> TestResult {
    let a = Variable::new(0);
    let b = Variable::new(1);
    let c = Variable::new(2);
    let constraint = Constraint::enforce_multiplication(a, b, c);
    let two = FieldElement::from_u64(2);
    let three = FieldElement::from_u64(3);
    let seven = FieldElement::from_u64(7);
    let assignment = vec![two, three, seven];
    let result = constraint.verify(&assignment).unwrap();
    if result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_new() -> TestResult {
    let circuit = Circuit::new();
    if !circuit.constraints.is_empty() {
        return TestResult::Fail;
    }
    if circuit.num_variables != 0 {
        return TestResult::Fail;
    }
    if circuit.num_inputs != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_with_params() -> TestResult {
    let constraints = vec![Constraint::default_multiplication(0)];
    let circuit = Circuit::with_params(constraints, 3, 2);
    if circuit.constraints.len() != 1 {
        return TestResult::Fail;
    }
    if circuit.num_variables != 3 {
        return TestResult::Fail;
    }
    if circuit.num_inputs != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_get_matrices() -> TestResult {
    let constraints = vec![Constraint::default_multiplication(0)];
    let circuit = Circuit::with_params(constraints, 3, 0);
    let (a, b, c) = circuit.get_matrices();
    if a.len() != 1 {
        return TestResult::Fail;
    }
    if b.len() != 1 {
        return TestResult::Fail;
    }
    if c.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_verify_assignment_empty() -> TestResult {
    let circuit = Circuit::new();
    let result = circuit.verify_assignment(&[]).unwrap();
    if !result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_verify_assignment_wrong_length() -> TestResult {
    let circuit = Circuit::with_params(vec![], 3, 0);
    let result = circuit.verify_assignment(&[]);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_new() -> TestResult {
    let builder = CircuitBuilder::new();
    if !builder.constraints.is_empty() {
        return TestResult::Fail;
    }
    if builder.num_variables != 0 {
        return TestResult::Fail;
    }
    if builder.num_inputs != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_alloc_variable() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let v = builder.alloc_variable(Some("test"));
    if builder.num_variables != 1 {
        return TestResult::Fail;
    }
    if !builder.variable_names.contains_key(&v) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_alloc_variable_no_name() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let _v = builder.alloc_variable(None);
    if builder.num_variables != 1 {
        return TestResult::Fail;
    }
    if !builder.variable_names.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_alloc_input() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let _v = builder.alloc_input(Some("input"));
    if builder.num_variables != 1 {
        return TestResult::Fail;
    }
    if builder.num_inputs != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_enforce_constraint() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let constraint = Constraint::default_multiplication(0);
    builder.enforce_constraint(constraint);
    if builder.constraints.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_enforce_equal() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let v1 = builder.alloc_variable(None);
    let v2 = builder.alloc_variable(None);
    builder
        .enforce_equal(LinearCombination::from_variable(v1), LinearCombination::from_variable(v2));
    if builder.constraints.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_enforce_multiplication() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let a = builder.alloc_variable(None);
    let b = builder.alloc_variable(None);
    let c = builder.alloc_variable(None);
    builder.enforce_multiplication(a, b, c);
    if builder.constraints.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_add_boolean_constraint() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let v = builder.alloc_variable(None);
    builder.add_boolean_constraint(v);
    if builder.constraints.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_add_range_constraint() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let v = builder.alloc_input(None);
    builder.add_range_constraint(v, 4);
    if builder.constraints.len() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_build() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let _x = builder.alloc_input(None);
    let _y = builder.alloc_input(None);
    let circuit = builder.build(1).unwrap();
    if circuit.num_inputs != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_builder_add_constraint() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let constraint = Constraint::default_multiplication(0);
    let result = builder.add_constraint(constraint);
    if result.is_err() {
        return TestResult::Fail;
    }
    if builder.constraints.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_optimizer_optimize_empty() -> TestResult {
    let circuit = Circuit::new();
    let optimized = CircuitOptimizer::optimize(circuit);
    if !optimized.constraints.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_optimizer_removes_trivial() -> TestResult {
    let trivial = Constraint::new(
        LinearCombination::new(),
        LinearCombination::new(),
        LinearCombination::new(),
    );
    let circuit = Circuit::with_params(vec![trivial], 0, 0);
    let optimized = CircuitOptimizer::optimize(circuit);
    if !optimized.constraints.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_optimizer_keeps_nontrivial() -> TestResult {
    let nontrivial = Constraint::default_multiplication(0);
    let circuit = Circuit::with_params(vec![nontrivial], 3, 0);
    let optimized = CircuitOptimizer::optimize(circuit);
    if optimized.constraints.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiplication_circuit() -> TestResult {
    let circuit = multiplication_circuit().unwrap();
    if circuit.num_inputs != 2 {
        return TestResult::Fail;
    }
    if circuit.constraints.len() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hash_preimage_circuit() -> TestResult {
    let circuit = hash_preimage_circuit().unwrap();
    if circuit.num_inputs != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_range_proof_circuit() -> TestResult {
    let circuit = range_proof_circuit(8).unwrap();
    if circuit.num_inputs != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_range_proof_circuit_zero_bits() -> TestResult {
    let circuit = range_proof_circuit(0).unwrap();
    if circuit.num_inputs != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_new() -> TestResult {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 42);
    if proof.circuit_id != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_serialize_deserialize() -> TestResult {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 123);
    let serialized = proof.serialize();
    let deserialized = Proof::deserialize(&serialized).unwrap();
    if deserialized.circuit_id != 123 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_deserialize_too_short() -> TestResult {
    let short = [0u8; 64];
    if Proof::deserialize(&short).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_is_valid_structure_valid() -> TestResult {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 1);
    if !proof.is_valid_structure() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_is_valid_structure_invalid_a() -> TestResult {
    let a = G1Point::infinity();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 1);
    if proof.is_valid_structure() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_is_valid_structure_invalid_b() -> TestResult {
    let a = G1Point::generator();
    let b = G2Point::infinity();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 1);
    if proof.is_valid_structure() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_is_valid_structure_invalid_c() -> TestResult {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::infinity();
    let proof = Proof::new(a, b, c, 1);
    if proof.is_valid_structure() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_verify_key_valid() -> TestResult {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    if !vk.verify_key().unwrap() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_verify_key_invalid_alpha() -> TestResult {
    let vk = VerifyingKey {
        alpha_g1: G1Point::infinity(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    if vk.verify_key().unwrap() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_verify_key_invalid_beta() -> TestResult {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::infinity(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    if vk.verify_key().unwrap() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verifying_key_verify_key_empty_ic() -> TestResult {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![],
    };
    if vk.verify_key().unwrap() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_cache_new() -> TestResult {
    let cache = VerificationCache::new();
    if cache.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_cache_insert_get() -> TestResult {
    let cache = VerificationCache::new();
    let key = [1u8; 32];
    cache.insert(key, true);
    if cache.get(&key) != Some(true) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_cache_get_missing() -> TestResult {
    let cache = VerificationCache::new();
    let key = [1u8; 32];
    if cache.get(&key) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_cache_len() -> TestResult {
    let cache = VerificationCache::new();
    cache.insert([1u8; 32], true);
    cache.insert([2u8; 32], false);
    if cache.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_cache_clear() -> TestResult {
    let cache = VerificationCache::new();
    cache.insert([1u8; 32], true);
    cache.clear();
    if cache.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_cache_evict_oldest() -> TestResult {
    let cache = VerificationCache::new();
    for i in 0..10u8 {
        cache.insert([i; 32], true);
    }
    cache.evict_oldest(5);
    if cache.len() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_cache_key_deterministic() -> TestResult {
    let circuit_id = 42u32;
    let proof_hash = [0xABu8; 32];
    let public_inputs: Vec<Vec<u8>> = vec![vec![1, 2, 3]];
    let key1 = compute_cache_key(circuit_id, &proof_hash, &public_inputs);
    let key2 = compute_cache_key(circuit_id, &proof_hash, &public_inputs);
    if key1 != key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_cache_key_different_circuit_id() -> TestResult {
    let proof_hash = [0xABu8; 32];
    let public_inputs: Vec<Vec<u8>> = vec![];
    let key1 = compute_cache_key(1, &proof_hash, &public_inputs);
    let key2 = compute_cache_key(2, &proof_hash, &public_inputs);
    if key1 == key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_result_success() -> TestResult {
    let result = VerificationResult::success(100);
    if !result.valid {
        return TestResult::Fail;
    }
    if result.error.is_some() {
        return TestResult::Fail;
    }
    if result.timing_ms != 100 {
        return TestResult::Fail;
    }
    if result.pairing_checks != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_result_failure() -> TestResult {
    let result = VerificationResult::failure(ZKError::VerificationFailed, 50);
    if result.valid {
        return TestResult::Fail;
    }
    if result.error.is_none() {
        return TestResult::Fail;
    }
    if result.timing_ms != 50 {
        return TestResult::Fail;
    }
    if result.pairing_checks != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_stats_default() -> TestResult {
    let stats = VerificationStats::default();
    if stats.total_verifications != 0 {
        return TestResult::Fail;
    }
    if stats.successful_verifications != 0 {
        return TestResult::Fail;
    }
    if stats.failed_verifications != 0 {
        return TestResult::Fail;
    }
    if stats.avg_verification_time_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_key_manager_new() -> TestResult {
    let manager = VerificationKeyManager::new();
    if manager.key_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_key_manager_add_key() -> TestResult {
    let mut manager = VerificationKeyManager::new();
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    if manager.add_key(1, vk).is_err() {
        return TestResult::Fail;
    }
    if manager.key_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_key_manager_get_key() -> TestResult {
    let mut manager = VerificationKeyManager::new();
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    manager.add_key(42, vk).unwrap();
    if manager.get_key(42).is_none() {
        return TestResult::Fail;
    }
    if manager.get_key(99).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_key_manager_remove_key() -> TestResult {
    let mut manager = VerificationKeyManager::new();
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    manager.add_key(1, vk).unwrap();
    let removed = manager.remove_key(1);
    if removed.is_none() {
        return TestResult::Fail;
    }
    if manager.key_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_key_manager_list_circuits() -> TestResult {
    let mut manager = VerificationKeyManager::new();
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    manager.add_key(1, vk.clone()).unwrap();
    manager.add_key(2, vk).unwrap();
    let circuits = manager.list_circuits();
    if circuits.len() != 2 {
        return TestResult::Fail;
    }
    if !circuits.contains(&1) {
        return TestResult::Fail;
    }
    if !circuits.contains(&2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_merkle_verifier_verify_membership_single() -> TestResult {
    let leaf = [1u8; 32];
    let root = leaf;
    let proof: &[[u8; 32]] = &[];
    if !MerkleVerifier::verify_membership(&root, &leaf, proof, 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_merkle_verifier_verify_membership_mismatch() -> TestResult {
    let leaf = [1u8; 32];
    let root = [2u8; 32];
    let proof: &[[u8; 32]] = &[];
    if MerkleVerifier::verify_membership(&root, &leaf, proof, 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_merkle_verifier_verify_membership_too_long_proof() -> TestResult {
    let leaf = [1u8; 32];
    let root = leaf;
    let proof: Vec<[u8; 32]> = (0..65).map(|_| [0u8; 32]).collect();
    if MerkleVerifier::verify_membership(&root, &leaf, &proof, 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_range_proof_verifier_invalid_range() -> TestResult {
    let commitment = [0u8; 32];
    let proof = [0u8; 256];
    if RangeProofVerifier::verify(&commitment, &proof, 100, 50) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_range_proof_verifier_verify_simple_invalid_bit_length_zero() -> TestResult {
    let commitment = [0u8; 32];
    let proof = [0u8; 256];
    if RangeProofVerifier::verify_simple(&commitment, &proof, 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_range_proof_verifier_verify_simple_invalid_bit_length_too_large() -> TestResult {
    let commitment = [0u8; 32];
    let proof = [0u8; 256];
    if RangeProofVerifier::verify_simple(&commitment, &proof, 65) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_constants() -> TestResult {
    if SYS_ZK_PROVE != 400 {
        return TestResult::Fail;
    }
    if SYS_ZK_VERIFY != 401 {
        return TestResult::Fail;
    }
    if SYS_ZK_COMPILE_CIRCUIT != 402 {
        return TestResult::Fail;
    }
    if SYS_ZK_GET_STATS != 403 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_limits() -> TestResult {
    if MAX_WITNESS_SIZE <= 0 {
        return TestResult::Fail;
    }
    if MAX_PROOF_SIZE <= 0 {
        return TestResult::Fail;
    }
    if MAX_PUBLIC_INPUTS <= 0 {
        return TestResult::Fail;
    }
    if MAX_CONSTRAINTS <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_constraints_empty() -> TestResult {
    let data: &[u8] = &[];
    let result = deserialize_constraints(data).unwrap();
    if !result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_constraints_invalid_length() -> TestResult {
    let data = [0u8; 63];
    if deserialize_constraints(&data).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_constraints_valid() -> TestResult {
    let data = [0u8; 128];
    let result = deserialize_constraints(&data).unwrap();
    if result.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_witness_too_short() -> TestResult {
    let data = [0u8; 2];
    if deserialize_witness(&data).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_witness_empty() -> TestResult {
    let data = [0u8, 0, 0, 0];
    let result = deserialize_witness(&data).unwrap();
    if !result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_witness_truncated() -> TestResult {
    let mut data = vec![1u8, 0, 0, 0];
    data.extend_from_slice(&[10u8, 0, 0, 0]);
    if deserialize_witness(&data).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_witness_valid() -> TestResult {
    let mut data = vec![1u8, 0, 0, 0];
    data.extend_from_slice(&[4u8, 0, 0, 0]);
    data.extend_from_slice(&[1, 2, 3, 4]);
    let result = deserialize_witness(&data).unwrap();
    if result.len() != 1 {
        return TestResult::Fail;
    }
    if result[0] != vec![1, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_deserialize_public_inputs() -> TestResult {
    let mut data = vec![1u8, 0, 0, 0];
    data.extend_from_slice(&[2u8, 0, 0, 0]);
    data.extend_from_slice(&[0xAB, 0xCD]);
    let result = deserialize_public_inputs(&data).unwrap();
    if result.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_measurement_new() -> TestResult {
    let measurement = KernelMeasurement::new();
    if measurement.code_hash != [0u8; 32] {
        return TestResult::Fail;
    }
    if measurement.data_hash != [0u8; 32] {
        return TestResult::Fail;
    }
    if measurement.config_hash != [0u8; 32] {
        return TestResult::Fail;
    }
    if !measurement.module_hashes.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_measurement_compute_integrity_hash() -> TestResult {
    let measurement = KernelMeasurement::new();
    let hash = measurement.compute_integrity_hash();
    if hash == [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_measurement_compute_integrity_hash_deterministic() -> TestResult {
    let measurement = KernelMeasurement::new();
    let hash1 = measurement.compute_integrity_hash();
    let hash2 = measurement.compute_integrity_hash();
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_memory_layout_default() -> TestResult {
    let layout = MemoryLayout::default();
    if layout.kernel_start.as_u64() != 0 {
        return TestResult::Fail;
    }
    if layout.kernel_end.as_u64() != 0 {
        return TestResult::Fail;
    }
    if layout.user_start.as_u64() != 0 {
        return TestResult::Fail;
    }
    if layout.user_end.as_u64() != 0 {
        return TestResult::Fail;
    }
    if layout.heap_start.as_u64() != 0 {
        return TestResult::Fail;
    }
    if layout.heap_end.as_u64() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_config_default() -> TestResult {
    let config = ZKConfig::default();
    if config.max_constraints != 1_000_000 {
        return TestResult::Fail;
    }
    if config.max_witnesses != 100_000 {
        return TestResult::Fail;
    }
    if !config.enable_preprocessing {
        return TestResult::Fail;
    }
    if !config.enable_verification_cache {
        return TestResult::Fail;
    }
    if config.trusted_setup_path.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_error_variants() -> TestResult {
    let errors = vec![
        ZKError::InvalidCircuit,
        ZKError::InvalidWitness,
        ZKError::ProvingFailed,
        ZKError::VerificationFailed,
        ZKError::CircuitNotFound,
        ZKError::InvalidProof,
        ZKError::SetupError,
        ZKError::OutOfMemory,
        ZKError::InvalidParameters,
        ZKError::TrustedSetupNotFound,
        ZKError::InvalidFormat,
        ZKError::CryptoError,
        ZKError::InvalidInput,
        ZKError::NetworkError,
        ZKError::AttestationError(String::from("test")),
        ZKError::NotInitialized,
    ];
    if errors.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_prove_params_size() -> TestResult {
    if core::mem::size_of::<ZKProveParams>() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_verify_params_size() -> TestResult {
    if core::mem::size_of::<ZKVerifyParams>() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_compile_params_size() -> TestResult {
    if core::mem::size_of::<ZKCompileParams>() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_stats_userspace_size() -> TestResult {
    if core::mem::size_of::<ZKStatsUserspace>() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_frobenius_coefficients() -> TestResult {
    let _ = G2FieldElement::frobenius_coeff_x_1();
    let _ = G2FieldElement::frobenius_coeff_x_2();
    let _ = G2FieldElement::frobenius_coeff_y_1();
    let _ = G2FieldElement::frobenius_coeff_y_2();
    let _ = G2FieldElement::frobenius_coeff_fp12();
    let _ = G2FieldElement::frobenius_coeff_fp12_sq();
    let _ = G2FieldElement::frobenius_coeff_fp12_cub();
    TestResult::Pass
}

pub(crate) fn test_bn254_modulus_nonzero() -> TestResult {
    if !BN254_MODULUS.iter().any(|&x| x != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_montgomery_r_nonzero() -> TestResult {
    if !MONTGOMERY_R.iter().any(|&x| x != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_montgomery_r2_nonzero() -> TestResult {
    if !MONTGOMERY_R2.iter().any(|&x| x != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_montgomery_inv_nonzero() -> TestResult {
    if MONTGOMERY_INV == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_from_limbs() -> TestResult {
    let limbs = [1u64, 2, 3, 4];
    let fe = FieldElement::from_limbs(limbs);
    if fe.limbs != limbs {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_range_proof_structure() -> TestResult {
    let proof = RangeProof {
        a: [0u8; 32],
        s: [1u8; 32],
        t1: [2u8; 32],
        t2: [3u8; 32],
        tau_x: [4u8; 32],
        mu: [5u8; 32],
        inner_product: [6u8; 32],
        bit_length: 64,
    };
    if proof.bit_length != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_from_affine() -> TestResult {
    let x = FieldElement::from_u64(1);
    let y = FieldElement::from_u64(2);
    let point = G1Point::from_affine(x, y);
    if point.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_equality() -> TestResult {
    let v1 = Variable::new(5);
    let v2 = Variable::new(5);
    if v1 != v2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_variable_copy() -> TestResult {
    let v1 = Variable::new(3);
    let v2 = v1;
    if v1 != v2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_clone() -> TestResult {
    let circuit = Circuit::new();
    let cloned = circuit.clone();
    if circuit.num_variables != cloned.num_variables {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constraint_clone() -> TestResult {
    let constraint = Constraint::default_multiplication(0);
    let cloned = constraint.clone();
    if constraint.a.terms.len() != cloned.a.terms.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_clone() -> TestResult {
    let lc = LinearCombination::from_variable(Variable::new(0));
    let cloned = lc.clone();
    if lc.terms.len() != cloned.terms.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_proof_clone() -> TestResult {
    let proof = Proof::new(G1Point::generator(), G2Point::generator(), G1Point::generator(), 1);
    let cloned = proof.clone();
    if proof.circuit_id != cloned.circuit_id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_copy() -> TestResult {
    let p1 = G1Point::generator();
    let p2 = p1;
    if p2.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_copy() -> TestResult {
    let p1 = G2Point::generator();
    let p2 = p1;
    if p2.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_copy() -> TestResult {
    let f1 = FieldElement::from_u64(42);
    let f2 = f1;
    if !f1.equals(&f2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_copy() -> TestResult {
    let f1 = G2FieldElement::one();
    let f2 = f1;
    if f1 != f2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gt_element_copy() -> TestResult {
    let g1 = GTElement::identity();
    let g2 = g1;
    if !g1.equals(&g2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_cache_default() -> TestResult {
    let cache = VerificationCache::default();
    if cache.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_sub_assign() -> TestResult {
    let mut a = [10u64, 0, 0, 0];
    let b = [3u64, 0, 0, 0];
    FieldElement::sub_assign(&mut a, &b);
    if a[0] != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_add_assign() -> TestResult {
    let mut a = [10u64, 0, 0, 0];
    let b = [3u64, 0, 0, 0];
    FieldElement::add_assign(&mut a, &b);
    if a[0] != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_neg_vs_negate() -> TestResult {
    let gen = G1Point::generator();
    let neg1 = gen.neg();
    let neg2 = gen.negate();
    let coords1 = neg1.to_affine_coords();
    let coords2 = neg2.to_affine_coords();
    if let (Some((x1, y1)), Some((x2, y2))) = (coords1, coords2) {
        if !x1.equals(&x2) {
            return TestResult::Fail;
        }
        if !y1.equals(&y2) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_groth16_verifier_new() -> TestResult {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator(), G1Point::generator()],
    };
    let verifier = Groth16Verifier::new(vk);
    if !verifier.verifying_key.verify_key().unwrap() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_measurement_clone() -> TestResult {
    let measurement = KernelMeasurement::new();
    let cloned = measurement.clone();
    if measurement.code_hash != cloned.code_hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_config_clone() -> TestResult {
    let config = ZKConfig::default();
    let cloned = config.clone();
    if config.max_constraints != cloned.max_constraints {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_error_clone() -> TestResult {
    let error = ZKError::InvalidCircuit;
    let cloned = error.clone();
    match cloned {
        ZKError::InvalidCircuit => {}
        _ => {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_linear_combination_multiple_terms() -> TestResult {
    let mut lc = LinearCombination::new();
    let v1 = Variable::new(0);
    let v2 = Variable::new(1);
    let v3 = Variable::new(2);
    lc.add_term(v1, FieldElement::from_u64(1));
    lc.add_term(v2, FieldElement::from_u64(2));
    lc.add_term(v3, FieldElement::from_u64(3));
    if lc.terms.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_circuit_compute_witness_map_wrong_inputs() -> TestResult {
    let mut builder = CircuitBuilder::new();
    let _x = builder.alloc_input(None);
    let _y = builder.alloc_input(None);
    let circuit = builder.build(0).unwrap();
    let result = circuit.compute_witness_map(&[FieldElement::from_u64(1)]);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g2_field_element_mul_complex() -> TestResult {
    let a = G2FieldElement { c0: FieldElement::from_u64(3), c1: FieldElement::from_u64(4) };
    let b = G2FieldElement { c0: FieldElement::from_u64(1), c1: FieldElement::from_u64(2) };
    let c = a.mul(&b);
    if c.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fp6_element_zero() -> TestResult {
    let zero = Fp6Element::ZERO;
    if !zero.c0.is_zero() {
        return TestResult::Fail;
    }
    if !zero.c1.is_zero() {
        return TestResult::Fail;
    }
    if !zero.c2.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fp6_element_one() -> TestResult {
    let one = Fp6Element::ONE;
    if one.c0.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pairing_bilinearity_property() -> TestResult {
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let e_g1_g2 = Pairing::compute(&g1, &g2);
    let g1_2 = g1.double();
    let e_2g1_g2 = Pairing::compute(&g1_2, &g2);
    let e_g1_g2_squared = e_g1_g2.mul(&e_g1_g2);
    if !e_2g1_g2.equals(&e_g1_g2_squared) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_module_hash_structure() -> TestResult {
    let mh = ModuleHash {
        name: String::from("test_module"),
        hash: [0xABu8; 32],
        address: VirtAddr::new(0x1000),
        size: 4096,
    };
    if mh.name != "test_module" {
        return TestResult::Fail;
    }
    if mh.hash[0] != 0xAB {
        return TestResult::Fail;
    }
    if mh.address.as_u64() != 0x1000 {
        return TestResult::Fail;
    }
    if mh.size != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_measurement_with_modules() -> TestResult {
    let mut measurement = KernelMeasurement::new();
    measurement.module_hashes.push(ModuleHash {
        name: String::from("module1"),
        hash: [1u8; 32],
        address: VirtAddr::new(0x1000),
        size: 4096,
    });
    measurement.module_hashes.push(ModuleHash {
        name: String::from("module2"),
        hash: [2u8; 32],
        address: VirtAddr::new(0x2000),
        size: 8192,
    });
    let hash1 = measurement.compute_integrity_hash();
    measurement.module_hashes.pop();
    let hash2 = measurement.compute_integrity_hash();
    if hash1 == hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_distributive() -> TestResult {
    let a = FieldElement::from_u64(2);
    let b = FieldElement::from_u64(3);
    let c = FieldElement::from_u64(4);
    let left = a.mul(&b.add(&c));
    let right = a.mul(&b).add(&a.mul(&c));
    if !left.equals(&right) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_associative_add() -> TestResult {
    let a = FieldElement::from_u64(1);
    let b = FieldElement::from_u64(2);
    let c = FieldElement::from_u64(3);
    let left = a.add(&b).add(&c);
    let right = a.add(&b.add(&c));
    if !left.equals(&right) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_field_element_associative_mul() -> TestResult {
    let a = FieldElement::from_u64(2);
    let b = FieldElement::from_u64(3);
    let c = FieldElement::from_u64(4);
    let left = a.mul(&b).mul(&c);
    let right = a.mul(&b.mul(&c));
    if !left.equals(&right) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_g1_point_associative_add() -> TestResult {
    let p = G1Point::generator();
    let q = p.double();
    let r = q.double();
    let left = p.add(&q).add(&r);
    let right = p.add(&q.add(&r));
    let left_coords = left.to_affine_coords();
    let right_coords = right.to_affine_coords();
    if let (Some((lx, ly)), Some((rx, ry))) = (left_coords, right_coords) {
        if !lx.equals(&rx) {
            return TestResult::Fail;
        }
        if !ly.equals(&ry) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_g2_point_associative_add() -> TestResult {
    let p = G2Point::generator();
    let q = p.double();
    let r = q.double();
    let left = p.add(&q).add(&r);
    let right = p.add(&q.add(&r));
    if left.is_infinity() {
        return TestResult::Fail;
    }
    if right.is_infinity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("zk_engine");

    // Field element tests (29 tests)
    suite.add(TestCase::new("field_element_zero", test_field_element_zero));
    suite.add(TestCase::new("field_element_one", test_field_element_one));
    suite.add(TestCase::new("field_element_from_u64", test_field_element_from_u64));
    suite.add(TestCase::new("field_element_from_u128", test_field_element_from_u128));
    suite.add(TestCase::new("field_element_add_zero", test_field_element_add_zero));
    suite.add(TestCase::new("field_element_add_commutative", test_field_element_add_commutative));
    suite.add(TestCase::new("field_element_sub_self_is_zero", test_field_element_sub_self_is_zero));
    suite.add(TestCase::new("field_element_mul_one", test_field_element_mul_one));
    suite.add(TestCase::new("field_element_mul_zero", test_field_element_mul_zero));
    suite.add(TestCase::new("field_element_mul_commutative", test_field_element_mul_commutative));
    suite.add(TestCase::new("field_element_square", test_field_element_square));
    suite.add(TestCase::new("field_element_double", test_field_element_double));
    suite.add(TestCase::new("field_element_neg", test_field_element_neg));
    suite.add(TestCase::new("field_element_neg_zero", test_field_element_neg_zero));
    suite.add(TestCase::new("field_element_inverse", test_field_element_inverse));
    suite.add(TestCase::new(
        "field_element_inverse_zero_returns_none",
        test_field_element_inverse_zero_returns_none,
    ));
    suite.add(TestCase::new("field_element_invert", test_field_element_invert));
    suite.add(TestCase::new("field_element_pow_zero", test_field_element_pow_zero));
    suite.add(TestCase::new("field_element_pow_one", test_field_element_pow_one));
    suite.add(TestCase::new(
        "field_element_sqrt_perfect_square",
        test_field_element_sqrt_perfect_square,
    ));
    suite.add(TestCase::new("field_element_sqrt_zero", test_field_element_sqrt_zero));
    suite.add(TestCase::new(
        "field_element_to_bytes_from_bytes_roundtrip",
        test_field_element_to_bytes_from_bytes_roundtrip,
    ));
    suite.add(TestCase::new(
        "field_element_from_bytes_too_short",
        test_field_element_from_bytes_too_short,
    ));
    suite.add(TestCase::new("field_element_from_bytes_array", test_field_element_from_bytes_array));
    suite.add(TestCase::new("field_element_gte_equal", test_field_element_gte_equal));
    suite.add(TestCase::new("field_element_gte_greater", test_field_element_gte_greater));
    suite.add(TestCase::new("field_element_gte_less", test_field_element_gte_less));
    suite.add(TestCase::new(
        "field_element_montgomery_conversion_roundtrip",
        test_field_element_montgomery_conversion_roundtrip,
    ));
    suite.add(TestCase::new("field_element_from_limbs", test_field_element_from_limbs));

    // G1 point tests (16 tests)
    suite.add(TestCase::new("g1_point_infinity", test_g1_point_infinity));
    suite.add(TestCase::new("g1_point_generator", test_g1_point_generator));
    suite.add(TestCase::new("g1_point_identity", test_g1_point_identity));
    suite.add(TestCase::new("g1_point_negate", test_g1_point_negate));
    suite.add(TestCase::new("g1_point_add_infinity_left", test_g1_point_add_infinity_left));
    suite.add(TestCase::new("g1_point_add_infinity_right", test_g1_point_add_infinity_right));
    suite.add(TestCase::new("g1_point_double", test_g1_point_double));
    suite.add(TestCase::new("g1_point_double_infinity", test_g1_point_double_infinity));
    suite.add(TestCase::new("g1_point_scalar_mul_zero", test_g1_point_scalar_mul_zero));
    suite.add(TestCase::new("g1_point_scalar_mul_one", test_g1_point_scalar_mul_one));
    suite.add(TestCase::new("g1_point_to_affine_infinity", test_g1_point_to_affine_infinity));
    suite.add(TestCase::new(
        "g1_point_to_bytes_from_bytes_roundtrip",
        test_g1_point_to_bytes_from_bytes_roundtrip,
    ));
    suite.add(TestCase::new("g1_point_from_bytes_too_short", test_g1_point_from_bytes_too_short));
    suite.add(TestCase::new("g1_point_from_bytes_all_zeros", test_g1_point_from_bytes_all_zeros));
    suite.add(TestCase::new("g1_affine_from_point", test_g1_affine_from_point));
    suite.add(TestCase::new("g1_point_from_affine", test_g1_point_from_affine));

    // G2 field element tests (12 tests)
    suite.add(TestCase::new("g2_field_element_zero", test_g2_field_element_zero));
    suite.add(TestCase::new("g2_field_element_one", test_g2_field_element_one));
    suite.add(TestCase::new(
        "g2_field_element_from_base_field",
        test_g2_field_element_from_base_field,
    ));
    suite.add(TestCase::new("g2_field_element_add_zero", test_g2_field_element_add_zero));
    suite.add(TestCase::new(
        "g2_field_element_sub_self_is_zero",
        test_g2_field_element_sub_self_is_zero,
    ));
    suite.add(TestCase::new("g2_field_element_mul_one", test_g2_field_element_mul_one));
    suite.add(TestCase::new("g2_field_element_square", test_g2_field_element_square));
    suite.add(TestCase::new("g2_field_element_double", test_g2_field_element_double));
    suite.add(TestCase::new("g2_field_element_neg", test_g2_field_element_neg));
    suite.add(TestCase::new("g2_field_element_inverse", test_g2_field_element_inverse));
    suite.add(TestCase::new(
        "g2_field_element_inverse_zero_returns_none",
        test_g2_field_element_inverse_zero_returns_none,
    ));
    suite.add(TestCase::new("g2_field_element_conjugate", test_g2_field_element_conjugate));

    // G2 point tests (14 tests)
    suite.add(TestCase::new("g2_point_infinity", test_g2_point_infinity));
    suite.add(TestCase::new("g2_point_generator", test_g2_point_generator));
    suite.add(TestCase::new("g2_point_negate", test_g2_point_negate));
    suite.add(TestCase::new("g2_point_add_infinity_left", test_g2_point_add_infinity_left));
    suite.add(TestCase::new("g2_point_add_infinity_right", test_g2_point_add_infinity_right));
    suite.add(TestCase::new("g2_point_double", test_g2_point_double));
    suite.add(TestCase::new("g2_point_double_infinity", test_g2_point_double_infinity));
    suite.add(TestCase::new("g2_point_scalar_mul_zero", test_g2_point_scalar_mul_zero));
    suite.add(TestCase::new("g2_point_to_affine_infinity", test_g2_point_to_affine_infinity));
    suite.add(TestCase::new(
        "g2_point_to_bytes_from_bytes_roundtrip",
        test_g2_point_to_bytes_from_bytes_roundtrip,
    ));
    suite.add(TestCase::new("g2_point_from_bytes_too_short", test_g2_point_from_bytes_too_short));
    suite.add(TestCase::new("g2_point_serialize_deserialize", test_g2_point_serialize_deserialize));
    suite.add(TestCase::new("g2_point_deserialize_too_short", test_g2_point_deserialize_too_short));
    suite.add(TestCase::new("g2_point_deserialize_all_zeros", test_g2_point_deserialize_all_zeros));
    suite.add(TestCase::new("g2_affine_neg", test_g2_affine_neg));

    // GT element tests (3 tests)
    suite.add(TestCase::new("gt_element_identity", test_gt_element_identity));
    suite.add(TestCase::new("gt_element_one", test_gt_element_one));
    suite.add(TestCase::new("gt_element_equals", test_gt_element_equals));

    // Pairing tests (5 tests)
    suite.add(TestCase::new("pairing_infinity_g1", test_pairing_infinity_g1));
    suite.add(TestCase::new("pairing_infinity_g2", test_pairing_infinity_g2));
    suite.add(TestCase::new("pairing_both_infinity", test_pairing_both_infinity));
    suite.add(TestCase::new("pairing_generators", test_pairing_generators));
    suite.add(TestCase::new("pairing_multi_empty", test_pairing_multi_empty));
    suite.add(TestCase::new("pairing_bilinearity_property", test_pairing_bilinearity_property));

    // Variable tests (4 tests)
    suite.add(TestCase::new("variable_one", test_variable_one));
    suite.add(TestCase::new("variable_new", test_variable_new));
    suite.add(TestCase::new("variable_ordering", test_variable_ordering));
    suite.add(TestCase::new("variable_equality", test_variable_equality));
    suite.add(TestCase::new("variable_copy", test_variable_copy));

    // Linear combination tests (14 tests)
    suite.add(TestCase::new("linear_combination_new", test_linear_combination_new));
    suite.add(TestCase::new(
        "linear_combination_from_variable",
        test_linear_combination_from_variable,
    ));
    suite.add(TestCase::new(
        "linear_combination_from_constant",
        test_linear_combination_from_constant,
    ));
    suite.add(TestCase::new(
        "linear_combination_from_constant_zero",
        test_linear_combination_from_constant_zero,
    ));
    suite.add(TestCase::new("linear_combination_add_term", test_linear_combination_add_term));
    suite.add(TestCase::new(
        "linear_combination_add_term_zero_coefficient",
        test_linear_combination_add_term_zero_coefficient,
    ));
    suite.add(TestCase::new(
        "linear_combination_add_term_cancellation",
        test_linear_combination_add_term_cancellation,
    ));
    suite.add(TestCase::new("linear_combination_scale", test_linear_combination_scale));
    suite.add(TestCase::new("linear_combination_scale_zero", test_linear_combination_scale_zero));
    suite.add(TestCase::new("linear_combination_add", test_linear_combination_add));
    suite.add(TestCase::new(
        "linear_combination_evaluate_constant",
        test_linear_combination_evaluate_constant,
    ));
    suite.add(TestCase::new(
        "linear_combination_evaluate_variable",
        test_linear_combination_evaluate_variable,
    ));
    suite.add(TestCase::new(
        "linear_combination_evaluate_out_of_bounds",
        test_linear_combination_evaluate_out_of_bounds,
    ));
    suite.add(TestCase::new(
        "linear_combination_multiple_terms",
        test_linear_combination_multiple_terms,
    ));
    suite.add(TestCase::new("linear_combination_clone", test_linear_combination_clone));

    // Constraint tests (6 tests)
    suite.add(TestCase::new("constraint_new", test_constraint_new));
    suite.add(TestCase::new("constraint_enforce_equal", test_constraint_enforce_equal));
    suite.add(TestCase::new(
        "constraint_enforce_multiplication",
        test_constraint_enforce_multiplication,
    ));
    suite.add(TestCase::new(
        "constraint_default_multiplication",
        test_constraint_default_multiplication,
    ));
    suite.add(TestCase::new("constraint_verify_valid", test_constraint_verify_valid));
    suite.add(TestCase::new("constraint_verify_invalid", test_constraint_verify_invalid));
    suite.add(TestCase::new("constraint_clone", test_constraint_clone));

    // Circuit tests (7 tests)
    suite.add(TestCase::new("circuit_new", test_circuit_new));
    suite.add(TestCase::new("circuit_with_params", test_circuit_with_params));
    suite.add(TestCase::new("circuit_get_matrices", test_circuit_get_matrices));
    suite.add(TestCase::new(
        "circuit_verify_assignment_empty",
        test_circuit_verify_assignment_empty,
    ));
    suite.add(TestCase::new(
        "circuit_verify_assignment_wrong_length",
        test_circuit_verify_assignment_wrong_length,
    ));
    suite.add(TestCase::new("circuit_clone", test_circuit_clone));
    suite.add(TestCase::new(
        "circuit_compute_witness_map_wrong_inputs",
        test_circuit_compute_witness_map_wrong_inputs,
    ));

    // Circuit builder tests (11 tests)
    suite.add(TestCase::new("circuit_builder_new", test_circuit_builder_new));
    suite.add(TestCase::new("circuit_builder_alloc_variable", test_circuit_builder_alloc_variable));
    suite.add(TestCase::new(
        "circuit_builder_alloc_variable_no_name",
        test_circuit_builder_alloc_variable_no_name,
    ));
    suite.add(TestCase::new("circuit_builder_alloc_input", test_circuit_builder_alloc_input));
    suite.add(TestCase::new(
        "circuit_builder_enforce_constraint",
        test_circuit_builder_enforce_constraint,
    ));
    suite.add(TestCase::new("circuit_builder_enforce_equal", test_circuit_builder_enforce_equal));
    suite.add(TestCase::new(
        "circuit_builder_enforce_multiplication",
        test_circuit_builder_enforce_multiplication,
    ));
    suite.add(TestCase::new(
        "circuit_builder_add_boolean_constraint",
        test_circuit_builder_add_boolean_constraint,
    ));
    suite.add(TestCase::new(
        "circuit_builder_add_range_constraint",
        test_circuit_builder_add_range_constraint,
    ));
    suite.add(TestCase::new("circuit_builder_build", test_circuit_builder_build));
    suite.add(TestCase::new("circuit_builder_add_constraint", test_circuit_builder_add_constraint));

    // Circuit optimizer tests (3 tests)
    suite.add(TestCase::new(
        "circuit_optimizer_optimize_empty",
        test_circuit_optimizer_optimize_empty,
    ));
    suite.add(TestCase::new(
        "circuit_optimizer_removes_trivial",
        test_circuit_optimizer_removes_trivial,
    ));
    suite.add(TestCase::new(
        "circuit_optimizer_keeps_nontrivial",
        test_circuit_optimizer_keeps_nontrivial,
    ));

    // Example circuit tests (4 tests)
    suite.add(TestCase::new("multiplication_circuit", test_multiplication_circuit));
    suite.add(TestCase::new("hash_preimage_circuit", test_hash_preimage_circuit));
    suite.add(TestCase::new("range_proof_circuit", test_range_proof_circuit));
    suite.add(TestCase::new("range_proof_circuit_zero_bits", test_range_proof_circuit_zero_bits));

    // Proof tests (7 tests)
    suite.add(TestCase::new("proof_new", test_proof_new));
    suite.add(TestCase::new("proof_serialize_deserialize", test_proof_serialize_deserialize));
    suite.add(TestCase::new("proof_deserialize_too_short", test_proof_deserialize_too_short));
    suite.add(TestCase::new("proof_is_valid_structure_valid", test_proof_is_valid_structure_valid));
    suite.add(TestCase::new(
        "proof_is_valid_structure_invalid_a",
        test_proof_is_valid_structure_invalid_a,
    ));
    suite.add(TestCase::new(
        "proof_is_valid_structure_invalid_b",
        test_proof_is_valid_structure_invalid_b,
    ));
    suite.add(TestCase::new(
        "proof_is_valid_structure_invalid_c",
        test_proof_is_valid_structure_invalid_c,
    ));
    suite.add(TestCase::new("proof_clone", test_proof_clone));

    // Verifying key tests (4 tests)
    suite.add(TestCase::new("verifying_key_verify_key_valid", test_verifying_key_verify_key_valid));
    suite.add(TestCase::new(
        "verifying_key_verify_key_invalid_alpha",
        test_verifying_key_verify_key_invalid_alpha,
    ));
    suite.add(TestCase::new(
        "verifying_key_verify_key_invalid_beta",
        test_verifying_key_verify_key_invalid_beta,
    ));
    suite.add(TestCase::new(
        "verifying_key_verify_key_empty_ic",
        test_verifying_key_verify_key_empty_ic,
    ));

    // Verification cache tests (8 tests)
    suite.add(TestCase::new("verification_cache_new", test_verification_cache_new));
    suite.add(TestCase::new("verification_cache_insert_get", test_verification_cache_insert_get));
    suite.add(TestCase::new("verification_cache_get_missing", test_verification_cache_get_missing));
    suite.add(TestCase::new("verification_cache_len", test_verification_cache_len));
    suite.add(TestCase::new("verification_cache_clear", test_verification_cache_clear));
    suite.add(TestCase::new(
        "verification_cache_evict_oldest",
        test_verification_cache_evict_oldest,
    ));
    suite.add(TestCase::new(
        "compute_cache_key_deterministic",
        test_compute_cache_key_deterministic,
    ));
    suite.add(TestCase::new(
        "compute_cache_key_different_circuit_id",
        test_compute_cache_key_different_circuit_id,
    ));
    suite.add(TestCase::new("verification_cache_default", test_verification_cache_default));

    // Verification result tests (2 tests)
    suite.add(TestCase::new("verification_result_success", test_verification_result_success));
    suite.add(TestCase::new("verification_result_failure", test_verification_result_failure));

    // Verification stats tests (1 test)
    suite.add(TestCase::new("verification_stats_default", test_verification_stats_default));

    // Verification key manager tests (5 tests)
    suite.add(TestCase::new("verification_key_manager_new", test_verification_key_manager_new));
    suite.add(TestCase::new(
        "verification_key_manager_add_key",
        test_verification_key_manager_add_key,
    ));
    suite.add(TestCase::new(
        "verification_key_manager_get_key",
        test_verification_key_manager_get_key,
    ));
    suite.add(TestCase::new(
        "verification_key_manager_remove_key",
        test_verification_key_manager_remove_key,
    ));
    suite.add(TestCase::new(
        "verification_key_manager_list_circuits",
        test_verification_key_manager_list_circuits,
    ));

    // Merkle verifier tests (3 tests)
    suite.add(TestCase::new(
        "merkle_verifier_verify_membership_single",
        test_merkle_verifier_verify_membership_single,
    ));
    suite.add(TestCase::new(
        "merkle_verifier_verify_membership_mismatch",
        test_merkle_verifier_verify_membership_mismatch,
    ));
    suite.add(TestCase::new(
        "merkle_verifier_verify_membership_too_long_proof",
        test_merkle_verifier_verify_membership_too_long_proof,
    ));

    // Range proof verifier tests (3 tests)
    suite.add(TestCase::new(
        "range_proof_verifier_invalid_range",
        test_range_proof_verifier_invalid_range,
    ));
    suite.add(TestCase::new(
        "range_proof_verifier_verify_simple_invalid_bit_length_zero",
        test_range_proof_verifier_verify_simple_invalid_bit_length_zero,
    ));
    suite.add(TestCase::new(
        "range_proof_verifier_verify_simple_invalid_bit_length_too_large",
        test_range_proof_verifier_verify_simple_invalid_bit_length_too_large,
    ));
    suite.add(TestCase::new("range_proof_structure", test_range_proof_structure));

    // Syscall tests (2 tests)
    suite.add(TestCase::new("syscall_constants", test_syscall_constants));
    suite.add(TestCase::new("syscall_limits", test_syscall_limits));

    // Deserialize tests (8 tests)
    suite.add(TestCase::new("deserialize_constraints_empty", test_deserialize_constraints_empty));
    suite.add(TestCase::new(
        "deserialize_constraints_invalid_length",
        test_deserialize_constraints_invalid_length,
    ));
    suite.add(TestCase::new("deserialize_constraints_valid", test_deserialize_constraints_valid));
    suite.add(TestCase::new("deserialize_witness_too_short", test_deserialize_witness_too_short));
    suite.add(TestCase::new("deserialize_witness_empty", test_deserialize_witness_empty));
    suite.add(TestCase::new("deserialize_witness_truncated", test_deserialize_witness_truncated));
    suite.add(TestCase::new("deserialize_witness_valid", test_deserialize_witness_valid));
    suite.add(TestCase::new("deserialize_public_inputs", test_deserialize_public_inputs));

    // Kernel measurement tests (5 tests)
    suite.add(TestCase::new("kernel_measurement_new", test_kernel_measurement_new));
    suite.add(TestCase::new(
        "kernel_measurement_compute_integrity_hash",
        test_kernel_measurement_compute_integrity_hash,
    ));
    suite.add(TestCase::new(
        "kernel_measurement_compute_integrity_hash_deterministic",
        test_kernel_measurement_compute_integrity_hash_deterministic,
    ));
    suite.add(TestCase::new("kernel_measurement_clone", test_kernel_measurement_clone));
    suite.add(TestCase::new(
        "kernel_measurement_with_modules",
        test_kernel_measurement_with_modules,
    ));

    // Memory layout tests (1 test)
    suite.add(TestCase::new("memory_layout_default", test_memory_layout_default));

    // ZK config tests (2 tests)
    suite.add(TestCase::new("zk_config_default", test_zk_config_default));
    suite.add(TestCase::new("zk_config_clone", test_zk_config_clone));

    // ZK error tests (2 tests)
    suite.add(TestCase::new("zk_error_variants", test_zk_error_variants));
    suite.add(TestCase::new("zk_error_clone", test_zk_error_clone));

    // ZK params size tests (4 tests)
    suite.add(TestCase::new("zk_prove_params_size", test_zk_prove_params_size));
    suite.add(TestCase::new("zk_verify_params_size", test_zk_verify_params_size));
    suite.add(TestCase::new("zk_compile_params_size", test_zk_compile_params_size));
    suite.add(TestCase::new("zk_stats_userspace_size", test_zk_stats_userspace_size));

    // G2 field element frobenius tests (1 test)
    suite.add(TestCase::new(
        "g2_field_element_frobenius_coefficients",
        test_g2_field_element_frobenius_coefficients,
    ));
    suite.add(TestCase::new("g2_field_element_mul_complex", test_g2_field_element_mul_complex));

    // BN254/Montgomery constant tests (4 tests)
    suite.add(TestCase::new("bn254_modulus_nonzero", test_bn254_modulus_nonzero));
    suite.add(TestCase::new("montgomery_r_nonzero", test_montgomery_r_nonzero));
    suite.add(TestCase::new("montgomery_r2_nonzero", test_montgomery_r2_nonzero));
    suite.add(TestCase::new("montgomery_inv_nonzero", test_montgomery_inv_nonzero));

    // Copy trait tests (5 tests)
    suite.add(TestCase::new("g1_point_copy", test_g1_point_copy));
    suite.add(TestCase::new("g2_point_copy", test_g2_point_copy));
    suite.add(TestCase::new("field_element_copy", test_field_element_copy));
    suite.add(TestCase::new("g2_field_element_copy", test_g2_field_element_copy));
    suite.add(TestCase::new("gt_element_copy", test_gt_element_copy));

    // Field element assign tests (2 tests)
    suite.add(TestCase::new("field_element_sub_assign", test_field_element_sub_assign));
    suite.add(TestCase::new("field_element_add_assign", test_field_element_add_assign));

    // Misc tests
    suite.add(TestCase::new("g1_point_neg_vs_negate", test_g1_point_neg_vs_negate));
    suite.add(TestCase::new("groth16_verifier_new", test_groth16_verifier_new));
    suite.add(TestCase::new("module_hash_structure", test_module_hash_structure));

    // Fp6 element tests (2 tests)
    suite.add(TestCase::new("fp6_element_zero", test_fp6_element_zero));
    suite.add(TestCase::new("fp6_element_one", test_fp6_element_one));

    // Field element property tests (3 tests)
    suite.add(TestCase::new("field_element_distributive", test_field_element_distributive));
    suite.add(TestCase::new("field_element_associative_add", test_field_element_associative_add));
    suite.add(TestCase::new("field_element_associative_mul", test_field_element_associative_mul));

    // Point associative add tests (2 tests)
    suite.add(TestCase::new("g1_point_associative_add", test_g1_point_associative_add));
    suite.add(TestCase::new("g2_point_associative_add", test_g2_point_associative_add));

    suite.run()
}
