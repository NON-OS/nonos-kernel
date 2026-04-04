use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use crate::memory::VirtAddr;
use crate::zk_engine::groth16::field::{FieldElement, BN254_MODULUS, MONTGOMERY_R, MONTGOMERY_R2, MONTGOMERY_INV};
use crate::zk_engine::groth16::g1::{G1Point, G1Affine};
use crate::zk_engine::groth16::g2::{G2Point, G2FieldElement, G2Affine};
use crate::zk_engine::groth16::gt::{GTElement, Fp6Element};
use crate::zk_engine::groth16::pairing::Pairing;
use crate::zk_engine::groth16::proof::Proof;
use crate::zk_engine::groth16::keys::{ProvingKey, VerifyingKey};
use crate::zk_engine::circuit::{Circuit, CircuitBuilder, Constraint, LinearCombination, Variable, CircuitOptimizer};
use crate::zk_engine::circuit::examples::{multiplication_circuit, hash_preimage_circuit, range_proof_circuit};
use crate::zk_engine::verification::{VerificationCache, compute_cache_key, Groth16Verifier, VerificationResult, VerificationStats, VerificationKeyManager};
use crate::zk_engine::verification::specialized::{MerkleVerifier, RangeProofVerifier, RangeProof};
use crate::zk_engine::setup::{SetupParameters, ToxicWaste, SetupVerifier};
use crate::zk_engine::syscalls::params::{SYS_ZK_PROVE, SYS_ZK_VERIFY, SYS_ZK_COMPILE_CIRCUIT, SYS_ZK_GET_STATS, MAX_WITNESS_SIZE, MAX_PROOF_SIZE, MAX_PUBLIC_INPUTS, MAX_CONSTRAINTS, ZKProveParams, ZKVerifyParams, ZKCompileParams, ZKStatsUserspace};
use crate::zk_engine::syscalls::helpers::{deserialize_constraints, deserialize_witness, deserialize_public_inputs};
use crate::zk_engine::attestation::types::{KernelMeasurement, KernelAttestation, MemoryLayout, ModuleHash};
use crate::zk_engine::types::{ZKConfig, ZKError, ZKProof, ZKStats};

#[test]
fn test_field_element_zero() {
    let zero = FieldElement::zero();
    assert!(zero.is_zero());
    assert_eq!(zero.limbs, [0, 0, 0, 0]);
}

#[test]
fn test_field_element_one() {
    let one = FieldElement::one();
    assert!(!one.is_zero());
    assert_eq!(one.limbs, MONTGOMERY_R);
}

#[test]
fn test_field_element_from_u64() {
    let fe = FieldElement::from_u64(42);
    assert!(!fe.is_zero());
}

#[test]
fn test_field_element_from_u128() {
    let fe = FieldElement::from_u128(0x123456789ABCDEF0_123456789ABCDEF0);
    assert!(!fe.is_zero());
}

#[test]
fn test_field_element_add_zero() {
    let a = FieldElement::from_u64(100);
    let zero = FieldElement::zero();
    let result = a.add(&zero);
    assert!(a.equals(&result));
}

#[test]
fn test_field_element_add_commutative() {
    let a = FieldElement::from_u64(123);
    let b = FieldElement::from_u64(456);
    let ab = a.add(&b);
    let ba = b.add(&a);
    assert!(ab.equals(&ba));
}

#[test]
fn test_field_element_sub_self_is_zero() {
    let a = FieldElement::from_u64(999);
    let result = a.sub(&a);
    assert!(result.is_zero());
}

#[test]
fn test_field_element_mul_one() {
    let a = FieldElement::from_u64(777);
    let one = FieldElement::one();
    let result = a.mul(&one);
    assert!(a.equals(&result));
}

#[test]
fn test_field_element_mul_zero() {
    let a = FieldElement::from_u64(555);
    let zero = FieldElement::zero();
    let result = a.mul(&zero);
    assert!(result.is_zero());
}

#[test]
fn test_field_element_mul_commutative() {
    let a = FieldElement::from_u64(17);
    let b = FieldElement::from_u64(23);
    let ab = a.mul(&b);
    let ba = b.mul(&a);
    assert!(ab.equals(&ba));
}

#[test]
fn test_field_element_square() {
    let a = FieldElement::from_u64(5);
    let square = a.square();
    let manual = a.mul(&a);
    assert!(square.equals(&manual));
}

#[test]
fn test_field_element_double() {
    let a = FieldElement::from_u64(100);
    let doubled = a.double();
    let manual = a.add(&a);
    assert!(doubled.equals(&manual));
}

#[test]
fn test_field_element_neg() {
    let a = FieldElement::from_u64(50);
    let neg_a = a.neg();
    let sum = a.add(&neg_a);
    assert!(sum.is_zero());
}

#[test]
fn test_field_element_neg_zero() {
    let zero = FieldElement::zero();
    let neg_zero = zero.neg();
    assert!(neg_zero.is_zero());
}

#[test]
fn test_field_element_inverse() {
    let a = FieldElement::from_u64(7);
    let inv = a.inverse().unwrap();
    let product = a.mul(&inv);
    assert!(product.equals(&FieldElement::one()));
}

#[test]
fn test_field_element_inverse_zero_returns_none() {
    let zero = FieldElement::zero();
    assert!(zero.inverse().is_none());
}

#[test]
fn test_field_element_invert() {
    let a = FieldElement::from_u64(11);
    let inv = a.invert().unwrap();
    let product = a.mul(&inv);
    assert!(product.equals(&FieldElement::one()));
}

#[test]
fn test_field_element_pow_zero() {
    let a = FieldElement::from_u64(99);
    let result = a.pow(&[0, 0, 0, 0]);
    assert!(result.equals(&FieldElement::one()));
}

#[test]
fn test_field_element_pow_one() {
    let a = FieldElement::from_u64(13);
    let result = a.pow(&[1, 0, 0, 0]);
    assert!(a.equals(&result));
}

#[test]
fn test_field_element_sqrt_perfect_square() {
    let a = FieldElement::from_u64(4);
    let sqrt = a.sqrt();
    if let Some(root) = sqrt {
        let squared = root.square();
        assert!(squared.equals(&a));
    }
}

#[test]
fn test_field_element_sqrt_zero() {
    let zero = FieldElement::zero();
    let sqrt = zero.sqrt().unwrap();
    assert!(sqrt.is_zero());
}

#[test]
fn test_field_element_to_bytes_from_bytes_roundtrip() {
    let a = FieldElement::from_u64(12345);
    let bytes = a.to_bytes();
    let recovered = FieldElement::from_bytes(&bytes).unwrap();
    assert!(a.equals(&recovered));
}

#[test]
fn test_field_element_from_bytes_too_short() {
    let short_bytes = [0u8; 16];
    assert!(FieldElement::from_bytes(&short_bytes).is_err());
}

#[test]
fn test_field_element_from_bytes_array() {
    let bytes = [0u8; 32];
    let fe = FieldElement::from_bytes_array(&bytes);
    assert!(fe.is_zero());
}

#[test]
fn test_field_element_gte_equal() {
    let a = [1u64, 2, 3, 4];
    let b = [1u64, 2, 3, 4];
    assert!(FieldElement::gte(&a, &b));
}

#[test]
fn test_field_element_gte_greater() {
    let a = [1u64, 2, 3, 5];
    let b = [1u64, 2, 3, 4];
    assert!(FieldElement::gte(&a, &b));
}

#[test]
fn test_field_element_gte_less() {
    let a = [1u64, 2, 3, 3];
    let b = [1u64, 2, 3, 4];
    assert!(!FieldElement::gte(&a, &b));
}

#[test]
fn test_field_element_montgomery_conversion_roundtrip() {
    let raw = FieldElement::from_limbs([1, 2, 3, 0]);
    let montgomery = raw.to_montgomery();
    let back = montgomery.from_montgomery();
    assert_eq!(raw.limbs, back.limbs);
}

#[test]
fn test_g1_point_infinity() {
    let inf = G1Point::infinity();
    assert!(inf.is_infinity());
    assert!(inf.is_identity());
}

#[test]
fn test_g1_point_generator() {
    let gen = G1Point::generator();
    assert!(!gen.is_infinity());
}

#[test]
fn test_g1_point_identity() {
    let id = G1Point::identity();
    assert!(id.is_identity());
}

#[test]
fn test_g1_point_negate() {
    let gen = G1Point::generator();
    let neg = gen.negate();
    let sum = gen.add(&neg);
    assert!(sum.is_infinity());
}

#[test]
fn test_g1_point_add_infinity_left() {
    let inf = G1Point::infinity();
    let gen = G1Point::generator();
    let result = inf.add(&gen);
    assert!(!result.is_infinity());
}

#[test]
fn test_g1_point_add_infinity_right() {
    let gen = G1Point::generator();
    let inf = G1Point::infinity();
    let result = gen.add(&inf);
    assert!(!result.is_infinity());
}

#[test]
fn test_g1_point_double() {
    let gen = G1Point::generator();
    let doubled = gen.double();
    let manual = gen.add(&gen);
    let d_coords = doubled.to_affine_coords();
    let m_coords = manual.to_affine_coords();
    if let (Some((dx, dy)), Some((mx, my))) = (d_coords, m_coords) {
        assert!(dx.equals(&mx));
        assert!(dy.equals(&my));
    }
}

#[test]
fn test_g1_point_double_infinity() {
    let inf = G1Point::infinity();
    let doubled = inf.double();
    assert!(doubled.is_infinity());
}

#[test]
fn test_g1_point_scalar_mul_zero() {
    let gen = G1Point::generator();
    let result = gen.scalar_mul(&[0, 0, 0, 0]);
    assert!(result.is_infinity());
}

#[test]
fn test_g1_point_scalar_mul_one() {
    let gen = G1Point::generator();
    let result = gen.scalar_mul(&[1, 0, 0, 0]);
    let gen_coords = gen.to_affine_coords();
    let result_coords = result.to_affine_coords();
    if let (Some((gx, gy)), Some((rx, ry))) = (gen_coords, result_coords) {
        assert!(gx.equals(&rx));
        assert!(gy.equals(&ry));
    }
}

#[test]
fn test_g1_point_to_affine_infinity() {
    let inf = G1Point::infinity();
    assert!(inf.to_affine_coords().is_none());
}

#[test]
fn test_g1_point_to_bytes_from_bytes_roundtrip() {
    let gen = G1Point::generator();
    let bytes = gen.to_bytes();
    let recovered = G1Point::from_bytes(&bytes).unwrap();
    assert!(!recovered.is_infinity());
}

#[test]
fn test_g1_point_from_bytes_too_short() {
    let short = [0u8; 16];
    assert!(G1Point::from_bytes(&short).is_err());
}

#[test]
fn test_g1_point_from_bytes_all_zeros() {
    let zeros = [0u8; 32];
    let result = G1Point::from_bytes(&zeros).unwrap();
    assert!(result.is_infinity());
}

#[test]
fn test_g1_affine_from_point() {
    let gen = G1Point::generator();
    let affine = gen.to_affine();
    assert!(!affine.x.is_zero() || !affine.y.is_zero());
}

#[test]
fn test_g2_field_element_zero() {
    let zero = G2FieldElement::zero();
    assert!(zero.is_zero());
}

#[test]
fn test_g2_field_element_one() {
    let one = G2FieldElement::one();
    assert!(!one.is_zero());
}

#[test]
fn test_g2_field_element_from_base_field() {
    let base = FieldElement::from_u64(42);
    let g2fe = G2FieldElement::from_base_field(&base);
    assert!(!g2fe.is_zero());
    assert!(g2fe.c1.is_zero());
}

#[test]
fn test_g2_field_element_add_zero() {
    let a = G2FieldElement::from_base(&FieldElement::from_u64(100));
    let zero = G2FieldElement::zero();
    let result = a.add(&zero);
    assert_eq!(a, result);
}

#[test]
fn test_g2_field_element_sub_self_is_zero() {
    let a = G2FieldElement::from_base(&FieldElement::from_u64(50));
    let result = a.sub(&a);
    assert!(result.is_zero());
}

#[test]
fn test_g2_field_element_mul_one() {
    let a = G2FieldElement::from_base(&FieldElement::from_u64(77));
    let one = G2FieldElement::one();
    let result = a.mul(&one);
    assert_eq!(a, result);
}

#[test]
fn test_g2_field_element_square() {
    let a = G2FieldElement::from_base(&FieldElement::from_u64(5));
    let squared = a.square();
    let manual = a.mul(&a);
    assert_eq!(squared, manual);
}

#[test]
fn test_g2_field_element_double() {
    let a = G2FieldElement::from_base(&FieldElement::from_u64(10));
    let doubled = a.double();
    let manual = a.add(&a);
    assert_eq!(doubled, manual);
}

#[test]
fn test_g2_field_element_neg() {
    let a = G2FieldElement::from_base(&FieldElement::from_u64(30));
    let neg_a = a.neg();
    let sum = a.add(&neg_a);
    assert!(sum.is_zero());
}

#[test]
fn test_g2_field_element_inverse() {
    let a = G2FieldElement::from_base(&FieldElement::from_u64(7));
    let inv = a.inverse().unwrap();
    let product = a.mul(&inv);
    assert_eq!(product, G2FieldElement::one());
}

#[test]
fn test_g2_field_element_inverse_zero_returns_none() {
    let zero = G2FieldElement::zero();
    assert!(zero.inverse().is_none());
}

#[test]
fn test_g2_field_element_conjugate() {
    let a = G2FieldElement {
        c0: FieldElement::from_u64(10),
        c1: FieldElement::from_u64(20),
    };
    let conj = a.conjugate();
    assert!(conj.c0.equals(&a.c0));
    assert!(conj.c1.equals(&a.c1.neg()));
}

#[test]
fn test_g2_point_infinity() {
    let inf = G2Point::infinity();
    assert!(inf.is_infinity());
    assert!(inf.is_identity());
}

#[test]
fn test_g2_point_generator() {
    let gen = G2Point::generator();
    assert!(!gen.is_infinity());
}

#[test]
fn test_g2_point_negate() {
    let gen = G2Point::generator();
    let neg = gen.negate();
    let sum = gen.add(&neg);
    assert!(sum.is_infinity());
}

#[test]
fn test_g2_point_add_infinity_left() {
    let inf = G2Point::infinity();
    let gen = G2Point::generator();
    let result = inf.add(&gen);
    assert!(!result.is_infinity());
}

#[test]
fn test_g2_point_add_infinity_right() {
    let gen = G2Point::generator();
    let inf = G2Point::infinity();
    let result = gen.add(&inf);
    assert!(!result.is_infinity());
}

#[test]
fn test_g2_point_double() {
    let gen = G2Point::generator();
    let doubled = gen.double();
    let manual = gen.add(&gen);
    assert!(!doubled.is_infinity());
    assert!(!manual.is_infinity());
}

#[test]
fn test_g2_point_double_infinity() {
    let inf = G2Point::infinity();
    let doubled = inf.double();
    assert!(doubled.is_infinity());
}

#[test]
fn test_g2_point_scalar_mul_zero() {
    let gen = G2Point::generator();
    let result = gen.scalar_mul(&[0, 0, 0, 0]);
    assert!(result.is_infinity());
}

#[test]
fn test_g2_point_to_affine_infinity() {
    let inf = G2Point::infinity();
    assert!(inf.to_affine_coords().is_none());
}

#[test]
fn test_g2_point_to_bytes_from_bytes_roundtrip() {
    let gen = G2Point::generator();
    let bytes = gen.to_bytes();
    let recovered = G2Point::from_bytes(&bytes).unwrap();
    assert!(!recovered.is_infinity());
}

#[test]
fn test_g2_point_from_bytes_too_short() {
    let short = [0u8; 32];
    assert!(G2Point::from_bytes(&short).is_err());
}

#[test]
fn test_g2_point_serialize_deserialize() {
    let gen = G2Point::generator();
    let serialized = gen.serialize();
    let deserialized = G2Point::deserialize(&serialized).unwrap();
    assert!(!deserialized.is_infinity());
}

#[test]
fn test_g2_point_deserialize_too_short() {
    let short = [0u8; 64];
    assert!(G2Point::deserialize(&short).is_err());
}

#[test]
fn test_g2_point_deserialize_all_zeros() {
    let zeros = [0u8; 128];
    let result = G2Point::deserialize(&zeros).unwrap();
    assert!(result.is_identity());
}

#[test]
fn test_g2_affine_neg() {
    let gen = G2Point::generator();
    let affine = gen.to_affine();
    let neg_affine = affine.neg();
    assert_eq!(neg_affine.x, affine.x);
}

#[test]
fn test_gt_element_identity() {
    let id = GTElement::identity();
    assert!(id.is_identity());
}

#[test]
fn test_gt_element_one() {
    let one = GTElement::one();
    assert!(one.is_identity());
}

#[test]
fn test_gt_element_equals() {
    let a = GTElement::identity();
    let b = GTElement::one();
    assert!(a.equals(&b));
}

#[test]
fn test_pairing_infinity_g1() {
    let inf = G1Point::infinity();
    let gen = G2Point::generator();
    let result = Pairing::compute(&inf, &gen);
    assert!(result.is_identity());
}

#[test]
fn test_pairing_infinity_g2() {
    let gen = G1Point::generator();
    let inf = G2Point::infinity();
    let result = Pairing::compute(&gen, &inf);
    assert!(result.is_identity());
}

#[test]
fn test_pairing_both_infinity() {
    let inf1 = G1Point::infinity();
    let inf2 = G2Point::infinity();
    let result = Pairing::compute(&inf1, &inf2);
    assert!(result.is_identity());
}

#[test]
fn test_pairing_generators() {
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let result = Pairing::compute(&g1, &g2);
    assert!(!result.is_identity());
}

#[test]
fn test_pairing_multi_empty() {
    let pairs: Vec<(G1Point, G2Point)> = vec![];
    let result = Pairing::multi_pairing(&pairs);
    assert!(result.is_identity());
}

#[test]
fn test_variable_one() {
    let one = Variable::ONE;
    assert_eq!(one.index(), 0);
}

#[test]
fn test_variable_new() {
    let v = Variable::new(5);
    assert_eq!(v.index(), 6);
}

#[test]
fn test_variable_ordering() {
    let v1 = Variable::new(1);
    let v2 = Variable::new(2);
    assert!(v1 < v2);
}

#[test]
fn test_linear_combination_new() {
    let lc = LinearCombination::new();
    assert!(lc.terms.is_empty());
}

#[test]
fn test_linear_combination_from_variable() {
    let v = Variable::new(3);
    let lc = LinearCombination::from_variable(v);
    assert_eq!(lc.terms.len(), 1);
    assert!(lc.terms.contains_key(&v));
}

#[test]
fn test_linear_combination_from_constant() {
    let c = FieldElement::from_u64(10);
    let lc = LinearCombination::from_constant(c);
    assert_eq!(lc.terms.len(), 1);
    assert!(lc.terms.contains_key(&Variable::ONE));
}

#[test]
fn test_linear_combination_from_constant_zero() {
    let zero = FieldElement::zero();
    let lc = LinearCombination::from_constant(zero);
    assert!(lc.terms.is_empty());
}

#[test]
fn test_linear_combination_add_term() {
    let mut lc = LinearCombination::new();
    let v = Variable::new(0);
    lc.add_term(v, FieldElement::from_u64(5));
    assert_eq!(lc.terms.len(), 1);
}

#[test]
fn test_linear_combination_add_term_zero_coefficient() {
    let mut lc = LinearCombination::new();
    let v = Variable::new(0);
    lc.add_term(v, FieldElement::zero());
    assert!(lc.terms.is_empty());
}

#[test]
fn test_linear_combination_add_term_cancellation() {
    let mut lc = LinearCombination::new();
    let v = Variable::new(0);
    let c = FieldElement::from_u64(5);
    lc.add_term(v, c);
    lc.add_term(v, c.neg());
    assert!(lc.terms.is_empty());
}

#[test]
fn test_linear_combination_scale() {
    let mut lc = LinearCombination::from_variable(Variable::new(0));
    lc.scale(&FieldElement::from_u64(3));
    assert_eq!(lc.terms.len(), 1);
}

#[test]
fn test_linear_combination_scale_zero() {
    let mut lc = LinearCombination::from_variable(Variable::new(0));
    lc.scale(&FieldElement::zero());
    assert!(lc.terms.is_empty());
}

#[test]
fn test_linear_combination_add() {
    let mut lc1 = LinearCombination::from_variable(Variable::new(0));
    let lc2 = LinearCombination::from_variable(Variable::new(1));
    lc1.add(&lc2);
    assert_eq!(lc1.terms.len(), 2);
}

#[test]
fn test_linear_combination_evaluate_constant() {
    let lc = LinearCombination::from_constant(FieldElement::from_u64(42));
    let result = lc.evaluate(&[]).unwrap();
    assert!(result.equals(&FieldElement::from_u64(42)));
}

#[test]
fn test_linear_combination_evaluate_variable() {
    let v = Variable::new(0);
    let lc = LinearCombination::from_variable(v);
    let assignment = vec![FieldElement::from_u64(10)];
    let result = lc.evaluate(&assignment).unwrap();
    assert!(result.equals(&FieldElement::from_u64(10)));
}

#[test]
fn test_linear_combination_evaluate_out_of_bounds() {
    let v = Variable::new(100);
    let lc = LinearCombination::from_variable(v);
    let assignment = vec![FieldElement::from_u64(10)];
    assert!(lc.evaluate(&assignment).is_err());
}

#[test]
fn test_constraint_new() {
    let a = LinearCombination::new();
    let b = LinearCombination::new();
    let c = LinearCombination::new();
    let constraint = Constraint::new(a, b, c);
    assert!(constraint.a.terms.is_empty());
}

#[test]
fn test_constraint_enforce_equal() {
    let left = LinearCombination::from_variable(Variable::new(0));
    let right = LinearCombination::from_variable(Variable::new(1));
    let constraint = Constraint::enforce_equal(left, right);
    assert!(!constraint.a.terms.is_empty());
}

#[test]
fn test_constraint_enforce_multiplication() {
    let a = Variable::new(0);
    let b = Variable::new(1);
    let c = Variable::new(2);
    let constraint = Constraint::enforce_multiplication(a, b, c);
    assert!(!constraint.a.terms.is_empty());
    assert!(!constraint.b.terms.is_empty());
    assert!(!constraint.c.terms.is_empty());
}

#[test]
fn test_constraint_default_multiplication() {
    let constraint = Constraint::default_multiplication(0);
    assert!(!constraint.a.terms.is_empty());
}

#[test]
fn test_constraint_verify_valid() {
    let a = Variable::new(0);
    let b = Variable::new(1);
    let c = Variable::new(2);
    let constraint = Constraint::enforce_multiplication(a, b, c);
    let two = FieldElement::from_u64(2);
    let three = FieldElement::from_u64(3);
    let six = FieldElement::from_u64(6);
    let assignment = vec![two, three, six];
    let result = constraint.verify(&assignment).unwrap();
    assert!(result);
}

#[test]
fn test_constraint_verify_invalid() {
    let a = Variable::new(0);
    let b = Variable::new(1);
    let c = Variable::new(2);
    let constraint = Constraint::enforce_multiplication(a, b, c);
    let two = FieldElement::from_u64(2);
    let three = FieldElement::from_u64(3);
    let seven = FieldElement::from_u64(7);
    let assignment = vec![two, three, seven];
    let result = constraint.verify(&assignment).unwrap();
    assert!(!result);
}

#[test]
fn test_circuit_new() {
    let circuit = Circuit::new();
    assert!(circuit.constraints.is_empty());
    assert_eq!(circuit.num_variables, 0);
    assert_eq!(circuit.num_inputs, 0);
}

#[test]
fn test_circuit_with_params() {
    let constraints = vec![Constraint::default_multiplication(0)];
    let circuit = Circuit::with_params(constraints, 3, 2);
    assert_eq!(circuit.constraints.len(), 1);
    assert_eq!(circuit.num_variables, 3);
    assert_eq!(circuit.num_inputs, 2);
}

#[test]
fn test_circuit_get_matrices() {
    let constraints = vec![Constraint::default_multiplication(0)];
    let circuit = Circuit::with_params(constraints, 3, 0);
    let (a, b, c) = circuit.get_matrices();
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(c.len(), 1);
}

#[test]
fn test_circuit_verify_assignment_empty() {
    let circuit = Circuit::new();
    let result = circuit.verify_assignment(&[]).unwrap();
    assert!(result);
}

#[test]
fn test_circuit_verify_assignment_wrong_length() {
    let circuit = Circuit::with_params(vec![], 3, 0);
    let result = circuit.verify_assignment(&[]);
    assert!(result.is_err());
}

#[test]
fn test_circuit_builder_new() {
    let builder = CircuitBuilder::new();
    assert!(builder.constraints.is_empty());
    assert_eq!(builder.num_variables, 0);
    assert_eq!(builder.num_inputs, 0);
}

#[test]
fn test_circuit_builder_alloc_variable() {
    let mut builder = CircuitBuilder::new();
    let v = builder.alloc_variable(Some("test"));
    assert_eq!(builder.num_variables, 1);
    assert!(builder.variable_names.contains_key(&v));
}

#[test]
fn test_circuit_builder_alloc_variable_no_name() {
    let mut builder = CircuitBuilder::new();
    let _v = builder.alloc_variable(None);
    assert_eq!(builder.num_variables, 1);
    assert!(builder.variable_names.is_empty());
}

#[test]
fn test_circuit_builder_alloc_input() {
    let mut builder = CircuitBuilder::new();
    let _v = builder.alloc_input(Some("input"));
    assert_eq!(builder.num_variables, 1);
    assert_eq!(builder.num_inputs, 1);
}

#[test]
fn test_circuit_builder_enforce_constraint() {
    let mut builder = CircuitBuilder::new();
    let constraint = Constraint::default_multiplication(0);
    builder.enforce_constraint(constraint);
    assert_eq!(builder.constraints.len(), 1);
}

#[test]
fn test_circuit_builder_enforce_equal() {
    let mut builder = CircuitBuilder::new();
    let v1 = builder.alloc_variable(None);
    let v2 = builder.alloc_variable(None);
    builder.enforce_equal(
        LinearCombination::from_variable(v1),
        LinearCombination::from_variable(v2),
    );
    assert_eq!(builder.constraints.len(), 1);
}

#[test]
fn test_circuit_builder_enforce_multiplication() {
    let mut builder = CircuitBuilder::new();
    let a = builder.alloc_variable(None);
    let b = builder.alloc_variable(None);
    let c = builder.alloc_variable(None);
    builder.enforce_multiplication(a, b, c);
    assert_eq!(builder.constraints.len(), 1);
}

#[test]
fn test_circuit_builder_add_boolean_constraint() {
    let mut builder = CircuitBuilder::new();
    let v = builder.alloc_variable(None);
    builder.add_boolean_constraint(v);
    assert_eq!(builder.constraints.len(), 1);
}

#[test]
fn test_circuit_builder_add_range_constraint() {
    let mut builder = CircuitBuilder::new();
    let v = builder.alloc_input(None);
    builder.add_range_constraint(v, 4);
    assert!(builder.constraints.len() > 0);
}

#[test]
fn test_circuit_builder_build() {
    let mut builder = CircuitBuilder::new();
    let _x = builder.alloc_input(None);
    let _y = builder.alloc_input(None);
    let circuit = builder.build(1).unwrap();
    assert_eq!(circuit.num_inputs, 2);
}

#[test]
fn test_circuit_builder_add_constraint() {
    let mut builder = CircuitBuilder::new();
    let constraint = Constraint::default_multiplication(0);
    let result = builder.add_constraint(constraint);
    assert!(result.is_ok());
    assert_eq!(builder.constraints.len(), 1);
}

#[test]
fn test_circuit_optimizer_optimize_empty() {
    let circuit = Circuit::new();
    let optimized = CircuitOptimizer::optimize(circuit);
    assert!(optimized.constraints.is_empty());
}

#[test]
fn test_circuit_optimizer_removes_trivial() {
    let trivial = Constraint::new(
        LinearCombination::new(),
        LinearCombination::new(),
        LinearCombination::new(),
    );
    let circuit = Circuit::with_params(vec![trivial], 0, 0);
    let optimized = CircuitOptimizer::optimize(circuit);
    assert!(optimized.constraints.is_empty());
}

#[test]
fn test_circuit_optimizer_keeps_nontrivial() {
    let nontrivial = Constraint::default_multiplication(0);
    let circuit = Circuit::with_params(vec![nontrivial], 3, 0);
    let optimized = CircuitOptimizer::optimize(circuit);
    assert_eq!(optimized.constraints.len(), 1);
}

#[test]
fn test_multiplication_circuit() {
    let circuit = multiplication_circuit().unwrap();
    assert_eq!(circuit.num_inputs, 2);
    assert!(circuit.constraints.len() > 0);
}

#[test]
fn test_hash_preimage_circuit() {
    let circuit = hash_preimage_circuit().unwrap();
    assert_eq!(circuit.num_inputs, 2);
}

#[test]
fn test_range_proof_circuit() {
    let circuit = range_proof_circuit(8).unwrap();
    assert_eq!(circuit.num_inputs, 1);
}

#[test]
fn test_range_proof_circuit_zero_bits() {
    let circuit = range_proof_circuit(0).unwrap();
    assert_eq!(circuit.num_inputs, 1);
}

#[test]
fn test_proof_new() {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 42);
    assert_eq!(proof.circuit_id, 42);
}

#[test]
fn test_proof_serialize_deserialize() {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 123);
    let serialized = proof.serialize();
    let deserialized = Proof::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.circuit_id, 123);
}

#[test]
fn test_proof_deserialize_too_short() {
    let short = [0u8; 64];
    assert!(Proof::deserialize(&short).is_err());
}

#[test]
fn test_proof_is_valid_structure_valid() {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 1);
    assert!(proof.is_valid_structure());
}

#[test]
fn test_proof_is_valid_structure_invalid_a() {
    let a = G1Point::infinity();
    let b = G2Point::generator();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 1);
    assert!(!proof.is_valid_structure());
}

#[test]
fn test_proof_is_valid_structure_invalid_b() {
    let a = G1Point::generator();
    let b = G2Point::infinity();
    let c = G1Point::generator();
    let proof = Proof::new(a, b, c, 1);
    assert!(!proof.is_valid_structure());
}

#[test]
fn test_proof_is_valid_structure_invalid_c() {
    let a = G1Point::generator();
    let b = G2Point::generator();
    let c = G1Point::infinity();
    let proof = Proof::new(a, b, c, 1);
    assert!(!proof.is_valid_structure());
}

#[test]
fn test_verifying_key_verify_key_valid() {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    assert!(vk.verify_key().unwrap());
}

#[test]
fn test_verifying_key_verify_key_invalid_alpha() {
    let vk = VerifyingKey {
        alpha_g1: G1Point::infinity(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    assert!(!vk.verify_key().unwrap());
}

#[test]
fn test_verifying_key_verify_key_invalid_beta() {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::infinity(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    assert!(!vk.verify_key().unwrap());
}

#[test]
fn test_verifying_key_verify_key_empty_ic() {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![],
    };
    assert!(!vk.verify_key().unwrap());
}

#[test]
fn test_verification_cache_new() {
    let cache = VerificationCache::new();
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_verification_cache_insert_get() {
    let cache = VerificationCache::new();
    let key = [1u8; 32];
    cache.insert(key, true);
    assert_eq!(cache.get(&key), Some(true));
}

#[test]
fn test_verification_cache_get_missing() {
    let cache = VerificationCache::new();
    let key = [1u8; 32];
    assert_eq!(cache.get(&key), None);
}

#[test]
fn test_verification_cache_len() {
    let cache = VerificationCache::new();
    cache.insert([1u8; 32], true);
    cache.insert([2u8; 32], false);
    assert_eq!(cache.len(), 2);
}

#[test]
fn test_verification_cache_clear() {
    let cache = VerificationCache::new();
    cache.insert([1u8; 32], true);
    cache.clear();
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_verification_cache_evict_oldest() {
    let cache = VerificationCache::new();
    for i in 0..10u8 {
        cache.insert([i; 32], true);
    }
    cache.evict_oldest(5);
    assert_eq!(cache.len(), 5);
}

#[test]
fn test_compute_cache_key_deterministic() {
    let circuit_id = 42u32;
    let proof_hash = [0xABu8; 32];
    let public_inputs: Vec<Vec<u8>> = vec![vec![1, 2, 3]];
    let key1 = compute_cache_key(circuit_id, &proof_hash, &public_inputs);
    let key2 = compute_cache_key(circuit_id, &proof_hash, &public_inputs);
    assert_eq!(key1, key2);
}

#[test]
fn test_compute_cache_key_different_circuit_id() {
    let proof_hash = [0xABu8; 32];
    let public_inputs: Vec<Vec<u8>> = vec![];
    let key1 = compute_cache_key(1, &proof_hash, &public_inputs);
    let key2 = compute_cache_key(2, &proof_hash, &public_inputs);
    assert_ne!(key1, key2);
}

#[test]
fn test_verification_result_success() {
    let result = VerificationResult::success(100);
    assert!(result.valid);
    assert!(result.error.is_none());
    assert_eq!(result.timing_ms, 100);
    assert_eq!(result.pairing_checks, 4);
}

#[test]
fn test_verification_result_failure() {
    let result = VerificationResult::failure(ZKError::VerificationFailed, 50);
    assert!(!result.valid);
    assert!(result.error.is_some());
    assert_eq!(result.timing_ms, 50);
    assert_eq!(result.pairing_checks, 0);
}

#[test]
fn test_verification_stats_default() {
    let stats = VerificationStats::default();
    assert_eq!(stats.total_verifications, 0);
    assert_eq!(stats.successful_verifications, 0);
    assert_eq!(stats.failed_verifications, 0);
    assert_eq!(stats.avg_verification_time_ms, 0);
}

#[test]
fn test_verification_key_manager_new() {
    let manager = VerificationKeyManager::new();
    assert_eq!(manager.key_count(), 0);
}

#[test]
fn test_verification_key_manager_add_key() {
    let mut manager = VerificationKeyManager::new();
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    assert!(manager.add_key(1, vk).is_ok());
    assert_eq!(manager.key_count(), 1);
}

#[test]
fn test_verification_key_manager_get_key() {
    let mut manager = VerificationKeyManager::new();
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator()],
    };
    manager.add_key(42, vk).unwrap();
    assert!(manager.get_key(42).is_some());
    assert!(manager.get_key(99).is_none());
}

#[test]
fn test_verification_key_manager_remove_key() {
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
    assert!(removed.is_some());
    assert_eq!(manager.key_count(), 0);
}

#[test]
fn test_verification_key_manager_list_circuits() {
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
    assert_eq!(circuits.len(), 2);
    assert!(circuits.contains(&1));
    assert!(circuits.contains(&2));
}

#[test]
fn test_merkle_verifier_verify_membership_single() {
    let leaf = [1u8; 32];
    let root = leaf;
    let proof: &[[u8; 32]] = &[];
    assert!(MerkleVerifier::verify_membership(&root, &leaf, proof, 0));
}

#[test]
fn test_merkle_verifier_verify_membership_mismatch() {
    let leaf = [1u8; 32];
    let root = [2u8; 32];
    let proof: &[[u8; 32]] = &[];
    assert!(!MerkleVerifier::verify_membership(&root, &leaf, proof, 0));
}

#[test]
fn test_merkle_verifier_verify_membership_too_long_proof() {
    let leaf = [1u8; 32];
    let root = leaf;
    let proof: Vec<[u8; 32]> = (0..65).map(|_| [0u8; 32]).collect();
    assert!(!MerkleVerifier::verify_membership(&root, &leaf, &proof, 0));
}

#[test]
fn test_range_proof_verifier_invalid_range() {
    let commitment = [0u8; 32];
    let proof = [0u8; 256];
    assert!(!RangeProofVerifier::verify(&commitment, &proof, 100, 50));
}

#[test]
fn test_range_proof_verifier_verify_simple_invalid_bit_length_zero() {
    let commitment = [0u8; 32];
    let proof = [0u8; 256];
    assert!(!RangeProofVerifier::verify_simple(&commitment, &proof, 0));
}

#[test]
fn test_range_proof_verifier_verify_simple_invalid_bit_length_too_large() {
    let commitment = [0u8; 32];
    let proof = [0u8; 256];
    assert!(!RangeProofVerifier::verify_simple(&commitment, &proof, 65));
}

#[test]
fn test_syscall_constants() {
    assert_eq!(SYS_ZK_PROVE, 400);
    assert_eq!(SYS_ZK_VERIFY, 401);
    assert_eq!(SYS_ZK_COMPILE_CIRCUIT, 402);
    assert_eq!(SYS_ZK_GET_STATS, 403);
}

#[test]
fn test_syscall_limits() {
    assert!(MAX_WITNESS_SIZE > 0);
    assert!(MAX_PROOF_SIZE > 0);
    assert!(MAX_PUBLIC_INPUTS > 0);
    assert!(MAX_CONSTRAINTS > 0);
}

#[test]
fn test_deserialize_constraints_empty() {
    let data: &[u8] = &[];
    let result = deserialize_constraints(data).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_deserialize_constraints_invalid_length() {
    let data = [0u8; 63];
    assert!(deserialize_constraints(&data).is_err());
}

#[test]
fn test_deserialize_constraints_valid() {
    let data = [0u8; 128];
    let result = deserialize_constraints(&data).unwrap();
    assert_eq!(result.len(), 2);
}

#[test]
fn test_deserialize_witness_too_short() {
    let data = [0u8; 2];
    assert!(deserialize_witness(&data).is_err());
}

#[test]
fn test_deserialize_witness_empty() {
    let data = [0u8, 0, 0, 0];
    let result = deserialize_witness(&data).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_deserialize_witness_truncated() {
    let mut data = vec![1u8, 0, 0, 0];
    data.extend_from_slice(&[10u8, 0, 0, 0]);
    assert!(deserialize_witness(&data).is_err());
}

#[test]
fn test_deserialize_witness_valid() {
    let mut data = vec![1u8, 0, 0, 0];
    data.extend_from_slice(&[4u8, 0, 0, 0]);
    data.extend_from_slice(&[1, 2, 3, 4]);
    let result = deserialize_witness(&data).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], vec![1, 2, 3, 4]);
}

#[test]
fn test_deserialize_public_inputs() {
    let mut data = vec![1u8, 0, 0, 0];
    data.extend_from_slice(&[2u8, 0, 0, 0]);
    data.extend_from_slice(&[0xAB, 0xCD]);
    let result = deserialize_public_inputs(&data).unwrap();
    assert_eq!(result.len(), 1);
}

#[test]
fn test_kernel_measurement_new() {
    let measurement = KernelMeasurement::new();
    assert_eq!(measurement.code_hash, [0u8; 32]);
    assert_eq!(measurement.data_hash, [0u8; 32]);
    assert_eq!(measurement.config_hash, [0u8; 32]);
    assert!(measurement.module_hashes.is_empty());
}

#[test]
fn test_kernel_measurement_compute_integrity_hash() {
    let measurement = KernelMeasurement::new();
    let hash = measurement.compute_integrity_hash();
    assert_ne!(hash, [0u8; 32]);
}

#[test]
fn test_kernel_measurement_compute_integrity_hash_deterministic() {
    let measurement = KernelMeasurement::new();
    let hash1 = measurement.compute_integrity_hash();
    let hash2 = measurement.compute_integrity_hash();
    assert_eq!(hash1, hash2);
}

#[test]
fn test_memory_layout_default() {
    let layout = MemoryLayout::default();
    assert_eq!(layout.kernel_start.as_u64(), 0);
    assert_eq!(layout.kernel_end.as_u64(), 0);
    assert_eq!(layout.user_start.as_u64(), 0);
    assert_eq!(layout.user_end.as_u64(), 0);
    assert_eq!(layout.heap_start.as_u64(), 0);
    assert_eq!(layout.heap_end.as_u64(), 0);
}

#[test]
fn test_zk_config_default() {
    let config = ZKConfig::default();
    assert_eq!(config.max_constraints, 1_000_000);
    assert_eq!(config.max_witnesses, 100_000);
    assert!(config.enable_preprocessing);
    assert!(config.enable_verification_cache);
    assert!(config.trusted_setup_path.is_none());
}

#[test]
fn test_zk_error_variants() {
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
    assert_eq!(errors.len(), 16);
}

#[test]
fn test_zk_prove_params_size() {
    assert!(core::mem::size_of::<ZKProveParams>() > 0);
}

#[test]
fn test_zk_verify_params_size() {
    assert!(core::mem::size_of::<ZKVerifyParams>() > 0);
}

#[test]
fn test_zk_compile_params_size() {
    assert!(core::mem::size_of::<ZKCompileParams>() > 0);
}

#[test]
fn test_zk_stats_userspace_size() {
    assert!(core::mem::size_of::<ZKStatsUserspace>() > 0);
}

#[test]
fn test_g2_field_element_frobenius_coefficients() {
    let _ = G2FieldElement::frobenius_coeff_x_1();
    let _ = G2FieldElement::frobenius_coeff_x_2();
    let _ = G2FieldElement::frobenius_coeff_y_1();
    let _ = G2FieldElement::frobenius_coeff_y_2();
    let _ = G2FieldElement::frobenius_coeff_fp12();
    let _ = G2FieldElement::frobenius_coeff_fp12_sq();
    let _ = G2FieldElement::frobenius_coeff_fp12_cub();
}

#[test]
fn test_bn254_modulus_nonzero() {
    assert!(BN254_MODULUS.iter().any(|&x| x != 0));
}

#[test]
fn test_montgomery_r_nonzero() {
    assert!(MONTGOMERY_R.iter().any(|&x| x != 0));
}

#[test]
fn test_montgomery_r2_nonzero() {
    assert!(MONTGOMERY_R2.iter().any(|&x| x != 0));
}

#[test]
fn test_montgomery_inv_nonzero() {
    assert_ne!(MONTGOMERY_INV, 0);
}

#[test]
fn test_field_element_from_limbs() {
    let limbs = [1u64, 2, 3, 4];
    let fe = FieldElement::from_limbs(limbs);
    assert_eq!(fe.limbs, limbs);
}

#[test]
fn test_range_proof_structure() {
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
    assert_eq!(proof.bit_length, 64);
}

#[test]
fn test_g1_point_from_affine() {
    let x = FieldElement::from_u64(1);
    let y = FieldElement::from_u64(2);
    let point = G1Point::from_affine(x, y);
    assert!(!point.is_infinity());
}

#[test]
fn test_variable_equality() {
    let v1 = Variable::new(5);
    let v2 = Variable::new(5);
    assert_eq!(v1, v2);
}

#[test]
fn test_variable_copy() {
    let v1 = Variable::new(3);
    let v2 = v1;
    assert_eq!(v1, v2);
}

#[test]
fn test_circuit_clone() {
    let circuit = Circuit::new();
    let cloned = circuit.clone();
    assert_eq!(circuit.num_variables, cloned.num_variables);
}

#[test]
fn test_constraint_clone() {
    let constraint = Constraint::default_multiplication(0);
    let cloned = constraint.clone();
    assert_eq!(constraint.a.terms.len(), cloned.a.terms.len());
}

#[test]
fn test_linear_combination_clone() {
    let lc = LinearCombination::from_variable(Variable::new(0));
    let cloned = lc.clone();
    assert_eq!(lc.terms.len(), cloned.terms.len());
}

#[test]
fn test_proof_clone() {
    let proof = Proof::new(
        G1Point::generator(),
        G2Point::generator(),
        G1Point::generator(),
        1,
    );
    let cloned = proof.clone();
    assert_eq!(proof.circuit_id, cloned.circuit_id);
}

#[test]
fn test_g1_point_copy() {
    let p1 = G1Point::generator();
    let p2 = p1;
    assert!(!p2.is_infinity());
}

#[test]
fn test_g2_point_copy() {
    let p1 = G2Point::generator();
    let p2 = p1;
    assert!(!p2.is_infinity());
}

#[test]
fn test_field_element_copy() {
    let f1 = FieldElement::from_u64(42);
    let f2 = f1;
    assert!(f1.equals(&f2));
}

#[test]
fn test_g2_field_element_copy() {
    let f1 = G2FieldElement::one();
    let f2 = f1;
    assert_eq!(f1, f2);
}

#[test]
fn test_gt_element_copy() {
    let g1 = GTElement::identity();
    let g2 = g1;
    assert!(g1.equals(&g2));
}

#[test]
fn test_verification_cache_default() {
    let cache = VerificationCache::default();
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_field_element_sub_assign() {
    let mut a = [10u64, 0, 0, 0];
    let b = [3u64, 0, 0, 0];
    FieldElement::sub_assign(&mut a, &b);
    assert_eq!(a[0], 7);
}

#[test]
fn test_field_element_add_assign() {
    let mut a = [10u64, 0, 0, 0];
    let b = [3u64, 0, 0, 0];
    FieldElement::add_assign(&mut a, &b);
    assert_eq!(a[0], 13);
}

#[test]
fn test_g1_point_neg_vs_negate() {
    let gen = G1Point::generator();
    let neg1 = gen.neg();
    let neg2 = gen.negate();
    let coords1 = neg1.to_affine_coords();
    let coords2 = neg2.to_affine_coords();
    if let (Some((x1, y1)), Some((x2, y2))) = (coords1, coords2) {
        assert!(x1.equals(&x2));
        assert!(y1.equals(&y2));
    }
}

#[test]
fn test_groth16_verifier_new() {
    let vk = VerifyingKey {
        alpha_g1: G1Point::generator(),
        beta_g2: G2Point::generator(),
        gamma_g2: G2Point::generator(),
        delta_g2: G2Point::generator(),
        ic: vec![G1Point::generator(), G1Point::generator()],
    };
    let verifier = Groth16Verifier::new(vk);
    assert!(verifier.verifying_key.verify_key().unwrap());
}

#[test]
fn test_kernel_measurement_clone() {
    let measurement = KernelMeasurement::new();
    let cloned = measurement.clone();
    assert_eq!(measurement.code_hash, cloned.code_hash);
}

#[test]
fn test_zk_config_clone() {
    let config = ZKConfig::default();
    let cloned = config.clone();
    assert_eq!(config.max_constraints, cloned.max_constraints);
}

#[test]
fn test_zk_error_clone() {
    let error = ZKError::InvalidCircuit;
    let cloned = error.clone();
    match cloned {
        ZKError::InvalidCircuit => {}
        _ => panic!("Clone produced different variant"),
    }
}

#[test]
fn test_linear_combination_multiple_terms() {
    let mut lc = LinearCombination::new();
    let v1 = Variable::new(0);
    let v2 = Variable::new(1);
    let v3 = Variable::new(2);
    lc.add_term(v1, FieldElement::from_u64(1));
    lc.add_term(v2, FieldElement::from_u64(2));
    lc.add_term(v3, FieldElement::from_u64(3));
    assert_eq!(lc.terms.len(), 3);
}

#[test]
fn test_circuit_compute_witness_map_wrong_inputs() {
    let mut builder = CircuitBuilder::new();
    let _x = builder.alloc_input(None);
    let _y = builder.alloc_input(None);
    let circuit = builder.build(0).unwrap();
    let result = circuit.compute_witness_map(&[FieldElement::from_u64(1)]);
    assert!(result.is_err());
}

#[test]
fn test_g2_field_element_mul_complex() {
    let a = G2FieldElement {
        c0: FieldElement::from_u64(3),
        c1: FieldElement::from_u64(4),
    };
    let b = G2FieldElement {
        c0: FieldElement::from_u64(1),
        c1: FieldElement::from_u64(2),
    };
    let c = a.mul(&b);
    assert!(!c.is_zero());
}

#[test]
fn test_fp6_element_zero() {
    let zero = Fp6Element::ZERO;
    assert!(zero.c0.is_zero());
    assert!(zero.c1.is_zero());
    assert!(zero.c2.is_zero());
}

#[test]
fn test_fp6_element_one() {
    let one = Fp6Element::ONE;
    assert!(!one.c0.is_zero());
}

#[test]
fn test_pairing_bilinearity_property() {
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let e_g1_g2 = Pairing::compute(&g1, &g2);
    let g1_2 = g1.double();
    let e_2g1_g2 = Pairing::compute(&g1_2, &g2);
    let e_g1_g2_squared = e_g1_g2.mul(&e_g1_g2);
    assert!(e_2g1_g2.equals(&e_g1_g2_squared));
}

#[test]
fn test_module_hash_structure() {
    let mh = ModuleHash {
        name: String::from("test_module"),
        hash: [0xABu8; 32],
        address: VirtAddr::new(0x1000),
        size: 4096,
    };
    assert_eq!(mh.name, "test_module");
    assert_eq!(mh.hash[0], 0xAB);
    assert_eq!(mh.address.as_u64(), 0x1000);
    assert_eq!(mh.size, 4096);
}

#[test]
fn test_kernel_measurement_with_modules() {
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
    assert_ne!(hash1, hash2);
}

#[test]
fn test_field_element_distributive() {
    let a = FieldElement::from_u64(2);
    let b = FieldElement::from_u64(3);
    let c = FieldElement::from_u64(4);
    let left = a.mul(&b.add(&c));
    let right = a.mul(&b).add(&a.mul(&c));
    assert!(left.equals(&right));
}

#[test]
fn test_field_element_associative_add() {
    let a = FieldElement::from_u64(1);
    let b = FieldElement::from_u64(2);
    let c = FieldElement::from_u64(3);
    let left = a.add(&b).add(&c);
    let right = a.add(&b.add(&c));
    assert!(left.equals(&right));
}

#[test]
fn test_field_element_associative_mul() {
    let a = FieldElement::from_u64(2);
    let b = FieldElement::from_u64(3);
    let c = FieldElement::from_u64(4);
    let left = a.mul(&b).mul(&c);
    let right = a.mul(&b.mul(&c));
    assert!(left.equals(&right));
}

#[test]
fn test_g1_point_associative_add() {
    let p = G1Point::generator();
    let q = p.double();
    let r = q.double();
    let left = p.add(&q).add(&r);
    let right = p.add(&q.add(&r));
    let left_coords = left.to_affine_coords();
    let right_coords = right.to_affine_coords();
    if let (Some((lx, ly)), Some((rx, ry))) = (left_coords, right_coords) {
        assert!(lx.equals(&rx));
        assert!(ly.equals(&ry));
    }
}

#[test]
fn test_g2_point_associative_add() {
    let p = G2Point::generator();
    let q = p.double();
    let r = q.double();
    let left = p.add(&q).add(&r);
    let right = p.add(&q.add(&r));
    assert!(!left.is_infinity());
    assert!(!right.is_infinity());
}
