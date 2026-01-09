// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::*;

fn scalar_pow(base: &Scalar, exp: &[u64; 4]) -> Scalar {
    let mut result = Scalar::ONE;
    let mut b = *base;
    for &limb in exp.iter() {
        for bit in 0..64 {
            if (limb >> bit) & 1 == 1 {
                result = result.mul(&b);
            }
            b = b.mul(&b);
        }
    }
    result
}

#[test]
fn test_keypair_generation() {
    let (sk, pk) = generate_keypair();
    assert!(sk.iter().any(|&b| b != 0));
    assert_eq!(pk[0], 0x04);
}

#[test]
fn test_sign_verify() {
    let sk: SecretKey = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let pk = public_key_from_secret(&sk);
    let message = b"test message";
    let sig = sign_message(&sk, message).expect("signing failed");
    assert!(verify_message(&pk, message, &sig), "Verification failed");
}

#[test]
fn test_ecdsa_deterministic() {
    let d = Scalar([7, 0, 0, 0]);

    let g = AffinePoint::generator().to_projective();
    let q = g.mul(&d).to_affine();
    assert!(!q.infinity, "Q should not be infinity");

    let k = Scalar([3, 0, 0, 0]);

    let r_point_proj = g.mul(&k);
    let r_point = r_point_proj.to_affine();
    assert!(!r_point.infinity, "R should not be infinity");

    let g_aff = AffinePoint::generator();
    let g_proj = g_aff.to_projective();
    let two_g = g_proj.double();
    let three_g = two_g.add(&g_proj);
    let three_g_aff = three_g.to_affine();

    assert_eq!(r_point.x.0, three_g_aff.x.0,
        "3*G via mul should match 3*G via double+add\nmul: {:?}\nadd: {:?}",
        r_point.x.0, three_g_aff.x.0);
}

#[test]
fn test_point_double() {
    let g = AffinePoint::generator().to_projective();

    let two_g = g.double().to_affine();
    assert!(!two_g.infinity, "2*G should not be infinity");

    let two_g_add = g.add(&g).to_affine();
    assert_eq!(two_g.x.0, two_g_add.x.0, "2*G via double should match G+G");
    assert_eq!(two_g.y.0, two_g_add.y.0, "2*G via double should match G+G");

    let three_g = two_g.to_projective().add(&g).to_affine();
    assert!(!three_g.infinity, "3*G should not be infinity");

    let k = Scalar([3, 0, 0, 0]);
    let three_g_mul = g.mul(&k).to_affine();
    assert_eq!(three_g.x.0, three_g_mul.x.0,
        "3*G via add should match 3*G via scalar mul\nadd: {:?}\nmul: {:?}",
        three_g.x.0, three_g_mul.x.0);
}

#[test]
fn test_scalar_mul_2() {
    let g = AffinePoint::generator().to_projective();

    let two_scalar = Scalar([2, 0, 0, 0]);
    let two_g_mul = g.mul(&two_scalar).to_affine();

    let two_g_double = g.double().to_affine();

    assert_eq!(two_g_mul.x.0, two_g_double.x.0,
        "2*G via scalar mul should match 2*G via double\nmul: {:?}\ndouble: {:?}",
        two_g_mul.x.0, two_g_double.x.0);
}

#[test]
fn test_point_add_order() {
    let g = AffinePoint::generator().to_projective();
    let two_g = g.double();

    let g_aff = g.to_affine();
    let _two_g_aff = two_g.to_affine();

    assert_eq!(g_aff.x.0, AffinePoint::generator().x.0, "G should match generator");

    let g_plus_2g = g.add(&two_g).to_affine();
    let two_g_plus_g = two_g.add(&g).to_affine();

    assert_eq!(g_plus_2g.x.0, two_g_plus_g.x.0,
        "G + 2G should equal 2G + G (commutativity)\nG + 2G: {:?}\n2G + G: {:?}",
        g_plus_2g.x.0, two_g_plus_g.x.0);
}

#[test]
fn test_projective_to_affine() {
    let g = AffinePoint::generator();
    let g_proj = g.to_projective();
    let g_back = g_proj.to_affine();

    assert_eq!(g.x.0, g_back.x.0, "x should be preserved");
    assert_eq!(g.y.0, g_back.y.0, "y should be preserved");

    let two_g = g_proj.double();
    let two_g_aff = two_g.to_affine();

    let two_g_proj = two_g_aff.to_projective();
    let two_g_back = two_g_proj.to_affine();

    assert_eq!(two_g_aff.x.0, two_g_back.x.0, "2G x should be preserved");
    assert_eq!(two_g_aff.y.0, two_g_back.y.0, "2G y should be preserved");
}

#[test]
fn test_scalar_squaring() {
    let a = Scalar([7, 0, 0, 0]);
    let a_sq = a.mul(&a);
    assert_eq!(a_sq.0, [49, 0, 0, 0], "7^2 should be 49");

    let b = Scalar([10, 0, 0, 0]);
    let b_sq = b.mul(&b);
    assert_eq!(b_sq.0, [100, 0, 0, 0], "10^2 should be 100");
}

#[test]
fn test_scalar_large_mul() {
    let a = Scalar([0, 1, 0, 0]);
    let b = a.mul(&a);
    assert_eq!(b.0, [0, 0, 1, 0], "2^64 * 2^64 should be 2^128");

    let c = Scalar([0, 0, 1, 0]);
    let d = c.mul(&c);
    let expected = [0x0C46353D039CDAAF, 0x4319055258E8617B, 0x0000000000000000, 0x00000000FFFFFFFF];
    assert_eq!(d.0, expected, "2^128 * 2^128 should be 2^256 mod n");
}

#[test]
fn test_fermat_identity() {
    let n_minus_1: [u64; 4] = [
        0xF3B9CAC2FC632550,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
    ];

    let seven = Scalar([7, 0, 0, 0]);
    let result = scalar_pow(&seven, &n_minus_1);
    assert_eq!(result.0, [1, 0, 0, 0], "7^(n-1) should be 1 mod n (Fermat)");
}

#[test]
fn test_scalar_invert() {
    let a = Scalar([7, 0, 0, 0]);
    let a_inv = a.invert().expect("invert failed");
    let result = a.mul(&a_inv);
    assert_eq!(result.0, Scalar::ONE.0, "a * a^-1 should be 1");

    let b = Scalar([0x123456789ABCDEF0, 0x0FEDCBA987654321, 0, 0]);
    let b_inv = b.invert().expect("invert failed");
    let result = b.mul(&b_inv);
    assert_eq!(result.0, Scalar::ONE.0, "b * b^-1 should be 1");
}

#[test]
fn test_scalar_from_to_bytes() {
    let bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let scalar = Scalar::from_bytes(&bytes).expect("from_bytes failed");
    let result = scalar.to_bytes();
    assert_eq!(result, bytes, "round-trip failed");
}

#[test]
fn test_field_arithmetic() {
    let a = FieldElement::ONE;
    let b = FieldElement::ONE;
    let c = a.mul(&b);
    assert_eq!(c.0, FieldElement::ONE.0, "1 * 1 should be 1");

    let two = FieldElement([2, 0, 0, 0]);
    let four = two.mul(&two);
    assert_eq!(four.0, [4, 0, 0, 0], "2 * 2 should be 4");

    let a = FieldElement([3, 0, 0, 0]);
    let b = FieldElement([5, 0, 0, 0]);
    let c = a.mul(&b);
    assert_eq!(c.0, [15, 0, 0, 0], "3 * 5 should be 15");
}

#[test]
fn test_field_sub() {
    let five = FieldElement([5, 0, 0, 0]);
    let three = FieldElement([3, 0, 0, 0]);
    let two = five.sub(&three);
    assert_eq!(two.0, [2, 0, 0, 0], "5 - 3 should be 2");

    let result = three.sub(&five);
    let expected = FieldElement([
        0xFFFFFFFFFFFFFFFD,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]);
    assert_eq!(result.0, expected.0, "3 - 5 should be p - 2");
}

#[test]
fn test_field_invert() {
    let a = FieldElement([7, 0, 0, 0]);
    let a_inv = a.invert().expect("invert failed");
    let result = a.mul(&a_inv);
    assert_eq!(result.0, FieldElement::ONE.0, "a * a^(-1) should be 1");

    let b = FieldElement([0x123456789ABCDEF0, 0xFEDCBA9876543210, 0, 0]);
    let b_inv = b.invert().expect("invert failed");
    let result = b.mul(&b_inv);
    assert_eq!(result.0, FieldElement::ONE.0, "b * b^(-1) should be 1");
}

#[test]
fn test_field_fermat() {
    let a = FieldElement([7, 0, 0, 0]);
    let p_minus_1 = [
        0xFFFFFFFFFFFFFFFE,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ];
    let result = a.pow(&p_minus_1);
    assert_eq!(result.0, FieldElement::ONE.0, "a^(p-1) should be 1 (Fermat)");
}

#[test]
fn test_point_mul_identity() {
    let g = AffinePoint::generator();
    let g_proj = g.to_projective();
    let result = g_proj.mul(&Scalar::ONE);
    let result_aff = result.to_affine();

    assert_eq!(result_aff.x.0, g.x.0, "G * 1 should have same x");
    assert_eq!(result_aff.y.0, g.y.0, "G * 1 should have same y");
}

#[test]
fn test_nist_2g_test_vector() {
    let expected_2gx = FieldElement([
        0xA60B48FC47669978,
        0xC08969E277F21B35,
        0x8A52380304B51AC3,
        0x7CF27B188D034F7E,
    ]);
    let expected_2gy = FieldElement([
        0x9E04B79D227873D1,
        0xBA7DADE63CE98229,
        0x293D9AC69F7430DB,
        0x07775510DB8ED040,
    ]);

    let g = AffinePoint::generator().to_projective();
    let two_g = g.double().to_affine();

    assert_eq!(two_g.x.0, expected_2gx.0,
        "2G x-coordinate should match NIST test vector\ngot: {:?}\nexp: {:?}",
        two_g.x.0, expected_2gx.0);
    assert_eq!(two_g.y.0, expected_2gy.0,
        "2G y-coordinate should match NIST test vector\ngot: {:?}\nexp: {:?}",
        two_g.y.0, expected_2gy.0);
}
