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

#[test]
fn test_field_element_roundtrip() {
    let bytes: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let fe = FieldElement::from_bytes(&bytes);
    let out = fe.to_bytes();
    assert_eq!(bytes, out, "Roundtrip failed for basepoint");

    let bytes2: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let fe2 = FieldElement::from_bytes(&bytes2);
    let out2 = fe2.to_bytes();
    assert_eq!(bytes2, out2, "Roundtrip failed for alice_private");
}

#[test]
fn test_field_element_mul_one() {
    let bytes: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let a = FieldElement::from_bytes(&bytes);
    let one = FieldElement::one();
    let result = a.mul(&one);
    assert_eq!(a.to_bytes(), result.to_bytes(), "a * 1 != a");
}

#[test]
fn test_field_element_add_zero() {
    let bytes: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let a = FieldElement::from_bytes(&bytes);
    let zero = FieldElement::zero();
    let result = a.add(&zero);
    assert_eq!(a.to_bytes(), result.to_bytes(), "a + 0 != a");
}

#[test]
fn test_field_element_invert() {
    let bytes: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let a = FieldElement::from_bytes(&bytes);
    let a_inv = a.invert();
    let result = a.mul(&a_inv);
    let one = FieldElement::one();
    assert_eq!(one.to_bytes(), result.to_bytes(), "a * a^(-1) != 1");
}

#[test]
fn test_field_element_square() {
    let bytes: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let a = FieldElement::from_bytes(&bytes);
    let sq = a.square();
    let mul = a.mul(&a);
    assert_eq!(sq.to_bytes(), mul.to_bytes(), "a^2 != a * a");
}

#[test]
fn test_field_element_mul121666() {
    let one = FieldElement::one();
    let result = one.mul121666();
    let expected = FieldElement([121666, 0, 0, 0, 0]).to_bytes();
    assert_eq!(result.to_bytes(), expected, "1 * 121666 failed");
}

#[test]
fn test_field_element_sub() {
    let bytes: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let a = FieldElement::from_bytes(&bytes);
    let zero = FieldElement::zero();
    let result = a.sub(&zero);
    assert_eq!(a.to_bytes(), result.to_bytes(), "a - 0 != a");

    let result2 = a.sub(&a);
    assert_eq!(zero.to_bytes(), result2.to_bytes(), "a - a != 0");
}

#[test]
fn test_basepoint_encoding() {
    let basepoint_bytes: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    let fe = FieldElement::from_bytes(&basepoint_bytes);
    assert_eq!(fe.0[0], 9);
    assert_eq!(fe.0[1], 0);
    assert_eq!(fe.0[2], 0);
    assert_eq!(fe.0[3], 0);
    assert_eq!(fe.0[4], 0);
}

#[test]
fn test_x25519_iteration_known() {
    let mut k: [u8; 32] = [9; 32];
    k[0] = 9;
    for i in 1..32 {
        k[i] = 0;
    }

    let mut u: [u8; 32] = [9; 32];
    u[0] = 9;
    for i in 1..32 {
        u[i] = 0;
    }

    let result = x25519(&k, &u);

    let expected: [u8; 32] = [
        0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27,
        0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae,
        0x30, 0x79,
    ];

    assert_eq!(result, expected, "X25519(9, 9) failed");
}

#[test]
fn test_ladder_first_step() {
    let x_1 = FieldElement::from_bytes(&[
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let a = FieldElement::from_bytes(&[
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let c = FieldElement::one();
    let b = FieldElement::one();
    let d = FieldElement::zero();

    let e = a.add(&c);
    assert_eq!(e.to_bytes()[0], 10, "e should be 10");

    let a_new = a.sub(&c);
    assert_eq!(a_new.to_bytes()[0], 8, "a_new should be 8");

    let cc = b.add(&d);
    assert_eq!(cc.to_bytes()[0], 1, "cc should be 1");

    let bb = b.sub(&d);
    assert_eq!(bb.to_bytes()[0], 1, "bb should be 1");

    let dd = e.square();
    assert_eq!(dd.to_bytes()[0], 100, "dd should be 100");

    let f = a_new.square();
    assert_eq!(f.to_bytes()[0], 64, "f should be 64");

    let aa = cc.mul(&a_new);
    assert_eq!(aa.to_bytes()[0], 8, "aa should be 8");

    let cc2 = bb.mul(&e);
    assert_eq!(cc2.to_bytes()[0], 10, "cc2 should be 10");

    let e2 = aa.add(&cc2);
    assert_eq!(e2.to_bytes()[0], 18, "e2 should be 18");

    let a2 = aa.sub(&cc2);
    let a2_bytes = a2.to_bytes();

    let bb2 = a2.square();
    assert_eq!(bb2.to_bytes()[0], 4, "bb2 should be 4");

    let cc3 = dd.sub(&f);
    assert_eq!(cc3.to_bytes()[0], 36, "cc3 should be 36");

    let a3 = cc3.mul121666();
    let a3_bytes = a3.to_bytes();
    assert_eq!(a3_bytes[0], 0x48, "a3[0] should be 0x48");
    assert_eq!(a3_bytes[1], 0xD5, "a3[1] should be 0xD5");
    assert_eq!(a3_bytes[2], 0x42, "a3[2] should be 0x42");

    let a4 = a3.add(&dd);
    let a4_bytes = a4.to_bytes();
    assert_eq!(a4_bytes[0], 0xAC, "a4[0] should be 0xAC");
    assert_eq!(a4_bytes[1], 0xD5, "a4[1] should be 0xD5");
    assert_eq!(a4_bytes[2], 0x42, "a4[2] should be 0x42");

    let c_new = cc3.mul(&a4);
    let c_bytes = c_new.to_bytes();
    assert_eq!(
        c_bytes[0], 0x30,
        "c_new[0] should be 0x30 (got {:02x})",
        c_bytes[0]
    );
    assert_eq!(
        c_bytes[1], 0x0C,
        "c_new[1] should be 0x0C (got {:02x})",
        c_bytes[1]
    );
    assert_eq!(
        c_bytes[2], 0x66,
        "c_new[2] should be 0x66 (got {:02x})",
        c_bytes[2]
    );
    assert_eq!(
        c_bytes[3], 0x09,
        "c_new[3] should be 0x09 (got {:02x})",
        c_bytes[3]
    );

    let a_final = dd.mul(&f);
    assert_eq!(a_final.to_bytes()[0], 0, "a_final bytes[0]");
    assert_eq!(a_final.to_bytes()[1], 25, "a_final bytes[1] = 6400 >> 8 = 25");

    let d_new = bb2.mul(&x_1);
    assert_eq!(d_new.to_bytes()[0], 36, "d_new should be 36");

    let b_new = e2.square();
    assert_eq!(b_new.to_bytes()[0], 0x44, "b_new[0] should be 0x44");
    assert_eq!(b_new.to_bytes()[1], 0x01, "b_new[1] should be 0x01");
}

#[test]
fn test_x25519_minimal_scalar() {
    let mut scalar = [0u8; 32];

    let point = [
        9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    let result = x25519(&scalar, &point);

    let all_zeros = [0u8; 32];
    assert_ne!(result, all_zeros, "Result should not be zero");
}

#[test]
fn test_field_large_invert() {
    let bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 0x30;
        b[1] = 0x0C;
        b[2] = 0x66;
        b[3] = 0x09;
        b
    };
    let a = FieldElement::from_bytes(&bytes);
    let a_inv = a.invert();
    let product = a.mul(&a_inv);
    let one = FieldElement::one();
    assert_eq!(
        product.to_bytes(),
        one.to_bytes(),
        "a * a^(-1) should equal 1"
    );
}

#[test]
fn test_field_very_large_invert() {
    let bytes: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x00, 0x00,
    ];
    let a = FieldElement::from_bytes(&bytes);
    let a_inv = a.invert();
    let product = a.mul(&a_inv);
    let one = FieldElement::one();
    assert_eq!(
        product.to_bytes(),
        one.to_bytes(),
        "large a * a^(-1) should equal 1"
    );
}

#[test]
fn test_x25519_rfc7748() {
    let alice_private: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let alice_public: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];

    let computed_public = x25519_base(&alice_private);
    assert_eq!(computed_public, alice_public);

    let bob_private: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    let bob_public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];

    let computed_public = x25519_base(&bob_private);
    assert_eq!(computed_public, bob_public);

    let expected_shared: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    let shared_ab = x25519(&alice_private, &bob_public);
    let shared_ba = x25519(&bob_private, &alice_public);
    assert_eq!(shared_ab, expected_shared);
    assert_eq!(shared_ba, expected_shared);
}

#[test]
fn test_ed25519_rfc8032() {
    use ed25519::*;

    let seed1: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let expected_pub1: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    let (pub1, priv1) = keypair_from_seed(&seed1);
    assert_eq!(pub1, expected_pub1);

    let msg1 = [];
    let sig1 = sign(&priv1, &pub1, &msg1);
    assert!(verify(&pub1, &msg1, &sig1));

    let seed2: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    let expected_pub2: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];

    let (pub2, priv2) = keypair_from_seed(&seed2);
    assert_eq!(pub2, expected_pub2);

    let msg2 = [0x72];
    let sig2 = sign(&priv2, &pub2, &msg2);
    assert!(verify(&pub2, &msg2, &sig2));
}
