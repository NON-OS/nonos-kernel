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

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::sha512::sha512;

use super::field::ct_eq_32;
use super::point::{
    ensure_precomp, ge_add, ge_pack, ge_scalarmult_base_ct, ge_scalarmult_point, ge_to_cached,
    ge_unpack, ge_p1p1_to_p3,
};
use super::scalar::{clamp_scalar, sc_addmul_mod_l, sc_mul, sc_reduce_mod_l, L};
use super::signature::{sign, verify, verify_batch, KeyPair, Signature};

#[test]
fn test_sc_reduce_known_values() {
    let mut zero = [0u8; 64];
    let result = sc_reduce_mod_l(&mut zero);
    assert_eq!(result, [0u8; 32], "Reducing 0 should give 0");

    let mut l_as_64 = [0u8; 64];
    l_as_64[..32].copy_from_slice(&L);
    let result = sc_reduce_mod_l(&mut l_as_64);
    assert_eq!(
        result,
        [0u8; 32],
        "Reducing L should give 0, got {:02x?}",
        &result[..8]
    );

    let small: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 0,
    ];
    let mut small64 = [0u8; 64];
    small64[..32].copy_from_slice(&small);
    let result = sc_reduce_mod_l(&mut small64);
    assert_eq!(&result[..], &small[..], "Small value should stay same");
}

#[test]
fn test_r_reduction_produces_correct_R() {
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    let h = sha512(&seed);
    let prefix = &h[32..64];

    let r64_full = sha512(prefix);
    let mut r64 = r64_full.clone();
    let r = sc_reduce_mod_l(&mut r64);

    ensure_precomp();
    let Rpt = ge_scalarmult_base_ct(&r);
    let R = ge_pack(&Rpt);

    let expected_R = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55,
    ];

    assert_eq!(
        &R, &expected_R,
        "r*B should equal expected R, got {:02x?}",
        &R[..8]
    );
}

#[test]
fn test_sc_addmul_simple() {
    let zero = [0u8; 32];
    let result = sc_addmul_mod_l(&zero, &zero, &zero);
    assert_eq!(result, zero, "0 + 0*0 should be 0");

    let mut one = [0u8; 32];
    one[0] = 1;
    let result = sc_addmul_mod_l(&one, &zero, &zero);
    assert_eq!(result, one, "1 + 0*0 should be 1");

    let result = sc_addmul_mod_l(&zero, &one, &one);
    assert_eq!(result, one, "0 + 1*1 should be 1");

    let mut two = [0u8; 32];
    two[0] = 2;
    let result = sc_addmul_mod_l(&one, &one, &one);
    assert_eq!(result, two, "1 + 1*1 should be 2");

    let mut two_sc = [0u8; 32];
    two_sc[0] = 2;
    let mut three = [0u8; 32];
    three[0] = 3;
    let mut six = [0u8; 32];
    six[0] = 6;
    let result = sc_addmul_mod_l(&zero, &two_sc, &three);
    assert_eq!(result, six, "0 + 2*3 should be 6");

    let mut a = [0u8; 32];
    a[0] = 255;
    let mut b = [0u8; 32];
    b[0] = 255;
    let result = sc_addmul_mod_l(&zero, &a, &b);
    assert_eq!(result[0], 0x01, "255*255 low byte should be 0x01");
    assert_eq!(result[1], 0xFE, "255*255 high byte should be 0xFE");
}

#[test]
fn test_sc_addmul_vs_separate_ops() {
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    let h = sha512(&seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    clamp_scalar(&mut a);

    let prefix = &h[32..64];
    let mut r_in = Vec::new();
    r_in.extend_from_slice(prefix);
    let mut r64 = sha512(&r_in);
    let r = sc_reduce_mod_l(&mut r64);

    ensure_precomp();
    let Rpt = ge_scalarmult_base_ct(&r);
    let R = ge_pack(&Rpt);

    let expected_R = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55,
    ];
    assert_eq!(&R, &expected_R, "R should match");

    let kp = KeyPair::from_seed(seed);

    let mut kin = Vec::new();
    kin.extend_from_slice(&R);
    kin.extend_from_slice(&kp.public);
    let mut k64 = sha512(&kin);
    let k = sc_reduce_mod_l(&mut k64);

    let S1 = sc_addmul_mod_l(&r, &k, &a);

    let ka = sc_mul(&k, &a);
    let mut one = [0u8; 32];
    one[0] = 1;
    let S2 = sc_addmul_mod_l(&ka, &one, &r);

    assert_eq!(&S1, &S2, "Two methods should give same result");

    let SB = ge_scalarmult_base_ct(&S1);
    let A = ge_unpack(&kp.public).expect("A");
    let kA = ge_scalarmult_point(&A, &k);
    let R_pt = ge_unpack(&R).expect("R");
    let RkA = ge_add(&R_pt, &ge_to_cached(&kA));
    let RkA_p3 = ge_p1p1_to_p3(&RkA);

    assert_eq!(ge_pack(&SB), ge_pack(&RkA_p3), "S*B should equal R + k*A");
}

#[test]
fn test_verify_equation_directly() {
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    let kp = KeyPair::from_seed(seed);
    let msg: [u8; 0] = [];

    let expected_R = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55,
    ];
    let expected_S = [
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4,
        0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a,
        0x10, 0x0b,
    ];

    ensure_precomp();
    let SB = ge_scalarmult_base_ct(&expected_S);
    let SB_packed = ge_pack(&SB);

    let A = ge_unpack(&kp.public).expect("A should decode");
    let R = ge_unpack(&expected_R).expect("R should decode");

    let mut kin = Vec::new();
    kin.extend_from_slice(&expected_R);
    kin.extend_from_slice(&kp.public);
    kin.extend_from_slice(&msg);
    let mut k64 = sha512(&kin);
    let k = sc_reduce_mod_l(&mut k64);

    let kA = ge_scalarmult_point(&A, &k);

    let RkA = ge_add(&R, &ge_to_cached(&kA));
    let RkA_p3 = ge_p1p1_to_p3(&RkA);
    let RkA_packed = ge_pack(&RkA_p3);

    assert_eq!(
        &SB_packed, &RkA_packed,
        "Verification equation failed for EXPECTED signature: S*B != R + k*A\nS*B = {:02x?}\nR+kA = {:02x?}",
        &SB_packed[..8],
        &RkA_packed[..8]
    );
}

#[test]
fn trace_rfc8032_tv1_intermediates() {
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    let kp = KeyPair::from_seed(seed);
    let msg: [u8; 0] = [];
    let sig = sign(&kp, &msg);

    let expected_R = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55,
    ];
    assert_eq!(&sig.R, &expected_R, "sign() R mismatch");

    let expected_S = [
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4,
        0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a,
        0x10, 0x0b,
    ];

    assert!(verify(&kp.public, &msg, &sig), "Our signature should verify");

    assert_eq!(
        &sig.S, &expected_S,
        "sign() S mismatch: expected {:02x?}, got {:02x?}",
        &expected_S[..8],
        &sig.S[..8]
    );
}

#[test]
fn debug_rfc8032_tv1() {
    let expected_sig = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let kp = KeyPair::from_seed(seed);

    let expected_pub = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    assert_eq!(&kp.public, &expected_pub, "Public key mismatch");

    let msg: [u8; 0] = [];

    let expected_R: [u8; 32] = expected_sig[..32].try_into().unwrap();
    let expected_S: [u8; 32] = expected_sig[32..].try_into().unwrap();
    let expected_sig_obj = Signature {
        R: expected_R,
        S: expected_S,
    };

    assert!(
        verify(&kp.public, &msg, &expected_sig_obj),
        "Expected RFC 8032 signature should verify"
    );

    let actual_sig = sign(&kp, &msg);
    assert_eq!(
        &actual_sig.R, &expected_R,
        "R mismatch: expected {:02x?}, got {:02x?}",
        &expected_R[..8],
        &actual_sig.R[..8]
    );
    assert_eq!(
        &actual_sig.S, &expected_S,
        "S mismatch: expected {:02x?}, got {:02x?}",
        &expected_S[..8],
        &actual_sig.S[..8]
    );
}

#[test]
fn rfc8032_tv1() {
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let kp = KeyPair::from_seed(seed);
    assert_eq!(
        &kp.public,
        &[
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ]
    );
    let msg: [u8; 0] = [];
    let sig = sign(&kp, &msg);
    assert!(verify(&kp.public, &msg, &sig));
    assert_eq!(&sig.R[..4], &[0xe5, 0x56, 0x43, 0x00]);
}

#[test]
fn sign_verify_roundtrip() {
    let kp = KeyPair::from_seed([7u8; 32]);
    let msg = b"ed25519 test message";
    let sig = sign(&kp, msg);
    assert!(verify(&kp.public, msg, &sig));
    let mut s = sig.to_bytes();
    s[10] ^= 0xFF;
    let sig2 = Signature::from_bytes(&s);
    assert!(!verify(&kp.public, msg, &sig2));
}

#[test]
fn batch_verify_basic() {
    let kp1 = KeyPair::from_seed([1u8; 32]);
    let kp2 = KeyPair::from_seed([2u8; 32]);
    let m1 = b"hello";
    let m2 = b"world";
    let s1 = sign(&kp1, m1);
    let s2 = sign(&kp2, m2);
    let items = vec![
        (kp1.public, &m1[..], s1.clone()),
        (kp2.public, &m2[..], s2.clone()),
    ];
    assert!(verify_batch(&items));
    let mut bad = s2.to_bytes();
    bad[0] ^= 1;
    let bad_sig = Signature::from_bytes(&bad);
    let items2 = vec![(kp1.public, &m1[..], s1), (kp2.public, &m2[..], bad_sig)];
    assert!(!verify_batch(&items2));
}
