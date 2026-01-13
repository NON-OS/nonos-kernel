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

use halo2_proofs::SerdeFormat;

use crate::crypto::zk::halo2::{
    api::{halo2_verify, halo2_verify_with_format},
    deserialize::{parse_public_inputs, read_params},
    params, verifier::Halo2Verifier, Halo2Error, FR_MODULUS_BYTES,
    MAX_K, MAX_PARAMS_BYTES, MAX_PROOF_BYTES, MAX_PUBLIC_INPUTS, MAX_VK_BYTES, MIN_K,
};

#[test]
fn test_constants() {
    assert_eq!(params::SECURITY_BITS, 100);
    assert_eq!(params::MIN_K, 4);
    assert_eq!(params::MAX_K, 24);
    assert_eq!(params::G1_SIZE, 64);
    assert_eq!(params::G2_SIZE, 128);
    assert_eq!(params::FR_SIZE, 32);
    assert_eq!(params::TWO_ADICITY, 28);
    assert_eq!(params::BLAKE2B_DIGEST_SIZE, 64);
    assert_eq!(params::TYPICAL_PROOF_SIZE, 1024);
}

#[test]
fn test_size_limits() {
    assert_eq!(MAX_PARAMS_BYTES, 64 * 1024 * 1024);
    assert_eq!(MAX_VK_BYTES, 16 * 1024 * 1024);
    assert_eq!(MAX_PROOF_BYTES, 1 * 1024 * 1024);
    assert_eq!(MAX_PUBLIC_INPUTS, 1 << 20);
}

#[test]
fn test_k_range() {
    assert_eq!(1u64 << MIN_K, 16);
    assert_eq!(1u64 << MAX_K, 16_777_216);
}

#[test]
fn test_k_range_values() {
    assert_eq!(MIN_K, 4);
    assert_eq!(MAX_K, 24);
    assert!(MIN_K < MAX_K);
}

#[test]
fn test_error_display_verify_failed() {
    let e = Halo2Error::VerifyFailed;
    assert_eq!(format!("{}", e), "proof verification failed");
}

#[test]
fn test_error_display_k_out_of_range() {
    let e = Halo2Error::KOutOfRange;
    let s = format!("{}", e);
    assert!(s.contains("4"));
    assert!(s.contains("24"));
}

#[test]
fn test_error_display_deserialize() {
    let e = Halo2Error::Deserialize("params");
    let s = format!("{}", e);
    assert!(s.contains("deserialize"));
    assert!(s.contains("params"));
}

#[test]
fn test_error_display_size_limit() {
    let e = Halo2Error::SizeLimit("proof");
    let s = format!("{}", e);
    assert!(s.contains("size"));
    assert!(s.contains("limit"));
}

#[test]
fn test_error_display_public_input_shape() {
    let e = Halo2Error::PublicInputShape;
    let s = format!("{}", e);
    assert!(s.contains("public input"));
    assert!(s.contains("shape") || s.contains("mismatch"));
}

#[test]
fn test_error_display_invalid_field() {
    let e = Halo2Error::InvalidFieldElement;
    let s = format!("{}", e);
    assert!(s.contains("field element"));
}

#[test]
fn test_error_display_io() {
    let e = Halo2Error::IoError;
    let s = format!("{}", e);
    assert!(s.contains("I/O"));
}

#[test]
fn test_error_equality() {
    assert_eq!(Halo2Error::VerifyFailed, Halo2Error::VerifyFailed);
    assert_ne!(Halo2Error::VerifyFailed, Halo2Error::IoError);
    assert_eq!(Halo2Error::KOutOfRange, Halo2Error::KOutOfRange);
}

#[test]
fn test_empty_params() {
    let result = read_params(&[]);
    assert!(matches!(result, Err(Halo2Error::Deserialize(_))));
}

#[test]
fn test_params_size_limit() {
    let oversized = vec![0u8; MAX_PARAMS_BYTES + 1];
    let result = read_params(&oversized);
    assert!(matches!(result, Err(Halo2Error::SizeLimit(_))));
}

#[test]
fn test_params_invalid_data() {
    let garbage = vec![0xffu8; 256];
    let result = read_params(&garbage);
    assert!(matches!(result, Err(Halo2Error::Deserialize(_))));
}

#[test]
fn test_parse_public_inputs_empty() {
    let result = parse_public_inputs(&[]);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_parse_public_inputs_empty_column() {
    let empty_col: &[[u8; 32]] = &[];
    let result = parse_public_inputs(&[empty_col]);
    assert!(result.is_ok());
    let cols = result.unwrap();
    assert_eq!(cols.len(), 1);
    assert!(cols[0].is_empty());
}

#[test]
fn test_parse_public_inputs_zero() {
    let zero = [[0u8; 32]];
    let result = parse_public_inputs(&[&zero[..]]);
    assert!(result.is_ok());
    let cols = result.unwrap();
    assert_eq!(cols.len(), 1);
    assert_eq!(cols[0].len(), 1);
}

#[test]
fn test_parse_public_inputs_one() {
    let mut one = [0u8; 32];
    one[0] = 1;
    let result = parse_public_inputs(&[&[one][..]]);
    assert!(result.is_ok());
}

#[test]
fn test_parse_public_inputs_multiple_columns() {
    let col1 = [[0u8; 32]];
    let mut elem = [0u8; 32];
    elem[0] = 42;
    let col2 = [elem];

    let result = parse_public_inputs(&[&col1[..], &col2[..]]);
    assert!(result.is_ok());
    let cols = result.unwrap();
    assert_eq!(cols.len(), 2);
}

#[test]
fn test_parse_public_inputs_invalid_field_element() {
    let mut invalid = [0u8; 32];
    invalid[31] = 0x31;
    for i in 0..31 {
        invalid[i] = 0xff;
    }

    let result = parse_public_inputs(&[&[invalid][..]]);
    assert!(matches!(result, Err(Halo2Error::InvalidFieldElement)));
}

#[test]
fn test_fr_modulus_bytes() {
    let mut val = [0u8; 32];
    val.copy_from_slice(&FR_MODULUS_BYTES);
    val.reverse();
    assert_eq!(val[0], 0x30);
}

#[test]
fn test_fr_modulus_length() {
    assert_eq!(FR_MODULUS_BYTES.len(), 32);
}

#[test]
fn test_params_r_matches_fr_modulus() {
    assert_eq!(params::R.len(), FR_MODULUS_BYTES.len());
}

#[test]
fn test_g1_size() {
    assert_eq!(params::G1_SIZE, 64);
}

#[test]
fn test_g2_size() {
    assert_eq!(params::G2_SIZE, 128);
}

#[test]
fn test_fr_size() {
    assert_eq!(params::FR_SIZE, 32);
}

#[test]
fn test_kzg_params_size_calculation() {
    let k10_estimate = (1u64 << 10) * 64 + 2 * 128;
    assert!(k10_estimate < MAX_PARAMS_BYTES as u64);
}

#[test]
fn test_max_k_fits_in_params() {
    let k20_estimate = (1u64 << 20) * 64 + 2 * 128;
    assert!(k20_estimate <= MAX_PARAMS_BYTES as u64);
}

#[test]
fn test_two_adicity() {
    assert_eq!(params::TWO_ADICITY, 28);
    assert!(params::TWO_ADICITY >= MAX_K);
}

#[test]
fn test_verifier_from_invalid_bytes() {
    let garbage = vec![0xffu8; 256];
    let result = Halo2Verifier::from_bytes(&garbage, &garbage);
    assert!(result.is_err());
}

#[test]
fn test_verifier_from_empty_bytes() {
    let result = Halo2Verifier::from_bytes(&[], &[]);
    assert!(result.is_err());
}

#[test]
fn test_halo2_verify_invalid_params() {
    let garbage = vec![0xffu8; 256];
    let result = halo2_verify(&garbage, &garbage, &garbage, &[]);
    assert!(result.is_err());
}

#[test]
fn test_halo2_verify_with_format_invalid() {
    let garbage = vec![0xffu8; 256];
    let result = halo2_verify_with_format(
        &garbage,
        &garbage,
        &garbage,
        &[],
        SerdeFormat::RawBytes,
    );
    assert!(result.is_err());
}

#[test]
fn test_params_p_length() {
    assert_eq!(params::P.len(), 32);
}

#[test]
fn test_params_p_not_all_zeros() {
    let sum: u64 = params::P.iter().map(|&b| b as u64).sum();
    assert!(sum > 0);
}

#[test]
fn test_params_r_not_all_zeros() {
    let sum: u64 = params::R.iter().map(|&b| b as u64).sum();
    assert!(sum > 0);
}

#[test]
fn test_params_p_vs_r() {
    assert_ne!(params::P, params::R);
}
