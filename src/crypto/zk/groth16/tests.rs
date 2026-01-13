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
fn test_params() {
    assert_eq!(params::SECURITY_BITS, 100);
    assert_eq!(params::PROOF_SIZE_COMPRESSED, 128);
    assert_eq!(params::PROOF_SIZE_UNCOMPRESSED, 256);
}

#[test]
fn test_params_hex_strings() {
    assert_eq!(params::P_HEX.len(), 64);
    assert_eq!(params::R_HEX.len(), 64);

    for c in params::P_HEX.chars() {
        assert!(c.is_ascii_hexdigit());
    }
    for c in params::R_HEX.chars() {
        assert!(c.is_ascii_hexdigit());
    }
}

#[test]
fn test_size_limits() {
    assert_eq!(MAX_VK_BYTES, 16 * 1024 * 1024);
    assert_eq!(MAX_PROOF_BYTES, 1 * 1024 * 1024);
    assert_eq!(MAX_PUBLIC_INPUTS, 262_000);
}

#[test]
fn test_max_public_inputs_consistent_with_vk_size() {
    let theoretical_max = MAX_VK_BYTES / 64;
    assert!(MAX_PUBLIC_INPUTS <= theoretical_max);
}

#[test]
fn test_error_display_deserialize() {
    let e = Groth16Error::Deserialize("test message");
    let s = format!("{}", e);
    assert!(s.contains("deserialize"));
    assert!(s.contains("test message"));
}

#[test]
fn test_error_display_size_limit() {
    let e = Groth16Error::SizeLimit("verifying key");
    let s = format!("{}", e);
    assert!(s.contains("size"));
    assert!(s.contains("limit"));
}

#[test]
fn test_error_display_invalid_public_input() {
    let e = Groth16Error::InvalidPublicInput;
    let s = format!("{}", e);
    assert!(s.contains("public input"));
}

#[test]
fn test_error_display_verify_failed() {
    let e = Groth16Error::VerifyFailed;
    let s = format!("{}", e);
    assert!(s.contains("verification failed"));
}

#[test]
fn test_error_equality() {
    assert_eq!(Groth16Error::VerifyFailed, Groth16Error::VerifyFailed);
    assert_ne!(Groth16Error::VerifyFailed, Groth16Error::InvalidPublicInput);
}

#[test]
fn test_read_vk_size_limit() {
    let oversized = vec![0u8; MAX_VK_BYTES + 1];
    let result = deserialize::read_vk(&oversized);
    assert!(matches!(result, Err(Groth16Error::SizeLimit(_))));
}

#[test]
fn test_read_vk_invalid_data() {
    let garbage = vec![0xffu8; 256];
    let result = deserialize::read_vk(&garbage);
    assert!(matches!(result, Err(Groth16Error::Deserialize(_))));
}

#[test]
fn test_read_proof_size_limit() {
    let oversized = vec![0u8; MAX_PROOF_BYTES + 1];
    let result = deserialize::read_proof(&oversized);
    assert!(matches!(result, Err(Groth16Error::SizeLimit(_))));
}

#[test]
fn test_read_proof_invalid_data() {
    let garbage = vec![0xffu8; 128];
    let result = deserialize::read_proof(&garbage);
    assert!(matches!(result, Err(Groth16Error::Deserialize(_))));
}

#[test]
fn test_public_inputs_from_le_bytes_empty() {
    let result = deserialize::public_inputs_from_le_bytes(&[]);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_public_inputs_from_le_bytes_zero() {
    let zero = [[0u8; 32]];
    let result = deserialize::public_inputs_from_le_bytes(&zero);
    assert!(result.is_ok());
    let fr_vec = result.unwrap();
    assert_eq!(fr_vec.len(), 1);
}

#[test]
fn test_public_inputs_from_le_bytes_one() {
    let mut one = [0u8; 32];
    one[0] = 1;
    let result = deserialize::public_inputs_from_le_bytes(&[one]);
    assert!(result.is_ok());
}

#[test]
fn test_public_inputs_from_le_bytes_multiple() {
    let input1 = [0u8; 32];
    let mut input2 = [0u8; 32];
    input2[0] = 42;

    let result = deserialize::public_inputs_from_le_bytes(&[input1, input2]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[test]
fn test_public_inputs_from_le_bytes_max_value() {
    let max = [0xffu8; 32];
    let result = deserialize::public_inputs_from_le_bytes(&[max]);
    assert!(result.is_ok());
}

#[test]
fn test_bn254_field_modulus_bits() {
    let first_byte = u8::from_str_radix(&params::R_HEX[0..2], 16).unwrap();
    assert_eq!(first_byte, 0x30);
}

#[test]
fn test_bn254_p_vs_r() {
    assert_ne!(params::P_HEX, params::R_HEX);
}

#[test]
fn test_proof_sizes() {
    assert_eq!(params::PROOF_SIZE_UNCOMPRESSED, 256);
    assert_eq!(params::PROOF_SIZE_COMPRESSED, 128);
}

#[test]
fn test_verifier_from_invalid_bytes() {
    let garbage = vec![0xffu8; 256];
    let result = Groth16Verifier::from_bytes(&garbage);
    assert!(result.is_err());
}

#[test]
fn test_verifier_from_empty_bytes() {
    let result = Groth16Verifier::from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_groth16_verify_bn254_invalid_vk() {
    let result = groth16_verify_bn254(&[0xffu8; 256], &[0u8; 128], &[]);
    assert!(result.is_err());
}

#[test]
fn test_params_g1_sizes() {
    assert_eq!(params::G1_COMPRESSED_SIZE, 32);
    assert_eq!(params::G1_UNCOMPRESSED_SIZE, 64);
}

#[test]
fn test_params_g2_sizes() {
    assert_eq!(params::G2_COMPRESSED_SIZE, 64);
    assert_eq!(params::G2_UNCOMPRESSED_SIZE, 128);
}

#[test]
fn test_params_min_vk_size() {
    assert_eq!(params::MIN_VK_SIZE_COMPRESSED, 256);
}

#[test]
fn test_params_proof_composition() {
    let expected =
        params::G1_COMPRESSED_SIZE + params::G2_COMPRESSED_SIZE + params::G1_COMPRESSED_SIZE;
    assert_eq!(params::PROOF_SIZE_COMPRESSED, expected);

    let expected =
        params::G1_UNCOMPRESSED_SIZE + params::G2_UNCOMPRESSED_SIZE + params::G1_UNCOMPRESSED_SIZE;
    assert_eq!(params::PROOF_SIZE_UNCOMPRESSED, expected);
}

#[test]
fn test_read_proof_too_short() {
    let short = vec![0u8; 64];
    let result = deserialize::read_proof(&short);
    assert!(matches!(result, Err(Groth16Error::Deserialize(_))));
}

#[test]
fn test_read_proof_exactly_compressed_size_invalid() {
    let invalid = vec![0u8; params::PROOF_SIZE_COMPRESSED];
    let result = deserialize::read_proof(&invalid);
    assert!(matches!(result, Err(Groth16Error::Deserialize(_))));
}

#[test]
fn test_read_vk_empty() {
    let result = deserialize::read_vk(&[]);
    assert!(matches!(result, Err(Groth16Error::Deserialize(_))));
}

#[test]
fn test_error_debug() {
    let e = Groth16Error::VerifyFailed;
    let debug_str = format!("{:?}", e);
    assert!(debug_str.contains("VerifyFailed"));
}

#[test]
fn test_error_clone() {
    let e = Groth16Error::Deserialize("test");
    let cloned = e.clone();
    assert_eq!(e, cloned);
}

#[test]
fn test_error_copy() {
    let e = Groth16Error::InvalidPublicInput;
    let copied = e;
    assert_eq!(e, copied);
}

#[test]
fn test_public_inputs_size_limit() {
    let too_many: Vec<[u8; 32]> = (0..MAX_PUBLIC_INPUTS + 1).map(|_| [0u8; 32]).collect();
    let result = deserialize::public_inputs_from_le_bytes(&too_many);
    assert!(matches!(result, Err(Groth16Error::SizeLimit(_))));
}

#[test]
fn test_public_inputs_all_ones() {
    let all_ones = [[0xffu8; 32]; 3];
    let result = deserialize::public_inputs_from_le_bytes(&all_ones);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 3);
}

#[test]
fn test_public_inputs_various_patterns() {
    let patterns: [[u8; 32]; 4] = [
        [0u8; 32],
        {
            let mut a = [0u8; 32];
            a[0] = 1;
            a
        },
        [0xaau8; 32],
        [0x55u8; 32],
    ];
    let result = deserialize::public_inputs_from_le_bytes(&patterns);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 4);
}
