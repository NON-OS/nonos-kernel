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

use alloc::vec::Vec;
use crate::crypto::asymmetric::rsa::{verify_pss, RsaPublicKey, BigUint};
use crate::crypto::asymmetric::p256;
use crate::crypto::hash::sha256;
use crate::network::onion::OnionError;
use super::x509_der::DerParser;

pub fn rsa_pss_sha256_verify_spki(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, OnionError> {
    if spki_der.len() < 32 || message.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    let public_key = parse_rsa_spki(spki_der)?;
    Ok(verify_pss(message, signature, &public_key))
}

pub fn ecdsa_p256_sha256_verify_spki(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, OnionError> {
    if public_key.is_empty() || message.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    let point_bytes = extract_ec_point(public_key)?;
    if point_bytes.len() != 65 || point_bytes[0] != 0x04 {
        return Ok(false);
    }
    let sig_fixed = parse_ecdsa_signature_der(signature)?;
    let hash = sha256(message);
    let pk: [u8; 65] = point_bytes.as_slice().try_into().map_err(|_| OnionError::CryptoError)?;
    Ok(p256::verify(&pk, &hash, &sig_fixed))
}

fn parse_rsa_spki(spki_der: &[u8]) -> Result<RsaPublicKey, OnionError> {
    let mut parser = DerParser::new(spki_der);
    parser.expect_sequence()?;
    let _spki_len = parser.read_length()?;
    parser.expect_sequence()?;
    let alg_len = parser.read_length()?;
    parser.skip(alg_len)?;
    parser.expect_tag(0x03)?;
    let _bit_len = parser.read_length()?;
    if parser.data.len() <= parser.offset {
        return Err(OnionError::CryptoError);
    }
    parser.offset += 1;
    parser.expect_sequence()?;
    let _rsa_len = parser.read_length()?;
    parser.expect_tag(0x02)?;
    let n_len = parser.read_length()?;
    let n_bytes = parser.read_bytes(n_len)?;
    parser.expect_tag(0x02)?;
    let e_len = parser.read_length()?;
    let e_bytes = parser.read_bytes(e_len)?;
    let n_stripped = strip_leading_zeros(n_bytes);
    let e_stripped = strip_leading_zeros(e_bytes);
    Ok(RsaPublicKey {
        n: BigUint::from_bytes_be(n_stripped),
        e: BigUint::from_bytes_be(e_stripped),
        bits: n_stripped.len() * 8,
    })
}

fn extract_ec_point(data: &[u8]) -> Result<Vec<u8>, OnionError> {
    if data.len() == 65 && data[0] == 0x04 {
        return Ok(data.to_vec());
    }
    if data.len() == 64 {
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(data);
        return Ok(point);
    }
    let mut parser = DerParser::new(data);
    if parser.expect_sequence().is_err() {
        return Err(OnionError::CryptoError);
    }
    let _spki_len = parser.read_length()?;
    parser.expect_sequence()?;
    let alg_len = parser.read_length()?;
    parser.skip(alg_len)?;
    parser.expect_tag(0x03)?;
    let bit_len = parser.read_length()?;
    if bit_len < 2 {
        return Err(OnionError::CryptoError);
    }
    parser.offset += 1;
    let point = parser.read_bytes(bit_len - 1)?;
    Ok(point.to_vec())
}

fn parse_ecdsa_signature_der(sig: &[u8]) -> Result<[u8; 64], OnionError> {
    if sig.len() == 64 {
        let mut result = [0u8; 64];
        result.copy_from_slice(sig);
        return Ok(result);
    }
    let mut parser = DerParser::new(sig);
    parser.expect_sequence()?;
    let _seq_len = parser.read_length()?;
    parser.expect_tag(0x02)?;
    let r_len = parser.read_length()?;
    let r_bytes = parser.read_bytes(r_len)?;
    parser.expect_tag(0x02)?;
    let s_len = parser.read_length()?;
    let s_bytes = parser.read_bytes(s_len)?;
    let mut result = [0u8; 64];
    let r_stripped = strip_leading_zeros(r_bytes);
    if r_stripped.len() > 32 {
        return Err(OnionError::CryptoError);
    }
    let r_offset = 32 - r_stripped.len();
    result[r_offset..32].copy_from_slice(r_stripped);
    let s_stripped = strip_leading_zeros(s_bytes);
    if s_stripped.len() > 32 {
        return Err(OnionError::CryptoError);
    }
    let s_offset = 32 - s_stripped.len();
    result[32 + s_offset..64].copy_from_slice(s_stripped);
    Ok(result)
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    &bytes[start..]
}
