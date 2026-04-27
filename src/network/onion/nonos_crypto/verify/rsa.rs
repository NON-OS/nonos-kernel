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

use super::super::x509_der::DerParser;
use super::util::strip_leading_zeros;
use crate::crypto::asymmetric::rsa::{
    verify_pkcs1v15, verify_pkcs1v15_sha384, verify_pss, verify_pss_sha384, BigUint, RsaPublicKey,
};
use crate::network::onion::OnionError;

pub fn rsa_pss_sha256_verify_spki(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, OnionError> {
    if spki_der.len() < 32 || message.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    let public_key = parse_rsa_spki(spki_der)?;
    Ok(verify_pss(message, signature, &public_key))
}

pub fn rsa_pss_sha384_verify_spki(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, OnionError> {
    if spki_der.len() < 32 || message.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    let public_key = parse_rsa_spki(spki_der)?;
    Ok(verify_pss_sha384(message, signature, &public_key))
}

pub fn rsa_pkcs1v15_sha256_verify_spki(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, OnionError> {
    if spki_der.len() < 32 || message.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    let public_key = parse_rsa_spki(spki_der)?;
    Ok(verify_pkcs1v15(&public_key, message, signature))
}

pub fn rsa_pkcs1v15_sha384_verify_spki(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, OnionError> {
    if spki_der.len() < 32 || message.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    let public_key = parse_rsa_spki(spki_der)?;
    Ok(verify_pkcs1v15_sha384(&public_key, message, signature))
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
