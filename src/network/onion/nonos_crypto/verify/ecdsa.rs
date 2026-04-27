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

use crate::crypto::asymmetric::p256;
use crate::crypto::asymmetric::p384;
use crate::crypto::hash::sha256;
use crate::crypto::hash::sha384::sha384;
use crate::network::onion::OnionError;
use crate::sys::serial;
use super::ec_point::extract_ec_point;
use super::sig_der::parse_ecdsa_signature_der;
use super::sig_der::parse_ecdsa_signature_der_p384;

pub fn ecdsa_p256_sha256_verify_spki(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, OnionError> {
    serial::print(b"[ECDSA] pk_len=");
    serial::print_dec(public_key.len() as u64);
    serial::print(b" msg_len=");
    serial::print_dec(message.len() as u64);
    serial::print(b" sig_len=");
    serial::print_dec(signature.len() as u64);
    serial::println(b"");
    if public_key.is_empty() || message.is_empty() || signature.is_empty() {
        serial::println(b"[ECDSA] empty input");
        return Ok(false);
    }
    let point_bytes = match extract_ec_point(public_key) {
        Ok(p) => p,
        Err(e) => {
            serial::println(b"[ECDSA] extract_ec_point failed");
            return Err(e);
        }
    };
    serial::print(b"[ECDSA] point_len=");
    serial::print_dec(point_bytes.len() as u64);
    if !point_bytes.is_empty() {
        serial::print(b" first_byte=0x");
        serial::print_hex(point_bytes[0] as u64);
    }
    serial::println(b"");
    if point_bytes.len() != 65 || point_bytes[0] != 0x04 {
        serial::println(b"[ECDSA] invalid point format");
        return Ok(false);
    }
    let sig_fixed = match parse_ecdsa_signature_der(signature) {
        Ok(s) => s,
        Err(e) => {
            serial::println(b"[ECDSA] parse_sig failed");
            return Err(e);
        }
    };
    serial::println(b"[ECDSA] sig parsed OK");
    let hash = sha256(message);
    let pk: [u8; 65] = point_bytes.as_slice().try_into().map_err(|_| OnionError::CryptoError)?;
    let result = p256::verify(&pk, &hash, &sig_fixed);
    serial::print(b"[ECDSA] verify result=");
    serial::println(if result { b"true" } else { b"false" });
    Ok(result)
}

pub fn ecdsa_p384_sha384_verify_spki(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, OnionError> {
    if public_key.is_empty() || message.is_empty() || signature.is_empty() {
        serial::println(b"[ECDSA384] empty input");
        return Ok(false);
    }
    let point_bytes = extract_ec_point(public_key)?;
    serial::print(b"[ECDSA384] point_len=");
    serial::print_dec(point_bytes.len() as u64);
    serial::println(b"");
    if point_bytes.len() != 97 || point_bytes[0] != 0x04 {
        serial::println(b"[ECDSA384] point not P-384 uncompressed, reject");
        return Ok(false);
    }
    let sig_fixed = match parse_ecdsa_signature_der_p384(signature) {
        Ok(s) => s,
        Err(e) => {
            serial::print(b"[ECDSA384] sig parse failed, sig_len=");
            serial::print_dec(signature.len() as u64);
            serial::println(b"");
            return Err(e);
        }
    };
    serial::println(b"[ECDSA384] sig parsed ok");
    let hash = sha384(message);
    let pk: [u8; 97] = point_bytes.as_slice().try_into().map_err(|_| OnionError::CryptoError)?;
    let result = p384::verify(&pk, &hash, &sig_fixed);
    serial::print(b"[ECDSA384] p384_verify=");
    serial::println(if result { b"true" } else { b"false" });
    Ok(result)
}
