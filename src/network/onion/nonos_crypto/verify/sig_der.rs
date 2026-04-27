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
use crate::network::onion::OnionError;
use crate::sys::serial;

pub(super) fn parse_ecdsa_signature_der(sig: &[u8]) -> Result<[u8; 64], OnionError> {
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
    serial::print(b"[ECDSA] r_len=");
    serial::print_dec(r_len as u64);
    serial::print(b" s_len=");
    serial::print_dec(s_len as u64);
    serial::println(b"");
    let mut result = [0u8; 64];
    let r_stripped = strip_leading_zeros(r_bytes);
    if r_stripped.len() > 32 {
        serial::println(b"[ECDSA] r too long");
        return Err(OnionError::CryptoError);
    }
    let r_offset = 32 - r_stripped.len();
    result[r_offset..32].copy_from_slice(r_stripped);
    let s_stripped = strip_leading_zeros(s_bytes);
    if s_stripped.len() > 32 {
        serial::println(b"[ECDSA] s too long");
        return Err(OnionError::CryptoError);
    }
    let s_offset = 32 - s_stripped.len();
    result[32 + s_offset..64].copy_from_slice(s_stripped);
    serial::print(b"[ECDSA] r[0..4]=");
    for i in 0..4.min(32) {
        serial::print_hex(result[i] as u64);
        serial::print(b" ");
    }
    serial::println(b"");
    serial::print(b"[ECDSA] s[0..4]=");
    for i in 0..4.min(32) {
        serial::print_hex(result[32 + i] as u64);
        serial::print(b" ");
    }
    serial::println(b"");
    Ok(result)
}

pub(super) fn parse_ecdsa_signature_der_p384(sig: &[u8]) -> Result<[u8; 96], OnionError> {
    if sig.len() == 96 {
        let mut result = [0u8; 96];
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
    let mut result = [0u8; 96];
    let r_stripped = strip_leading_zeros(r_bytes);
    if r_stripped.len() > 48 {
        return Err(OnionError::CryptoError);
    }
    let r_offset = 48 - r_stripped.len();
    result[r_offset..48].copy_from_slice(r_stripped);
    let s_stripped = strip_leading_zeros(s_bytes);
    if s_stripped.len() > 48 {
        return Err(OnionError::CryptoError);
    }
    let s_offset = 48 - s_stripped.len();
    result[48 + s_offset..96].copy_from_slice(s_stripped);
    Ok(result)
}
