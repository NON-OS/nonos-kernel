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

use super::super::types::{AlgorithmIdentifier, ObjectIdentifier};
use super::super::x509_der::DerParser;
use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub(super) fn parse_algorithm_identifier(
    parser: &mut DerParser,
) -> Result<AlgorithmIdentifier, OnionError> {
    parser.expect_sequence()?;
    let alg_len = parser.read_length()?;
    let alg_end = parser.offset + alg_len;
    parser.expect_tag(0x06)?;
    let oid_len = parser.read_length()?;
    let oid_bytes = parser.read_bytes(oid_len)?;
    let algorithm = parse_oid(oid_bytes)?;
    let parameters = if parser.offset < alg_end {
        let remaining = alg_end - parser.offset;
        Some(parser.read_bytes(remaining)?.to_vec())
    } else {
        None
    };
    parser.offset = alg_end;
    Ok(AlgorithmIdentifier { algorithm, parameters })
}

pub(super) fn parse_oid(bytes: &[u8]) -> Result<ObjectIdentifier, OnionError> {
    if bytes.is_empty() {
        return Err(OnionError::CryptoError);
    }
    let mut components = Vec::new();
    let first_byte = bytes[0];
    components.push((first_byte / 40) as u32);
    components.push((first_byte % 40) as u32);
    let mut i = 1;
    while i < bytes.len() {
        let mut value = 0u32;
        loop {
            if i >= bytes.len() {
                return Err(OnionError::CryptoError);
            }
            let byte = bytes[i];
            i += 1;
            value = (value << 7) | (byte & 0x7F) as u32;
            if byte & 0x80 == 0 {
                break;
            }
        }
        components.push(value);
    }
    Ok(ObjectIdentifier { components })
}
