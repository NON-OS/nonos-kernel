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

use super::super::types::PublicKeyInfo;
use super::super::x509_der::DerParser;
use super::oid::parse_algorithm_identifier;
use crate::network::onion::OnionError;

pub(super) fn parse_subject_public_key_info(
    parser: &mut DerParser,
) -> Result<PublicKeyInfo, OnionError> {
    let spki_start = parser.offset;
    parser.expect_sequence()?;
    let spki_len = parser.read_length()?;
    let spki_end = parser.offset + spki_len;
    let raw_spki = parser.data[spki_start..spki_end].to_vec();
    let algorithm = parse_algorithm_identifier(parser)?;
    parser.expect_tag(0x03)?;
    let key_len = parser.read_length()?;
    parser.skip(1)?;
    let public_key = parser.read_bytes(key_len - 1)?.to_vec();
    parser.offset = spki_end;
    Ok(PublicKeyInfo { algorithm, public_key, raw_spki })
}

/// Parse a standalone SPKI DER blob into a PublicKeyInfo.
/// Used by chain building to extract the algorithm and public key from
/// a trusted root CA's stored spki_der bytes.
pub(in crate::network::onion::nonos_crypto) fn parse_spki_der(
    spki_der: &[u8],
) -> Result<PublicKeyInfo, OnionError> {
    let mut parser = DerParser::new(spki_der);
    parse_subject_public_key_info(&mut parser)
}
