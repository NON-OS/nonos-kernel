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

use crate::network::onion::nonos_crypto::x509_der::DerParser;
use crate::network::onion::OnionError;

pub(super) fn parse_octet_string_value(data: &[u8]) -> Result<alloc::vec::Vec<u8>, OnionError> {
    let mut p = DerParser::new(data);
    p.expect_tag(0x04)?;
    let len = p.read_length()?;
    let bytes = p.read_bytes(len)?;
    Ok(bytes.to_vec())
}

pub(super) fn parse_authority_key_id(
    data: &[u8],
) -> Result<Option<alloc::vec::Vec<u8>>, OnionError> {
    let mut p = DerParser::new(data);
    p.expect_sequence()?;
    let seq_len = p.read_length()?;
    let seq_end = p.offset + seq_len;
    if p.offset >= seq_end {
        return Ok(None);
    }
    if p.peek_tag() == Some(0x80) {
        p.expect_tag(0x80)?;
        let len = p.read_length()?;
        let bytes = p.read_bytes(len)?;
        return Ok(Some(bytes.to_vec()));
    }
    Ok(None)
}
