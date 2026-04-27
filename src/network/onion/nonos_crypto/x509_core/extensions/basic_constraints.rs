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

use crate::network::onion::nonos_crypto::types::BasicConstraints;
use crate::network::onion::nonos_crypto::x509_der::DerParser;
use crate::network::onion::OnionError;

pub(super) fn parse_basic_constraints(
    data: &[u8],
    bc: &mut BasicConstraints,
) -> Result<(), OnionError> {
    let mut p = DerParser::new(data);
    p.expect_sequence()?;
    let seq_len = p.read_length()?;
    let seq_end = p.offset + seq_len;
    if p.offset >= seq_end {
        return Ok(());
    }
    if p.peek_tag() == Some(0x01) {
        p.expect_tag(0x01)?;
        let len = p.read_length()?;
        if len == 1 && p.offset < p.data.len() {
            bc.ca = p.data[p.offset] != 0;
            p.offset += 1;
        } else {
            p.skip(len)?;
        }
    }
    if p.offset < seq_end && p.peek_tag() == Some(0x02) {
        p.expect_tag(0x02)?;
        let len = p.read_length()?;
        if len == 1 && p.offset < p.data.len() {
            bc.path_len_constraint = Some(p.data[p.offset]);
        } else {
            p.skip(len)?;
        }
    }
    Ok(())
}
