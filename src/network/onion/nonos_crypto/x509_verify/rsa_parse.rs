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
use crate::crypto::rsa;
use crate::network::onion::OnionError;

pub(super) fn parse_rsa_public_key(key_bytes: &[u8]) -> Result<rsa::RsaPublicKey, OnionError> {
    let mut parser = DerParser::new(key_bytes);
    parser.expect_sequence()?;
    let _seq_len = parser.read_length()?;
    parser.expect_tag(0x02)?;
    let n_len = parser.read_length()?;
    let n = parser.read_bytes(n_len)?.to_vec();
    parser.expect_tag(0x02)?;
    let e_len = parser.read_length()?;
    let e = parser.read_bytes(e_len)?.to_vec();
    Ok(rsa::create_public_key(n, e))
}
