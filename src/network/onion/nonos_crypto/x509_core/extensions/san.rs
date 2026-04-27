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
use alloc::string::String;

pub(super) fn parse_san(
    data: &[u8],
    dns_names: &mut alloc::vec::Vec<String>,
) -> Result<(), OnionError> {
    let mut p = DerParser::new(data);
    p.expect_sequence()?;
    let seq_len = p.read_length()?;
    let seq_end = p.offset + seq_len;
    while p.offset < seq_end {
        let tag = p.peek_tag().ok_or(OnionError::CertificateError)?;
        p.offset += 1;
        let len = p.read_length()?;
        if tag == 0x82 {
            let bytes = p.read_bytes(len)?;
            if let Ok(name) = core::str::from_utf8(bytes) {
                dns_names.push(String::from(name));
            }
        } else {
            p.skip(len)?;
        }
    }
    Ok(())
}
