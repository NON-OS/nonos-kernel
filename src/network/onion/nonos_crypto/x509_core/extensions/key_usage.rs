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

use super::oids::*;
use crate::network::onion::nonos_crypto::types::ExtKeyUsage;
use crate::network::onion::nonos_crypto::x509_der::DerParser;
use crate::network::onion::OnionError;

pub(super) fn parse_key_usage(data: &[u8]) -> Result<u16, OnionError> {
    let mut p = DerParser::new(data);
    p.expect_tag(0x03)?;
    let len = p.read_length()?;
    if len < 2 {
        return Ok(0);
    }
    let _unused_bits = p.data.get(p.offset).copied().unwrap_or(0);
    p.offset += 1;
    let byte0 = p.data.get(p.offset).copied().unwrap_or(0);
    let mut bits = byte0 as u16;
    if len > 2 {
        let byte1 = p.data.get(p.offset + 1).copied().unwrap_or(0);
        bits |= (byte1 as u16) << 8;
    }
    Ok(bits)
}

pub(super) fn parse_ext_key_usage(
    data: &[u8],
    ekus: &mut alloc::vec::Vec<ExtKeyUsage>,
) -> Result<(), OnionError> {
    let mut p = DerParser::new(data);
    p.expect_sequence()?;
    let seq_len = p.read_length()?;
    let seq_end = p.offset + seq_len;
    while p.offset < seq_end {
        p.expect_tag(0x06)?;
        let oid_len = p.read_length()?;
        let oid_bytes = p.read_bytes(oid_len)?;
        if oid_bytes == OID_EKU_SERVER_AUTH {
            ekus.push(ExtKeyUsage::ServerAuth);
        } else if oid_bytes == OID_EKU_CLIENT_AUTH {
            ekus.push(ExtKeyUsage::ClientAuth);
        } else if oid_bytes == OID_EKU_OCSP_SIGNING {
            ekus.push(ExtKeyUsage::OcspSigning);
        }
    }
    Ok(())
}
